#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
import subprocess
import time
from logging import getLogger
from pathlib import Path

from moulinette import m18n

from ..tools import Migration
from ..utils.error import YunohostError, YunohostValidationError
from ..utils.system import free_space_in_directory, space_used_by_directory

logger = getLogger("yunohost.migration")


class PostgreSQLMigration(Migration):
    "Migrate DBs between Postgresql versions after migrating to a new Debian version"

    # Provided by calling class
    previous_version: str
    target_version: str

    def run(self):
        ynh_deps_cmd = 'grep -A10 "ynh-deps" /var/lib/dpkg/status | grep -E "Package:|Depends:" | grep -B1 postgresql'
        if os.system(ynh_deps_cmd) != 0:
            logger.info("No YunoHost app seem to require postgresql... Skipping!")
            return

        if not self.package_is_installed(f"postgresql-{self.previous_version}"):
            logger.warning(m18n.n("migration_postgresql_previous_not_installed"))
            return

        if not self.package_is_installed(f"postgresql-{self.target_version}"):
            raise YunohostValidationError(
                "migration_postgresql_target_not_installed",
                previous=self.previous_version,
                target=self.target_version,
            )

        # Make sure there's a 15 cluster
        try:
            self.runcmd(f"pg_lsclusters | grep -q '^{self.previous_version} '")
        except Exception:
            logger.warning(
                f"It looks like there's not active {self.previous_version} cluster, so probably don't need to run this migration"
            )
            return

        if not space_used_by_directory(
            f"/var/lib/postgresql/{self.previous_version}"
        ) > free_space_in_directory("/var/lib/postgresql"):
            raise YunohostValidationError(
                "migration_not_enough_space", path="/var/lib/postgresql/"
            )

        self.runcmd("systemctl stop postgresql")
        time.sleep(3)
        self.runcmd(
            f"LC_ALL=C pg_dropcluster --stop {self.target_version} main || true"
        )  # We do not trigger an exception if the command fails because that probably means cluster self.target_version doesn't exists, which is fine because it's created during the pg_upgradecluster)
        time.sleep(3)
        self.runcmd(
            f"LC_ALL=C pg_upgradecluster -m upgrade {self.previous_version} main -v {self.target_version}"
        )
        self.runcmd(f"LC_ALL=C pg_dropcluster --stop {self.previous_version} main")

        # Fix possibly borked postgresql default config when Immich is installed
        self.runcmd(r"sed -i '/^\* \* 15 main postgres$/d' /etc/postgresql-common/user_clusters")

        self.runcmd("systemctl start postgresql")

        logger.warning(m18n.n("migration_postgresql_reindexing_databases"))

        password = Path("/etc/yunohost/psql").read_text().strip()
        sudocmd = f"LC_ALL=C sudo --login -u postgres PGUSER=postgres PGPASSWORD='{password}'"
        psqlcmd = "psql --tuples-only --no-align --dbname=postgres --command=\"SELECT datname FROM pg_database WHERE datistemplate = false OR datname = 'template1';\""
        _, out, _ = self.runcmd(f"{sudocmd} {psqlcmd}")
        databases = [line.strip() for line in out]
        for database in databases:
            # See https://www.postgresql.org/docs/17/sql-altercollation.html#SQL-ALTERCOLLATION-NOTES
            self.runcmd(f"{sudocmd} psql --dbname='{database}' --command='REINDEX DATABASE {database};'")
            self.runcmd(f"{sudocmd} psql --dbname='{database}' --command='ALTER DATABASE {database} REFRESH COLLATION VERSION;'")

    def package_is_installed(self, package_name):
        (returncode, out, err) = self.runcmd(
            "dpkg --list | grep '^ii ' | grep -q -w {}".format(package_name),
            raise_on_errors=False,
        )
        return returncode == 0

    def runcmd(self, cmd, raise_on_errors=True):
        logger.debug("Running command: " + cmd)

        p = subprocess.Popen(
            cmd,
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        out, err = p.communicate()
        returncode = p.returncode
        if raise_on_errors and returncode != 0:
            raise YunohostError(
                "Failed to run command '{}'.\nreturncode: {}\nstdout:\n{}\nstderr:\n{}\n".format(
                    cmd, returncode, out, err
                )
            )

        out = out.strip().split(b"\n")
        return (returncode, out, err)
