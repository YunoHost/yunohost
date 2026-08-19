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

import json
import os
import subprocess
import time
from logging import getLogger

from moulinette import m18n

from ..tools import Migration
from ..utils.error import YunohostError, YunohostValidationError
from ..utils.system import free_space_in_directory, space_used_by_directory

logger = getLogger("yunohost.migration")


class PostgreSQLMigration(Migration):
    "Migrate DBs between Postgresql versions after migrating to a new Debian version"

    # Provided by calling class
    previous_version: int
    target_version: int

    def run(self):
        ynh_deps_cmd = "grep -A10 'ynh-deps' /var/lib/dpkg/status | grep -E 'Package:|Depends:' | grep -B1 postgresql"
        if subprocess.run(ynh_deps_cmd, shell=True, stdout=subprocess.DEVNULL, check=False).returncode != 0:
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
        if not self.cluster_is_installed(int(self.previous_version), "main"):
            if self.cluster_is_installed(int(self.target_version), "main"):
                logger.info(f"Migration to version {self.target_version} looks already done, running the post-migrations steps")
                self.run_post_migration()
            else:
                logger.warning(
                    f"It looks like there's no active cluster for postgresql-{self.previous_version}, "
                    "so probably don't need to run this migration."
                )
            return

        used_space = space_used_by_directory(f"/var/lib/postgresql/{self.previous_version}", follow_symlinks=False)
        free_space = free_space_in_directory("/var/lib/postgresql")
        if used_space >= free_space:
            raise YunohostValidationError(
                "migration_not_enough_space", path="/var/lib/postgresql/"
            )

        environ = os.environ.copy()
        environ["LC_ALL"] = "C"

        subprocess.check_call(["systemctl", "stop", "postgresql"])
        time.sleep(3)

        logger.info("Dropping target cluster...")
        # We do not trigger an exception if the command fails because that probably means cluster
        # self.target_version doesn't exists, which is fine because it's created during the pg_upgradecluster)
        cmd = ["pg_dropcluster", "--stop", str(self.target_version), "main"]
        subprocess.run(cmd, env=environ, check=False)
        time.sleep(3)

        logger.info("Upgrading cluster...")
        cmd = ["pg_upgradecluster", "-m", "upgrade", str(self.previous_version), "main", "-v", str(self.target_version)]
        subprocess.check_call(cmd, env=environ)

        logger.info("Dropping old cluster...")
        cmd = ["pg_dropcluster", "--stop", str(self.previous_version), "main"]
        subprocess.check_call(cmd, env=environ)

        # Fix possibly borked postgresql default config when Immich is installed
        subprocess.check_call(["sed", "-i", r"/^\* \* 15 main postgres$/d", "/etc/postgresql-common/user_clusters"])

        subprocess.check_call(["systemctl", "start", "postgresql"])

        self.run_post_migration()


    def run_post_migration(self):
        logger.warning(m18n.n("migration_postgresql_reindexing_databases"))
        environ = os.environ.copy()
        environ["LC_ALL"] = "C"

        psqlcmd = "SELECT datname FROM pg_database WHERE datistemplate = false OR datname = 'template1';"
        cmd = ["sudo", "-u", "postgres", "psql", "--tuples-only", "--no-align", "--dbname=postgres", "--command", psqlcmd]
        out = subprocess.check_output(cmd, env=environ, text=True)

        databases = [line.strip() for line in out.splitlines()]
        for database in databases:
            # See https://www.postgresql.org/docs/17/sql-altercollation.html#SQL-ALTERCOLLATION-NOTES
            cmd = ["sudo", "-u", "postgres", "psql", "--dbname", database, "--command", f"REINDEX DATABASE {database};"]
            subprocess.check_call(cmd, env=environ)
            cmd = ["sudo", "-u", "postgres", "psql", "--dbname", database, "--command", f"ALTER DATABASE {database} REFRESH COLLATION VERSION;"]
            subprocess.check_call(cmd, env=environ)

    def package_is_installed(self, package_name):
        return subprocess.run(["dpkg-query", "--no-pager", "-l", package_name], check=False, stdout=subprocess.DEVNULL).returncode == 0

    def cluster_is_installed(self, version: int, name: str) -> bool:
        clusters_info = json.loads(subprocess.check_output(["pg_lsclusters", "--json"]))
        clusters = [[cluster["version"], cluster["cluster"]] for cluster in clusters_info]
        return [version, name] in clusters
