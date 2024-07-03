import subprocess
import time
import os
from logging import getLogger

from moulinette import m18n
from yunohost.utils.error import YunohostError, YunohostValidationError

from yunohost.tools import Migration
from yunohost.utils.system import free_space_in_directory, space_used_by_directory

logger = getLogger("yunohost.migration")


class MyMigration(Migration):
    "Migrate DBs from Postgresql 13 to 15 after migrating to Bookworm"

    dependencies = ["migrate_to_bookworm"]

    def run(self):
        if (
            os.system(
                'grep -A10 "ynh-deps" /var/lib/dpkg/status | grep -E "Package:|Depends:" | grep -B1 postgresql'
            )
            != 0
        ):
            logger.info("No YunoHost app seem to require postgresql... Skipping!")
            return

        if not self.package_is_installed("postgresql-13"):
            logger.warning(m18n.n("migration_0029_postgresql_13_not_installed"))
            return

        if not self.package_is_installed("postgresql-15"):
            raise YunohostValidationError("migration_0029_postgresql_15_not_installed")

        # Make sure there's a 13 cluster
        try:
            self.runcmd("pg_lsclusters | grep -q '^13 '")
        except Exception:
            logger.warning(
                "It looks like there's not active 13 cluster, so probably don't need to run this migration"
            )
            return

        if not space_used_by_directory(
            "/var/lib/postgresql/13"
        ) > free_space_in_directory("/var/lib/postgresql"):
            raise YunohostValidationError(
                "migration_0029_not_enough_space", path="/var/lib/postgresql/"
            )

        self.runcmd("systemctl stop postgresql")
        time.sleep(3)
        self.runcmd(
            "LC_ALL=C pg_dropcluster --stop 15 main || true"
        )  # We do not trigger an exception if the command fails because that probably means cluster 15 doesn't exists, which is fine because it's created during the pg_upgradecluster)
        time.sleep(3)
        self.runcmd("LC_ALL=C pg_upgradecluster -m upgrade 13 main")
        self.runcmd("LC_ALL=C pg_dropcluster --stop 13 main")
        self.runcmd("systemctl start postgresql")

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
