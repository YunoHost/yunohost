import subprocess

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.utils.filesystem import free_space_in_directory, space_used_by_directory

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):

    "Migrate DBs from Postgresql 9.6 to 11 after migrating to Buster"

    dependencies = ["migrate_to_buster"]

    def run(self):

        if not self.package_is_installed("postgresql-9.6"):
            logger.warning(m18n.n("migration_0017_postgresql_96_not_installed"))
            return

        if not self.package_is_installed("postgresql-11"):
            raise YunohostError("migration_0017_postgresql_11_not_installed")

        if not space_used_by_directory("/var/lib/postgresql/9.6") > free_space_in_directory("/var/lib/postgresql"):
            raise YunohostError("migration_0017_not_enough_space", path="/var/lib/postgresql/")

        self.runcmd("systemctl stop postgresql")
        self.runcmd("pg_dropcluster --stop 11 main")
        self.runcmd("pg_upgradecluster -m upgrade 9.6 main")
        self.runcmd("pg_dropcluster --stop 9.6 main")
        self.runcmd("systemctl start postgresql")

    def package_is_installed(self, package_name):

        (returncode, out, err) = self.runcmd("dpkg --list | grep '^ii ' | grep -q -w {}".format(package_name), raise_on_errors=False)
        return returncode == 0

    def runcmd(self, cmd, raise_on_errors=True):
        p = subprocess.Popen(cmd,
                             shell=True,
                             executable='/bin/bash',
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        out, err = p.communicate()
        returncode = p.returncode
        if raise_on_errors and returncode != 0:
            raise YunohostError("Failed to run command '{}'.\nreturncode: {}\nstdout:\n{}\nstderr:\n{}\n".format(cmd, returncode, out, err))

        out = out.strip().split("\n")
        return (returncode, out, err)

