import subprocess

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.utils.filesystem import free_space_in_directory, space_used_by_directory

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):

    "Migrate DBs from Postgresql 9.4 to 9.6 after migrating to Stretch"

    def migrate(self):

        if not self.package_is_installed("postgresql-9.4"):
            logger.warning(m18n.n("migration_0005_postgresql_94_not_installed"))
            return

        if not self.package_is_installed("postgresql-9.6"):
            raise YunohostError("migration_0005_postgresql_96_not_installed")

        if not space_used_by_directory("/var/lib/postgresql/9.4") > free_space_in_directory("/var/lib/postgresql"):
            raise YunohostError("migration_0005_not_enough_space", path="/var/lib/postgresql/")

        subprocess.check_call("service postgresql stop", shell=True)
        subprocess.check_call("pg_dropcluster --stop 9.6 main", shell=True)
        subprocess.check_call("pg_upgradecluster -m upgrade 9.4 main", shell=True)
        subprocess.check_call("pg_dropcluster --stop 9.4 main", shell=True)
        subprocess.check_call("service postgresql start", shell=True)

    def backward(self):

        pass

    def package_is_installed(self, package_name):

        p = subprocess.Popen("dpkg --list | grep '^ii ' | grep -q -w {}".format(package_name), shell=True)
        p.communicate()
        return p.returncode == 0
