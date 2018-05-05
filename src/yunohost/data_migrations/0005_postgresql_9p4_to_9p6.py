import subprocess

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    "Migrate DBs from Postgresql 9.4 to 9.6 after migrating to Stretch"


    def migrate(self):

        if not self.package_is_installed("postgresql-9.4"):
            logger.warning(m18n.n("migration_0005_postgresql_94_not_installed"))
            return

        if not self.package_is_installed("postgresql-9.6"):
            raise MoulinetteError(m18n.n("migration_0005_postgresql_96_not_installed"))

        # FIXME / TODO : maybe add checks about the size of
        #  /var/lib/postgresql/9.4/main/base/ compared to available space ?

        subprocess.check_call("service postgresql stop", shell=True)
        subprocess.check_call("pg_dropcluster --stop 9.6 main", shell=True)
        subprocess.check_call("pg_upgradecluster -m upgrade 9.4 main", shell=True)
        subprocess.check_call("pg_dropcluster --stop 9.4 main", shell=True)
        subprocess.check_call("service postgresql start", shell=True)

    def backward(self):

        pass


    def package_is_installed(self, package_name):

        p = subprocess.Popen("dpkg --list | grep -q -w {}".format(package_name), shell=True)
        p.communicate()
        return p.returncode == 0
