from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration

logger = getActionLogger("yunohost.migration")


class MyMigration(Migration):
    """
    Regen SSOwat conf to add remote_user_var_in_nginx_conf properties
    """

    introduced_in_version = "11.1"  # FIXME?
    dependencies = []

    def run(self, *args):
        from yunohost.app import app_ssowatconf
        app_ssowatconf()

    def run_after_system_restore(self):
        self.run()
