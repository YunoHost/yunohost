from logging import getLogger

from yunohost.tools import Migration

logger = getLogger("yunohost.migration")

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):
    """
    Delete legacy XMPP permission
    """

    introduced_in_version = "12.0"
    dependencies = []

    ldap_migration_started = False

    @Migration.ldap_migration
    def run(self, *args):
        from yunohost.permission import user_permission_list, permission_delete

        self.ldap_migration_started = True

        if "xmpp.main" in user_permission_list()["permissions"]:
            permission_delete("xmpp.main", force=True)

    def run_after_system_restore(self):
        self.run()
