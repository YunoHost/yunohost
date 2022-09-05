import os
from moulinette.utils.log import getActionLogger

from yunohost.utils.error import YunohostError
from yunohost.tools import Migration

logger = getActionLogger("yunohost.migration")

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):
    """
    Add new permissions around SSH/SFTP features
    """

    introduced_in_version = "11.1"  # FIXME?
    dependencies = []

    ldap_migration_started = False

    @Migration.ldap_migration
    def run(self, *args):

        from yunohost.user import user_list, user_info, user_group_update
        from yunohost.utils.ldap import _get_ldap_interface

        ldap = _get_ldap_interface()

        all_users = user_list()["users"].keys()
        new_admin_user = None
        for user in all_users:
            if any(alias.startswith("root@") for alias in user_info(user).get("mail-aliases", [])):
                new_admin_user = user
                break

        if not new_admin_user:
            new_admin_user = os.environ.get("YNH_NEW_ADMIN_USER")
            if new_admin_user:
                assert new_admin_user in all_users, f"{new_admin_user} is not an existing yunohost user"
            else:
                raise YunohostError(
                    # FIXME: i18n
                    """The very first user created on this Yunohost instance could not be found, and therefore this migration can not be ran. You should re-run this migration as soon as possible from the command line with, after choosing which user should become the admin:

export YNH_NEW_ADMIN_USER=some_existing_username
yunohost tools migrations run""",
                    raw_msg=True
                )

        self.ldap_migration_started = True

        stuff_to_delete = [
            "cn=admin,ou=sudo",
            "cn=admin",
            "cn=admins,ou=groups",
        ]

        for stuff in stuff_to_delete:
            if ldap.search(stuff):
                ldap.remove(stuff)

        ldap.add(
            "cn=admins,ou=sudo",
            {
                "cn": ["admins"],
                "objectClass": ["top", "sudoRole"],
                "sudoCommand": ["ALL"],
                "sudoUser": ["%admins"],
                "sudoHost": ["ALL"],
            }
        )

        ldap.add(
            "cn=admins,ou=groups",
            {
                "cn": ["admins"],
                "objectClass": ["top", "posixGroup", "groupOfNamesYnh", "mailGroup"],
                "gidNumber": ["4001"],
                "mail": ["root", "admin", "admins", "webmaster", "postmaster", "abuse"],
            }
        )

        user_group_update(groupname="admins", add=new_admin_user, sync_perm=True)

    def run_after_system_restore(self):
        self.run()
