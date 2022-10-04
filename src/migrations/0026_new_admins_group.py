from moulinette.utils.log import getActionLogger

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

        from yunohost.user import user_list, user_info, user_group_update, user_update
        from yunohost.utils.ldap import _get_ldap_interface
        from yunohost.permission import permission_sync_to_user

        ldap = _get_ldap_interface()

        all_users = user_list()["users"].keys()
        new_admin_user = None
        for user in all_users:
            if any(alias.startswith("root@") for alias in user_info(user).get("mail-aliases", [])):
                new_admin_user = user
                break

        self.ldap_migration_started = True

        if new_admin_user:
            aliases = user_info(new_admin_user).get("mail-aliases", [])
            old_admin_aliases_to_remove = [alias for alias in aliases if any(alias.startswith(a) for a in ["root@", "admin@", "admins@", "webmaster@", "postmaster@", "abuse@"])]

            user_update(new_admin_user, remove_mailalias=old_admin_aliases_to_remove)

        admin_hashs = ldap.search("cn=admin", attrs={"userPassword"})[0]["userPassword"]

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

        permission_sync_to_user()

        if new_admin_user:
            user_group_update(groupname="admins", add=new_admin_user, sync_perm=True)

        # Re-add admin as a regular user
        attr_dict = {
            "objectClass": [
                "mailAccount",
                "inetOrgPerson",
                "posixAccount",
                "userPermissionYnh",
            ],
            "givenName": ["Admin"],
            "sn": ["Admin"],
            "displayName": ["Admin"],
            "cn": ["Admin"],
            "uid": ["admin"],
            "mail": "admin_legacy",
            "maildrop": ["admin"],
            "mailuserquota": ["0"],
            "userPassword": admin_hashs,
            "gidNumber": ["1007"],
            "uidNumber": ["1007"],
            "homeDirectory": ["/home/admin"],
            "loginShell": ["/bin/bash"],
        }
        ldap.add("uid=admin,ou=users", attr_dict)
        user_group_update(groupname="admins", add="admin", sync_perm=True)


    def run_after_system_restore(self):
        self.run()
