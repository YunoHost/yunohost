import subprocess
import os

from moulinette import m18n
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.permission import user_permission_update, permission_sync_to_user
from yunohost.regenconf import manually_modified_files

logger = getActionLogger("yunohost.migration")

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):
    """
    Add new permissions around SSH/SFTP features
    """

    introduced_in_version = "4.2.2"
    dependencies = ["extend_permissions_features"]

    @Migration.ldap_migration
    def run(self, *args):

        from yunohost.utils.ldap import _get_ldap_interface

        ldap = _get_ldap_interface()

        existing_perms_raw = ldap.search(
            "ou=permission,dc=yunohost,dc=org", "(objectclass=permissionYnh)", ["cn"]
        )
        existing_perms = [perm["cn"][0] for perm in existing_perms_raw]

        # Add SSH and SFTP permissions
        if "sftp.main" not in existing_perms:
            ldap.add(
                "cn=sftp.main,ou=permission",
                {
                    "cn": "sftp.main",
                    "gidNumber": "5004",
                    "objectClass": ["posixGroup", "permissionYnh"],
                    "groupPermission": [],
                    "authHeader": "FALSE",
                    "label": "SFTP",
                    "showTile": "FALSE",
                    "isProtected": "TRUE",
                },
            )

        if "ssh.main" not in existing_perms:
            ldap.add(
                "cn=ssh.main,ou=permission",
                {
                    "cn": "ssh.main",
                    "gidNumber": "5003",
                    "objectClass": ["posixGroup", "permissionYnh"],
                    "groupPermission": [],
                    "authHeader": "FALSE",
                    "label": "SSH",
                    "showTile": "FALSE",
                    "isProtected": "TRUE",
                },
            )

            # Add a bash terminal to each users
            users = ldap.search(
                "ou=users,dc=yunohost,dc=org",
                filter="(loginShell=*)",
                attrs=["dn", "uid", "loginShell"],
            )
            for user in users:
                if user["loginShell"][0] == "/bin/false":
                    dn = user["dn"][0].replace(",dc=yunohost,dc=org", "")
                    ldap.update(dn, {"loginShell": ["/bin/bash"]})
                else:
                    user_permission_update(
                        "ssh.main", add=user["uid"][0], sync_perm=False
                    )

            permission_sync_to_user()

            # Somehow this is needed otherwise the PAM thing doesn't forget about the
            # old loginShell value ?
            subprocess.call(["nscd", "-i", "passwd"])

        if (
            "/etc/ssh/sshd_config" in manually_modified_files()
            and os.system(
                "grep -q '^ *AllowGroups\\|^ *AllowUsers' /etc/ssh/sshd_config"
            )
            != 0
        ):
            logger.error(m18n.n("diagnosis_sshd_config_insecure"))

    def run_after_system_restore(self):
        self.run()
