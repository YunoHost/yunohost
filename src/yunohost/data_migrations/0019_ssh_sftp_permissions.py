import time
import subprocess

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_yaml

from yunohost.tools import Migration
from yunohost.permission import user_permission_update

logger = getActionLogger('yunohost.migration')

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):
    """
        Add new permissions around SSH/SFTP features
    """

    required = True

    def run(self):
        logger.info(m18n.n("migration_0019_ssh_sftp_permissions"))

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        add_perm_to_users = False

        # Add SSH and SFTP permissions
        ldap_map = read_yaml('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml')
        for rdn, attr_dict in ldap_map['depends_children'].items():
            try:
                objects = ldap.search(rdn + ",dc=yunohost,dc=org")
            # ldap search will raise an exception if no corresponding object is found >.> ...
            except Exception as e:
                if rdn == "cn=ssh.main,ou=permission":
                    add_perm_to_users = True
                ldap.add(rdn, attr_dict)

        # Add a bash terminal to each users
        users = ldap.search('ou=users,dc=yunohost,dc=org', filter="(loginShell=*)", attrs=["dn", "uid", "loginShell"])
        for user in users:
            if user['loginShell'][0] == '/bin/false':
                dn=user['dn'][0].replace(',dc=yunohost,dc=org', '')
                ldap.update(dn, {'loginShell': ['/bin/bash']})
            elif add_perm_to_users:
                user_permission_update("ssh.main", add=user["uid"][0], sync_perm=False)

        # Somehow this is needed otherwise the PAM thing doesn't forget about the
        # old loginShell value ?
        subprocess.call(['nscd', '-i', 'passwd'])
