import os

from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.user import user_group_update
from yunohost.permission import permission_sync_to_user


logger = getActionLogger('yunohost.migration')

class MyMigration(Migration):

    """Fix ldap access for visitors group"""

    def run(self):

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        # Create a group for each yunohost user
        user_list = ldap.search('ou=users,dc=yunohost,dc=org',
                                '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))',
                                ['uid', 'uidNumber'])
        for user_info in user_list:
            username = user_info['uid'][0]
            user_group_update(groupname='visitors', add=username, force=True, sync_perm=False)
        
        permission_sync_to_user()


