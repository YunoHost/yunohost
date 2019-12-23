import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.permission import user_permission_list, SYSTEM_PERMS

logger = getActionLogger('yunohost.migration')

###################################################
# Tools used also for restoration
###################################################

class MyMigration(Migration):
    """
        Add protected attribute in LDAP permission
    """

    required = True

    def run(self):

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        permission_list = user_permission_list(short=True)
        
        for permission in permission_list:
            if permission in SYSTEM_PERMS:
                ldap.update('cn=%s,ou=permission' % permission, 'isProtected': "TRUE"})
            elif permission.end_with(".main"):
                ldap.update('cn=%s,ou=permission' % permission, 'isProtected': "FALSE"})
            else:
                ldap.update('cn=%s,ou=permission' % permission, 'isProtected': "TRUE"})
