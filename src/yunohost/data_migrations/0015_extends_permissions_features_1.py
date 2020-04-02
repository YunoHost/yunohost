import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.app import app_setting
from yunohost.permission import user_permission_list, SYSTEM_PERMS

logger = getActionLogger('yunohost.migration')

class MyMigration(Migration):
    """
        Add protected attribute in LDAP permission
    """

    required = True

    def run(self):

        from yunohost.utils.ldap import _get_ldap_interface
        from yunohost.regenconf import regen_conf, BACKUP_CONF_DIR

        # Check if the migration can be processed
        ldap_regen_conf_status = regen_conf(names=['slapd'], dry_run=True)
        # By this we check if the have been customized
        if ldap_regen_conf_status and ldap_regen_conf_status['slapd']['pending']:
            logger.warning(m18n.n("migration_0011_slapd_config_will_be_overwritten", conf_backup_folder=BACKUP_CONF_DIR))

        regen_conf(names=['slapd'], force=True)

        ldap = _get_ldap_interface()

        permission_list = user_permission_list(short=True)["permissions"]

        for permission in permission_list:
            if permission.split('.')[0] in SYSTEM_PERMS:
                ldap.update('cn=%s,ou=permission' % permission, {
                    'authHeader': ["FALSE"],
                    'label': [permission.split('.')[0]],
                    'showTile': ["FALSE"],
                    'isProtected': ["TRUE"],
                })
            else:
                label = app_setting(permission.split('.')[0], 'label')

                if permission.endswith(".main"):
                    ldap.update('cn=%s,ou=permission' % permission, {
                        'authHeader': ["TRUE"],
                        'label': [label],
                        'showTile': ["TRUE"],
                        'isProtected': ["FALSE"]
                    })
                else:
                    ldap.update('cn=%s,ou=permission' % permission, {
                        'authHeader': ["TRUE"],
                        'label': ["%s (%s)" (label, permission.split('.')[1])],
                        'showTile': ["FALSE"],
                        'isProtected': ["TRUE"]
                    })
                app_setting(permission.split('.')[0], 'label', delete=True)
