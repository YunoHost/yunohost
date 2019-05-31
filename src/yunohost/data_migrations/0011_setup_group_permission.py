import yaml
import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.user import user_group_add, user_group_update
from yunohost.app import app_setting, app_list
from yunohost.regenconf import regen_conf
from yunohost.permission import permission_add, permission_sync_to_user
from yunohost.user import user_permission_add

logger = getActionLogger('yunohost.migration')

###################################################
# Tools used also for restoration
###################################################

class MyMigration(Migration):
    """
        Update the LDAP DB to be able to store the permission
        Create a group for each yunohost user
        Migrate app permission from apps setting to LDAP
    """

    required = True

    def migrate_LDAP_db(self):

        logger.info(m18n.n("migration_0011_update_LDAP_database"))

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        try:
            ldap.remove('cn=sftpusers,ou=groups')
        except:
            logger.warn(m18n.n("error_when_removing_sftpuser_group"))

        with open('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml') as f:
            ldap_map = yaml.load(f)

        try:
            attr_dict = ldap_map['parents']['ou=permission']
            ldap.add('ou=permission', attr_dict)

            attr_dict = ldap_map['children']['cn=all_users,ou=groups']
            ldap.add('cn=all_users,ou=groups', attr_dict)

            for rdn, attr_dict in ldap_map['depends_children'].items():
                ldap.add(rdn, attr_dict)
        except Exception as e:
            raise YunohostError("migration_0011_LDAP_update_failed", error=e)

        logger.info(m18n.n("migration_0011_create_group"))

        # Create a group for each yunohost user
        user_list = ldap.search('ou=users,dc=yunohost,dc=org',
                                '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))',
                                ['uid', 'uidNumber'])
        for user_info in user_list:
            username = user_info['uid'][0]
            ldap.update('uid=%s,ou=users' % username,
                        {'objectClass': ['mailAccount', 'inetOrgPerson', 'posixAccount', 'userPermissionYnh']})
            user_group_add(username, gid=user_info['uidNumber'][0], sync_perm=False)
            user_group_update(groupname=username, add_user=username, force=True, sync_perm=False)
            user_group_update(groupname='all_users', add_user=username, force=True, sync_perm=False)


    def migrate_app_permission(self, app=None):
        logger.info(m18n.n("migration_0011_migrate_permission"))

        if app:
            apps = app_list(installed=True, filter=app)['apps']
        else:
            apps = app_list(installed=True)['apps']

        for app_info in apps:
            app = app_info['id']
            permission = app_setting(app, 'allowed_users')
            path = app_setting(app, 'path')
            domain = app_setting(app, 'domain')

            urls = [domain + path] if domain and path else None
            permission_add(app, permission='main', urls=urls, default_allow=True, sync_perm=False)
            if permission:
                allowed_group = permission.split(',')
                user_permission_add([app], permission='main', group=allowed_group, sync_perm=False)
            app_setting(app, 'allowed_users', delete=True)


    def migrate(self):
        # Check if the migration can be processed
        ldap_regen_conf_status = regen_conf(names=['slapd'], dry_run=True)
        # By this we check if the have been customized
        if ldap_regen_conf_status and ldap_regen_conf_status['slapd']['pending']:
            raise YunohostError("migration_0011_LDAP_config_dirty")

        # Backup LDAP and the apps settings before to do the migration
        logger.info(m18n.n("migration_0011_backup_before_migration"))
        try:
            backup_folder = "/home/yunohost.backup/premigration/" + time.strftime('%Y%m%d-%H%M%S', time.gmtime())
            os.makedirs(backup_folder, 0o750)
            os.system("systemctl stop slapd")
            os.system("cp -r --preserve /etc/ldap %s/ldap_config" % backup_folder)
            os.system("cp -r --preserve /var/lib/ldap %s/ldap_db" % backup_folder)
            os.system("cp -r --preserve /etc/yunohost/apps %s/apps_settings" % backup_folder)
        except Exception as e:
            raise YunohostError("migration_0011_can_not_backup_before_migration", error=e)
        finally:
            os.system("systemctl start slapd")

        try:
            # Update LDAP schema restart slapd
            logger.info(m18n.n("migration_0011_update_LDAP_schema"))
            regen_conf(names=['slapd'], force=True)

            # Update LDAP database
            self.migrate_LDAP_db()

            # Migrate permission
            self.migrate_app_permission()

            permission_sync_to_user()
        except Exception as e:
            logger.warn(m18n.n("migration_0011_migration_failed_trying_to_rollback"))
            os.system("systemctl stop slapd")
            os.system("rm -r /etc/ldap/slapd.d")  # To be sure that we don't keep some part of the old config
            os.system("cp -r --preserve %s/ldap_config/. /etc/ldap/" % backup_folder)
            os.system("cp -r --preserve %s/ldap_db/. /var/lib/ldap/" % backup_folder)
            os.system("cp -r --preserve %s/apps_settings/. /etc/yunohost/apps/" % backup_folder)
            os.system("systemctl start slapd")
            os.system("rm -r " + backup_folder)
            logger.info(m18n.n("migration_0011_rollback_success"))
            raise
        else:
            os.system("rm -r " + backup_folder)

            logger.info(m18n.n("migration_0011_done"))
