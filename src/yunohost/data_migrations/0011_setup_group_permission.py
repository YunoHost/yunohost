import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_yaml

from yunohost.tools import Migration
from yunohost.user import user_list, user_group_create, user_group_update
from yunohost.app import app_setting, _installed_apps
from yunohost.regenconf import regen_conf, BACKUP_CONF_DIR
from yunohost.permission import permission_create, user_permission_update, permission_sync_to_user

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

    def remove_if_exists(self, target):

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        try:
            objects = ldap.search(target + ",dc=yunohost,dc=org")
        # ldap search will raise an exception if no corresponding object is found >.> ...
        except Exception as e:
            logger.debug("%s does not exist, no need to delete it" % target)
            return

        objects.reverse()
        for o in objects:
            for dn in o["dn"]:
                dn = dn.replace(",dc=yunohost,dc=org", "")
                logger.debug("Deleting old object %s ..." % dn)
                try:
                    ldap.remove(dn)
                except Exception as e:
                    raise YunohostError("migration_0011_failed_to_remove_stale_object", dn=dn, error=e)

    def migrate_LDAP_db(self):

        logger.info(m18n.n("migration_0011_update_LDAP_database"))

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        ldap_map = read_yaml('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml')

        try:
            self.remove_if_exists("ou=permission")
            self.remove_if_exists('ou=groups')

            attr_dict = ldap_map['parents']['ou=permission']
            ldap.add('ou=permission', attr_dict)

            attr_dict = ldap_map['parents']['ou=groups']
            ldap.add('ou=groups', attr_dict)

            attr_dict = ldap_map['children']['cn=all_users,ou=groups']
            ldap.add('cn=all_users,ou=groups', attr_dict)

            attr_dict = ldap_map['children']['cn=visitors,ou=groups']
            ldap.add('cn=visitors,ou=groups', attr_dict)

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
            user_group_create(username, gid=user_info['uidNumber'][0], primary_group=True, sync_perm=False)
            user_group_update(groupname='all_users', add=username, force=True, sync_perm=False)

    def migrate_app_permission(self, app=None):
        logger.info(m18n.n("migration_0011_migrate_permission"))

        apps = _installed_apps()

        if app:
            if app not in apps:
                logger.error("Can't migrate permission for app %s because it ain't installed..." % app)
                apps = []
            else:
                apps = [app]

        for app in apps:
            permission = app_setting(app, 'allowed_users')
            path = app_setting(app, 'path')
            domain = app_setting(app, 'domain')

            url = "/" if domain and path else None
            if permission:
                known_users = user_list()["users"].keys()
                allowed = [user for user in permission.split(',') if user in known_users]
            else:
                allowed = ["all_users"]
            permission_create(app+".main", url=url, allowed=allowed, sync_perm=False)

            app_setting(app, 'allowed_users', delete=True)

            # Migrate classic public app still using the legacy unprotected_uris
            if app_setting(app, "unprotected_uris") == "/" or app_setting(app, "skipped_uris") == "/":
                user_permission_update(app+".main", add="visitors", sync_perm=False)

        permission_sync_to_user()

    def run(self):

        # FIXME : what do we really want to do here ...
        # Imho we should just force-regen the conf in all case, and maybe
        # just display a warning if we detect that the conf was manually modified

        # Check if the migration can be processed
        ldap_regen_conf_status = regen_conf(names=['slapd'], dry_run=True)
        # By this we check if the have been customized
        if ldap_regen_conf_status and ldap_regen_conf_status['slapd']['pending']:
            logger.warning(m18n.n("migration_0011_slapd_config_will_be_overwritten", conf_backup_folder=BACKUP_CONF_DIR))

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
