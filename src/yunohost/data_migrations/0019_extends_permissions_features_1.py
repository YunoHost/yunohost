import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.app import app_setting, _installed_apps
from yunohost.permission import user_permission_list, permission_create, permission_sync_to_user
from yunohost.utils.legacy import legacy_permission_label

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    """
        Add protected attribute in LDAP permission
    """

    required = True

    def add_new_ldap_attributes(self):

        from yunohost.utils.ldap import _get_ldap_interface
        from yunohost.regenconf import regen_conf, BACKUP_CONF_DIR

        # Check if the migration can be processed
        ldap_regen_conf_status = regen_conf(names=['slapd'], dry_run=True)
        # By this we check if the have been customized
        if ldap_regen_conf_status and ldap_regen_conf_status['slapd']['pending']:
            logger.warning(m18n.n("migration_0019_slapd_config_will_be_overwritten", conf_backup_folder=BACKUP_CONF_DIR))

        # Update LDAP schema restart slapd
        logger.info(m18n.n("migration_0019_update_LDAP_schema"))
        regen_conf(names=['slapd'], force=True)

        logger.info(m18n.n("migration_0019_add_new_attributes_in_ldap"))
        ldap = _get_ldap_interface()
        permission_list = user_permission_list(short=True, full_path=False)["permissions"]

        labels = {}
        for app in _installed_apps():
            labels[app] = app_setting(app, 'label')
            app_setting(app, 'label', delete=True)

        for permission in permission_list:
            if permission.split('.')[0] == 'mail':
                ldap.update('cn=%s,ou=permission' % permission, {
                    'authHeader': ["FALSE"],
                    'label': ['E-mail'],
                    'showTile': ["FALSE"],
                    'isProtected': ["TRUE"],
                })
            elif permission.split('.')[0] == 'xmpp':
                ldap.update('cn=%s,ou=permission' % permission, {
                    'authHeader': ["FALSE"],
                    'label': ['XMPP'],
                    'showTile': ["FALSE"],
                    'isProtected': ["TRUE"],
                })
            else:
                label = labels[permission.split('.')[0]].title()

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
                        'label': [permission.split('.')[1]],
                        'showTile': ["FALSE"],
                        'isProtected': ["TRUE"]
                    })

    def migrate_skipped_unprotected_protected_uris(self, app=None):

        logger.info(m18n.n("migration_0019_migrate_old_app_settings"))
        apps = _installed_apps()

        if app:
            if app not in apps:
                logger.error("Can't migrate permission for app %s because it ain't installed..." % app)
                apps = []
            else:
                apps = [app]

        def _get_setting(app, name):
            s = app_setting(app, name)
            return s.split(',') if s else []

        for app in apps:
            skipped_urls = [uri for uri in _get_setting(app, 'skipped_uris') if uri != '/']
            skipped_urls += ['re:' + regex for regex in _get_setting(app, 'skipped_regex')]
            unprotected_urls = [uri for uri in _get_setting(app, 'unprotected_uris') if uri != '/']
            unprotected_urls += ['re:' + regex for regex in _get_setting(app, 'unprotected_regex')]
            protected_urls = [uri for uri in _get_setting(app, 'protected_uris') if uri != '/']
            protected_urls += ['re:' + regex for regex in _get_setting(app, 'protected_regex')]

            if skipped_urls != []:
                permission_create(app + ".legacy_skipped_uris", additional_urls=skipped_urls,
                                  auth_header=False, label=legacy_permission_label(app, "skipped"),
                                  show_tile=False, allowed='visitors', protected=True, sync_perm=False)
            if unprotected_urls != []:
                permission_create(app + ".legacy_unprotected_uris", additional_urls=unprotected_urls,
                                  auth_header=True, label=legacy_permission_label(app, "unprotected"),
                                  show_tile=False, allowed='visitors', protected=True, sync_perm=False)
            if protected_urls != []:
                permission_create(app + ".legacy_protected_uris", additional_urls=protected_urls,
                                  auth_header=True, label=legacy_permission_label(app, "protected"),
                                  show_tile=False, allowed=user_permission_list()['permissions'][app + ".main"]['allowed'],
                                  protected=True, sync_perm=False)

            app_setting(app, 'skipped_uris', delete=True)
            app_setting(app, 'unprotected_uris', delete=True)
            app_setting(app, 'protected_uris', delete=True)

        permission_sync_to_user()

    def run(self):

        # FIXME : what do we really want to do here ...
        # Imho we should just force-regen the conf in all case, and maybe
        # just display a warning if we detect that the conf was manually modified

        # Backup LDAP and the apps settings before to do the migration
        logger.info(m18n.n("migration_0019_backup_before_migration"))
        try:
            backup_folder = "/home/yunohost.backup/premigration/" + time.strftime('%Y%m%d-%H%M%S', time.gmtime())
            os.makedirs(backup_folder, 0o750)
            os.system("systemctl stop slapd")
            os.system("cp -r --preserve /etc/ldap %s/ldap_config" % backup_folder)
            os.system("cp -r --preserve /var/lib/ldap %s/ldap_db" % backup_folder)
            os.system("cp -r --preserve /etc/yunohost/apps %s/apps_settings" % backup_folder)
        except Exception as e:
            raise YunohostError("migration_0019_can_not_backup_before_migration", error=e)
        finally:
            os.system("systemctl start slapd")

        try:
            # Update LDAP database
            self.add_new_ldap_attributes()

            # Migrate old settings
            self.migrate_skipped_unprotected_protected_uris()

        except Exception as e:
            logger.warn(m18n.n("migration_0019_migration_failed_trying_to_rollback"))
            os.system("systemctl stop slapd")
            os.system("rm -r /etc/ldap/slapd.d")  # To be sure that we don't keep some part of the old config
            os.system("cp -r --preserve %s/ldap_config/. /etc/ldap/" % backup_folder)
            os.system("cp -r --preserve %s/ldap_db/. /var/lib/ldap/" % backup_folder)
            os.system("cp -r --preserve %s/apps_settings/. /etc/yunohost/apps/" % backup_folder)
            os.system("systemctl start slapd")
            os.system("rm -r " + backup_folder)
            logger.info(m18n.n("migration_0019_rollback_success"))
            raise
        else:
            os.system("rm -r " + backup_folder)
