import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.permission import user_permission_list
from yunohost.utils.legacy import migrate_legacy_permission_settings

logger = getActionLogger("yunohost.migration")


class MyMigration(Migration):
    """
    Add protected attribute in LDAP permission
    """

    required = True

    def add_new_ldap_attributes(self):

        from yunohost.utils.ldap import _get_ldap_interface
        from yunohost.regenconf import regen_conf, BACKUP_CONF_DIR

        # Check if the migration can be processed
        ldap_regen_conf_status = regen_conf(names=["slapd"], dry_run=True)
        # By this we check if the have been customized
        if ldap_regen_conf_status and ldap_regen_conf_status["slapd"]["pending"]:
            logger.warning(
                m18n.n(
                    "migration_0019_slapd_config_will_be_overwritten",
                    conf_backup_folder=BACKUP_CONF_DIR,
                )
            )

        # Update LDAP schema restart slapd
        logger.info(m18n.n("migration_0011_update_LDAP_schema"))
        regen_conf(names=["slapd"], force=True)

        logger.info(m18n.n("migration_0019_add_new_attributes_in_ldap"))
        ldap = _get_ldap_interface()
        permission_list = user_permission_list(full=True)["permissions"]

        for permission in permission_list:
            system_perms = {
                "mail": "E-mail",
                "xmpp": "XMPP",
                "ssh": "SSH",
                "sftp": "STFP",
            }
            if permission.split(".")[0] in system_perms:
                update = {
                    "authHeader": ["FALSE"],
                    "label": [system_perms[permission.split(".")[0]]],
                    "showTile": ["FALSE"],
                    "isProtected": ["TRUE"],
                }
            else:
                app, subperm_name = permission.split(".")
                if permission.endswith(".main"):
                    update = {
                        "authHeader": ["TRUE"],
                        "label": [
                            app
                        ],  # Note that this is later re-changed during the call to migrate_legacy_permission_settings() if a 'label' setting exists
                        "showTile": ["TRUE"],
                        "isProtected": ["FALSE"],
                    }
                else:
                    update = {
                        "authHeader": ["TRUE"],
                        "label": [subperm_name.title()],
                        "showTile": ["FALSE"],
                        "isProtected": ["TRUE"],
                    }

            ldap.update("cn=%s,ou=permission" % permission, update)

    def run(self):

        # FIXME : what do we really want to do here ...
        # Imho we should just force-regen the conf in all case, and maybe
        # just display a warning if we detect that the conf was manually modified

        # Backup LDAP and the apps settings before to do the migration
        logger.info(m18n.n("migration_0019_backup_before_migration"))
        try:
            backup_folder = "/home/yunohost.backup/premigration/" + time.strftime(
                "%Y%m%d-%H%M%S", time.gmtime()
            )
            os.makedirs(backup_folder, 0o750)
            os.system("systemctl stop slapd")
            os.system("cp -r --preserve /etc/ldap %s/ldap_config" % backup_folder)
            os.system("cp -r --preserve /var/lib/ldap %s/ldap_db" % backup_folder)
            os.system(
                "cp -r --preserve /etc/yunohost/apps %s/apps_settings" % backup_folder
            )
        except Exception as e:
            raise YunohostError(
                "migration_0019_can_not_backup_before_migration", error=e
            )
        finally:
            os.system("systemctl start slapd")

        try:
            # Update LDAP database
            self.add_new_ldap_attributes()

            # Migrate old settings
            migrate_legacy_permission_settings()

        except Exception:
            logger.warn(m18n.n("migration_0019_migration_failed_trying_to_rollback"))
            os.system("systemctl stop slapd")
            os.system(
                "rm -r /etc/ldap/slapd.d"
            )  # To be sure that we don't keep some part of the old config
            os.system("cp -r --preserve %s/ldap_config/. /etc/ldap/" % backup_folder)
            os.system("cp -r --preserve %s/ldap_db/. /var/lib/ldap/" % backup_folder)
            os.system(
                "cp -r --preserve %s/apps_settings/. /etc/yunohost/apps/"
                % backup_folder
            )
            os.system("systemctl start slapd")
            os.system("rm -r " + backup_folder)
            logger.info(m18n.n("migration_0019_rollback_success"))
            raise
        else:
            os.system("rm -r " + backup_folder)
