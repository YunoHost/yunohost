from moulinette import m18n
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.permission import user_permission_list
from yunohost.utils.legacy import migrate_legacy_permission_settings

logger = getActionLogger("yunohost.migration")


class MyMigration(Migration):
    """
    Add protected attribute in LDAP permission
    """

    @Migration.ldap_migration
    def run(self, backup_folder):

        # Update LDAP database
        self.add_new_ldap_attributes()

        # Migrate old settings
        migrate_legacy_permission_settings()

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
        logger.info(m18n.n("migration_update_LDAP_schema"))
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

    introduced_in_version = "4.1"

    def run_after_system_restore(self):
        # Update LDAP database
        self.add_new_ldap_attributes()

    def run_before_app_restore(self, app_id):
        from yunohost.app import app_setting
        from yunohost.utils.legacy import migrate_legacy_permission_settings

        # Migrate old settings
        legacy_permission_settings = [
            "skipped_uris",
            "unprotected_uris",
            "protected_uris",
            "skipped_regex",
            "unprotected_regex",
            "protected_regex",
        ]
        if any(
            app_setting(app_id, setting) is not None
            for setting in legacy_permission_settings
        ):
            migrate_legacy_permission_settings(app=app_id)
