from logging import getLogger

from yunohost.tools import Migration
from yunohost.regenconf import regen_conf
from yunohost.permission import permission_sync_to_user
from yunohost.app import app_setting

logger = getLogger("yunohost.migration")

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):

    introduced_in_version = "12.1"
    dependencies = []

    ldap_migration_started = False

    @Migration.ldap_migration
    def run(self, *args):

        regen_conf(["slapd"], force=True)

        self.ldap_migration_started = True

        permissions_per_app = self.read_legacy_permissions_per_app()
        for app, permissions in permissions_per_app.items():
            app_setting(app, "_permissions", permissions)

        permission_sync_to_user()

    def run_after_system_restore(self):
        self.run()

    def read_legacy_permissions_per_app(self):

        from yunohost.utils.ldap import _get_ldap_interface
        SYSTEM_PERMS = ["mail", "sftp", "ssh"]

        ldap = _get_ldap_interface()
        permissions_infos = ldap.search(
            "ou=permission",
            "(objectclass=permissionYnh)",
            [
                "cn",
                "URL",
                "additionalUrls",
                "authHeader",
                "label",
                "showTile",
                "isProtected",
            ],
        )

        permissions_per_app = {}
        for infos in permissions_infos:
            app, name = infos["cn"][0].split(".")

            # LDAP won't delete the old, obsolete info, we have to do it ourselves ~_~
            ldap.update(f'cn={infos["cn"][0]},ou=permission', {
                'label': [],
                'authHeader': [],
                'showTile': [],
                'isProtected': [],
                'URL': [],
                'additionalUrls': []
            })

            if app in SYSTEM_PERMS:
                continue

            if app not in permissions_per_app:
                permissions_per_app[app] = {}

            permissions_per_app[app][name] = {
                "label": infos.get("label", [None])[0],
                "show_tile": infos.get("showTile", [False])[0] == "TRUE",
                "auth_header": infos.get("authHeader", [False])[0] == "TRUE",
                "protected": infos.get("isProtected", [False])[0] == "TRUE",
                "url": infos.get("URL", [None])[0],
                "additional_urls": infos.get("additionalUrls", []),
            }

        return permissions_per_app
