from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_yaml

from yunohost.user import user_list, user_group_create, user_group_update
from yunohost.app import app_setting, _installed_apps
from yunohost.permission import permission_create, user_permission_update, permission_sync_to_user

logger = getActionLogger('yunohost.legacy')


class SetupGroupPermissions():

    @staticmethod
    def remove_if_exists(target):

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
                    raise YunohostError("migration_0019_failed_to_remove_stale_object", dn=dn, error=e)

    @staticmethod
    def migrate_LDAP_db():

        logger.info(m18n.n("migration_0019_update_LDAP_database"))

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        ldap_map = read_yaml('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml')

        try:
            SetupGroupPermissions.remove_if_exists("ou=permission")
            SetupGroupPermissions.remove_if_exists('ou=groups')

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
            raise YunohostError("migration_0019_LDAP_update_failed", error=e)

        logger.info(m18n.n("migration_0019_create_group"))

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

    @staticmethod
    def migrate_app_permission(app=None):
        logger.info(m18n.n("migration_0019_migrate_permission"))

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
            permission_create(app + ".main", url=url, allowed=allowed, protected=False, sync_perm=False)

            app_setting(app, 'allowed_users', delete=True)

            # Migrate classic public app still using the legacy unprotected_uris
            if app_setting(app, "unprotected_uris") == "/" or app_setting(app, "skipped_uris") == "/":
                user_permission_update(app + ".main", add="visitors", sync_perm=False)

        permission_sync_to_user()


LEGACY_PERMISSION_LABEL = {
    ("nextcloud", "skipped"): "api",              # .well-known
    ("libreto", "skipped"): "pad access",         # /[^/]+
    ("leed", "skipped"): "api",                   # /action.php, for cron task ...
    ("mailman", "protected"): "admin",            # /admin
    ("prettynoemiecms", "protected"): "admin",    # /admin
    ("etherpad_mypads", "skipped"): "admin",      # /admin
    ("baikal", "protected"): "admin",             # /admin/
    ("couchpotato", "unprotected"): "api",        # /api
    ("freshrss", "skipped"): "api",               # /api/,
    ("portainer", "skipped"): "api",              # /api/webhooks/
    ("jeedom", "unprotected"): "api",             # /core/api/jeeApi.php
    ("bozon", "protected"): "user interface",     # /index.php
    ("limesurvey", "protected"): "admin",         # /index.php?r=admin,/index.php?r=plugins,/scripts
    ("kanboard", "unprotected"): "api",           # /jsonrpc.php
    ("seafile", "unprotected"): "medias",         # /media
    ("ttrss", "skipped"): "api",                  # /public.php,/api,/opml.php?op=publish
    ("libreerp", "protected"): "admin",           # /web/database/manager
    ("z-push", "skipped"): "api",                 # $domain/[Aa]uto[Dd]iscover/.*
    ("radicale", "skipped"): "?",                 # $domain$path_url
    ("jirafeau", "protected"): "user interface",  # $domain$path_url/$","$domain$path_url/admin.php.*$
    ("opensondage", "protected"): "admin",        # $domain$path_url/admin/
    ("lstu", "protected"): "user interface",      # $domain$path_url/login$","$domain$path_url/logout$","$domain$path_url/api$","$domain$path_url/extensions$","$domain$path_url/stats$","$domain$path_url/d/.*$","$domain$path_url/a$","$domain$path_url/$
    ("lutim", "protected"): "user interface",     # $domain$path_url/stats/?$","$domain$path_url/manifest.webapp/?$","$domain$path_url/?$","$domain$path_url/[d-m]/.*$
    ("lufi", "protected"): "user interface",      # $domain$path_url/stats$","$domain$path_url/manifest.webapp$","$domain$path_url/$","$domain$path_url/d/.*$","$domain$path_url/m/.*$
    ("gogs", "skipped"): "api",                   # $excaped_domain$excaped_path/[%w-.]*/[%w-.]*/git%-receive%-pack,$excaped_domain$excaped_path/[%w-.]*/[%w-.]*/git%-upload%-pack,$excaped_domain$excaped_path/[%w-.]*/[%w-.]*/info/refs
}


def legacy_permission_label(app, permission_type):
    return LEGACY_PERMISSION_LABEL.get((app, permission_type), "Legacy %s urls" % permission_type)
