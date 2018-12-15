import yaml

from moulinette import m18n
from moulinette.core import init_authenticator
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.utils.filesystem import free_space_in_directory, space_used_by_directory
from yunohost.user import user_list, user_group_add, user_group_update
from yunohost.app import app_setting, app_list
from yunohost.service import service_regen_conf
from yunohost.permission import permission_add, permission_sync_to_user
from yunohost.user import user_permission_add

logger = getActionLogger('yunohost.migration')

###################################################
# Tools used also for restoration
###################################################

def migrate_LDAP_db(auth):
    logger.info(m18n.n("migration_0009_update_LDAP_database"))
    try:
        auth.remove('cn=sftpusers,ou=groups')
    except Exception as e:
        logger.warn("Error when trying remove sftpusers group")

    with open('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml') as f:
        ldap_map = yaml.load(f)

    try:
        attr_dict = ldap_map['parents']['ou=permission']
        auth.add('ou=permission', attr_dict)

        attr_dict = ldap_map['children']['cn=all_users,ou=groups']
        auth.add('cn=all_users,ou=groups', attr_dict)

        for rdn, attr_dict in ldap_map['depends_children'].items():
            auth.add(rdn, attr_dict)
    except Exception as e:
        raise YunohostError("LDAP_update_failled")

    logger.info(m18n.n("migration_0009_create_group"))

    #Create group for each yunohost user
    user_list = auth.search('ou=users,dc=yunohost,dc=org',
                            '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))',
                            ['uid', 'uidNumber'])
    for user_info in user_list:
        username = user_info['uid'][0]
        user_group_add(auth, username, gid=user_info['uidNumber'][0], sync_perm=False)
        user_group_update(auth, groupname=username, add_user=username, force=True, sync_perm=False)
        user_group_update(auth, 'all_users', add_user=username, force=True, sync_perm=False)


def migrate_app_permission(auth, app=None):
    logger.info(m18n.n("migration_0009_migrate_permission"))

    if app:
        apps = app_list(installed=True, filter=app)['apps']
    else:
        apps = app_list(installed=True)['apps']

    for app_info in apps:
        app = app_info['id']
        permission = app_setting(app, 'allowed_users')
        path = app_setting(app, 'path')
        domain = app_setting(app, 'domain')

        url = None
        if domain and path:
            url = domain + path
        permission_add(auth, app, 'main', url=url, default_allow=True, sync_perm=False)
        if permission:
            allowed_group = permission.split(',')
            user_permission_add(auth, [app], 'main', group=allowed_group, sync_perm=False)
        app_setting(app, 'allowed_users', delete=True)


class MyMigration(Migration):
    """
        Update the LDAP DB to be able to store the permission
        Create a group for each yunohost user
        Migrate app permission from apps setting to LDAP
    """

    required = True

    def migrate(self):
        # Update LDAP schema restart slapd
        logger.info(m18n.n("migration_0009_update_LDAP_schema"))
        service_regen_conf(names=['slapd'], force=True)

        # Do the authentication to LDAP after LDAP as been updated
        AUTH_IDENTIFIER = ('ldap', 'as-root')
        AUTH_PARAMETERS = {'uri': 'ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi',
                           'base_dn': 'dc=yunohost,dc=org',
                           'user_rdn': 'gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth'}
        auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

        #Update LDAP database
        migrate_LDAP_db(auth)

        # Migrate permission
        migrate_app_permission(auth)

        permission_sync_to_user(auth)
        logger.info(m18n.n("migration_0009_done"))

    @property
    def disclaimer(self):
        return m18n.n("migration_0009_disclaimer")
