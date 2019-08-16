import pytest

from moulinette.core import MoulinetteError
from yunohost.app import app_install, app_remove, app_change_url, app_list
from yunohost.user import user_list, user_create, user_permission_list, user_delete, user_group_list, user_group_delete, user_permission_add, user_permission_remove, user_permission_clear
from yunohost.permission import permission_add, permission_update, permission_remove
from yunohost.domain import _get_maindomain
from yunohost.utils.error import YunohostError

# Get main domain
maindomain = _get_maindomain()

def clean_user_groups_permission():
    for u in user_list()['users']:
        user_delete(u)

    for g in user_group_list()['groups']:
        if g != "all_users":
            user_group_delete(g)

    for a, per in user_permission_list()['permissions'].items():
        if a in ['wiki', 'blog', 'site']:
            for p in per:
                permission_remove(a, p, force=True, sync_perm=False)

def setup_function(function):
    clean_user_groups_permission()

    user_create("alice", "Alice", "White", "alice@" + maindomain, "test123Ynh")
    user_create("bob", "Bob", "Snow", "bob@" + maindomain, "test123Ynh")
    permission_add("wiki", "main", [maindomain + "/wiki"], sync_perm=False)
    permission_add("blog", "main", sync_perm=False)

    user_permission_add(["blog"], "main", group="alice")

def teardown_function(function):
    clean_user_groups_permission()
    try:
        app_remove("permissions_app")
    except:
        pass

@pytest.fixture(autouse=True)
def check_LDAP_db_integrity_call():
    check_LDAP_db_integrity()
    yield
    check_LDAP_db_integrity()

def check_LDAP_db_integrity():
    # Here we check that all attributes in all object are sychronized.
    # Here is the list of attributes per object:
    # user : memberOf, permission
    # group : member, permission
    # permission : groupPermission, inheritPermission
    #
    # The idea is to check that all attributes on all sides of object are sychronized.
    # One part should be done automatically by the "memberOf" overlay of LDAP.
    # The other part is done by the the "permission_sync_to_user" function of the permission module

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    user_search = ldap.search('ou=users,dc=yunohost,dc=org',
                              '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))',
                              ['uid', 'memberOf', 'permission'])
    group_search = ldap.search('ou=groups,dc=yunohost,dc=org',
                               '(objectclass=groupOfNamesYnh)',
                               ['cn', 'member', 'memberUid', 'permission'])
    permission_search = ldap.search('ou=permission,dc=yunohost,dc=org',
                                    '(objectclass=permissionYnh)',
                                    ['cn', 'groupPermission', 'inheritPermission', 'memberUid'])

    user_map = {u['uid'][0]: u for u in user_search}
    group_map = {g['cn'][0]: g for g in group_search}
    permission_map = {p['cn'][0]: p for p in permission_search}

    for user in user_search:
        user_dn = 'uid=' + user['uid'][0] + ',ou=users,dc=yunohost,dc=org'
        group_list = [m.split("=")[1].split(",")[0] for m in user['memberOf']]
        permission_list = []
        if 'permission' in user:
            permission_list = [m.split("=")[1].split(",")[0] for m in user['permission']]

        for group in group_list:
            assert user_dn in group_map[group]['member']
        for permission in permission_list:
            assert user_dn in permission_map[permission]['inheritPermission']

    for permission in permission_search:
        permission_dn = 'cn=' + permission['cn'][0] + ',ou=permission,dc=yunohost,dc=org'
        user_list = []
        group_list = []
        if 'inheritPermission' in permission:
            user_list = [m.split("=")[1].split(",")[0] for m in permission['inheritPermission']]
            assert set(user_list) == set(permission['memberUid'])
        if 'groupPermission' in permission:
            group_list = [m.split("=")[1].split(",")[0] for m in permission['groupPermission']]

        for user in user_list:
            assert permission_dn in user_map[user]['permission']
        for group in group_list:
            assert permission_dn in group_map[group]['permission']
            if 'member' in group_map[group]:
                user_list_in_group = [m.split("=")[1].split(",")[0] for m in group_map[group]['member']]
                assert set(user_list_in_group) <= set(user_list)

    for group in group_search:
        group_dn = 'cn=' + group['cn'][0] + ',ou=groups,dc=yunohost,dc=org'
        user_list = []
        permission_list = []
        if 'member' in group:
            user_list = [m.split("=")[1].split(",")[0] for m in group['member']]
            if group['cn'][0] in user_list:
                # If it's the main group of the user it's normal that it is not in the memberUid
                g_list = list(user_list)
                g_list.remove(group['cn'][0])
                if 'memberUid' in group:
                    assert set(g_list) == set(group['memberUid'])
                else:
                    assert g_list == []
            else:
                assert set(user_list) == set(group['memberUid'])
        if 'permission' in group:
            permission_list = [m.split("=")[1].split(",")[0] for m in group['permission']]

        for user in user_list:
            assert group_dn in user_map[user]['memberOf']
        for permission in permission_list:
            assert group_dn in permission_map[permission]['groupPermission']
            if 'inheritPermission' in permission_map:
                allowed_user_list = [m.split("=")[1].split(",")[0] for m in permission_map[permission]['inheritPermission']]
                assert set(user_list) <= set(allowed_user_list)


def check_permission_for_apps():
    # We check that the for each installed apps we have at last the "main" permission
    # and we don't have any permission linked to no apps. The only exception who is not liked to an app
    # is mail, metronome, and sftp

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()
    permission_search = ldap.search('ou=permission,dc=yunohost,dc=org',
                                    '(objectclass=permissionYnh)',
                                    ['cn', 'groupPermission', 'inheritPermission', 'memberUid'])

    installed_apps = {app['id'] for app in app_list(installed=True)['apps']}
    permission_list_set = {permission['cn'][0].split(".")[1] for permission in permission_search}

    extra_service_permission = set(['mail', 'metronome'])
    if 'sftp' in permission_list_set:
        extra_service_permission.add('sftp')
    assert installed_apps == permission_list_set - extra_service_permission

#
# List functions
#

def test_list_permission():
    res = user_permission_list()['permissions']

    assert "wiki" in res
    assert "main" in res['wiki']
    assert "blog" in res
    assert "main" in res['blog']
    assert "mail" in res
    assert "main" in res['mail']
    assert "metronome" in res
    assert "main" in res['metronome']
    assert ["all_users"] == res['wiki']['main']['allowed_groups']
    assert ["alice"] == res['blog']['main']['allowed_groups']
    assert set(["alice", "bob"]) == set(res['wiki']['main']['allowed_users'])
    assert ["alice"] == res['blog']['main']['allowed_users']
    assert [maindomain + "/wiki"] == res['wiki']['main']['URL']

#
# Create - Remove functions
#

def test_add_permission_1():
    permission_add("site", "test")

    res = user_permission_list()['permissions']
    assert "site" in res
    assert "test" in res['site']
    assert "all_users" in res['site']['test']['allowed_groups']
    assert set(["alice", "bob"]) == set(res['site']['test']['allowed_users'])

def test_add_permission_2():
    permission_add("site", "main", default_allow=False)

    res = user_permission_list()['permissions']
    assert "site" in res
    assert "main" in res['site']
    assert [] == res['site']['main']['allowed_groups']
    assert [] == res['site']['main']['allowed_users']

def test_remove_permission():
    permission_remove("wiki", "main", force=True)

    res = user_permission_list()['permissions']
    assert "wiki" not in res

#
# Error on create - remove function
#

def test_add_bad_permission():
    # Create permission with same name
    with pytest.raises(YunohostError):
        permission_add("wiki", "main")

def test_remove_bad_permission():
    # Remove not existant permission
    with pytest.raises(MoulinetteError):
        permission_remove("non_exit", "main", force=True)

    res = user_permission_list()['permissions']
    assert "wiki" in res
    assert "main" in res['wiki']
    assert "blog" in res
    assert "main" in res['blog']
    assert "mail" in res
    assert "main" in res ['mail']
    assert "metronome" in res
    assert "main" in res['metronome']

def test_remove_main_permission():
    with pytest.raises(YunohostError):
        permission_remove("blog", "main")

    res = user_permission_list()['permissions']
    assert "mail" in res
    assert "main" in res['mail']

#
# Update functions
#

# user side functions

def test_allow_first_group():
    # Remove permission to all_users and define per users
    user_permission_add(["wiki"], "main", group="alice")

    res = user_permission_list()['permissions']
    assert ['alice'] == res['wiki']['main']['allowed_users']
    assert ['alice'] == res['wiki']['main']['allowed_groups']

def test_allow_other_group():
    # Allow new user in a permission
    user_permission_add(["blog"], "main", group="bob")

    res = user_permission_list()['permissions']
    assert set(["alice", "bob"]) == set(res['blog']['main']['allowed_users'])
    assert set(["alice", "bob"]) == set(res['blog']['main']['allowed_groups'])

def test_disallow_group_1():
    # Disallow a user in a permission
    user_permission_remove(["blog"], "main", group="alice")

    res = user_permission_list()['permissions']
    assert [] == res['blog']['main']['allowed_users']
    assert [] == res['blog']['main']['allowed_groups']

def test_allow_group_1():
    # Allow a user when he is already allowed
    user_permission_add(["blog"], "main", group="alice")

    res = user_permission_list()['permissions']
    assert ["alice"] == res['blog']['main']['allowed_users']
    assert ["alice"] == res['blog']['main']['allowed_groups']

def test_disallow_group_1():
    # Disallow a user when he is already disallowed
    user_permission_remove(["blog"], "main", group="bob")

    res = user_permission_list()['permissions']
    assert ["alice"] == res['blog']['main']['allowed_users']
    assert ["alice"] == res['blog']['main']['allowed_groups']

def test_reset_permission():
    # Reset permission
    user_permission_clear(["blog"], "main")

    res = user_permission_list()['permissions']
    assert set(["alice", "bob"]) == set(res['blog']['main']['allowed_users'])
    assert ["all_users"] == res['blog']['main']['allowed_groups']

# internal functions

def test_add_url_1():
    # Add URL in permission which hasn't any URL defined
    permission_update("blog", "main", add_url=[maindomain + "/testA"])

    res = user_permission_list()['permissions']
    assert [maindomain + "/testA"] == res['blog']['main']['URL']

def test_add_url_2():
    # Add a second URL in a permission
    permission_update("wiki", "main", add_url=[maindomain + "/testA"])

    res = user_permission_list()['permissions']
    assert set([maindomain + "/testA", maindomain + "/wiki"]) == set(res['wiki']['main']['URL'])

def test_remove_url_1():
    permission_update("wiki", "main", remove_url=[maindomain + "/wiki"])

    res = user_permission_list()['permissions']
    assert 'URL' not in res['wiki']['main']

def test_add_url_3():
    # Add a url already added
    permission_update("wiki", "main", add_url=[maindomain + "/wiki"])

    res = user_permission_list()['permissions']
    assert [maindomain + "/wiki"] == res['wiki']['main']['URL']

def test_remove_url_2():
    # Remove a url not added (with a permission which contain some URL)
    permission_update("wiki", "main", remove_url=[maindomain + "/not_exist"])

    res = user_permission_list()['permissions']
    assert [maindomain + "/wiki"] == res['wiki']['main']['URL']

def test_remove_url_2():
    # Remove a url not added (with a permission which contain no URL)
    permission_update("blog", "main", remove_url=[maindomain + "/not_exist"])

    res = user_permission_list()['permissions']
    assert 'URL' not in res['blog']['main']

#
# Error on update function
#

def test_disallow_bad_group_1():
    # Disallow a group when the group all_users is allowed
    with pytest.raises(YunohostError):
        user_permission_remove("wiki", "main", group="alice")

    res = user_permission_list()['permissions']
    assert ["all_users"] == res['wiki']['main']['allowed_groups']
    assert set(["alice", "bob"]) == set(res['wiki']['main']['allowed_users'])

def test_allow_bad_user():
    # Allow a non existant group
    with pytest.raises(YunohostError):
        user_permission_add(["blog"], "main", group="not_exist")

    res = user_permission_list()['permissions']
    assert ["alice"] == res['blog']['main']['allowed_groups']
    assert ["alice"] == res['blog']['main']['allowed_users']

def test_disallow_bad_group_2():
    # Disallow a non existant group
    with pytest.raises(YunohostError):
        user_permission_remove(["blog"], "main", group="not_exist")

    res = user_permission_list()['permissions']
    assert ["alice"] == res['blog']['main']['allowed_groups']
    assert ["alice"] == res['blog']['main']['allowed_users']

def test_allow_bad_permission_1():
    # Allow a user to a non existant permission
    with pytest.raises(YunohostError):
        user_permission_add(["wiki"], "not_exit", group="alice")

def test_allow_bad_permission_2():
    # Allow a user to a non existant permission
    with pytest.raises(YunohostError):
        user_permission_add(["not_exit"], "main", group="alice")

#
# Application interaction
#

def test_install_app():
    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)

    res = user_permission_list()['permissions']
    assert "permissions_app" in res
    assert "main" in res['permissions_app']
    assert [maindomain + "/urlpermissionapp"] == res['permissions_app']['main']['URL']
    assert [maindomain + "/urlpermissionapp/admin"] == res['permissions_app']['admin']['URL']
    assert [maindomain + "/urlpermissionapp/dev"] == res['permissions_app']['dev']['URL']

    assert ["all_users"] == res['permissions_app']['main']['allowed_groups']
    assert set(["alice", "bob"]) == set(res['permissions_app']['main']['allowed_users'])

    assert ["alice"] == res['permissions_app']['admin']['allowed_groups']
    assert ["alice"] == res['permissions_app']['admin']['allowed_users']

    assert ["all_users"] == res['permissions_app']['dev']['allowed_groups']
    assert set(["alice", "bob"]) == set(res['permissions_app']['dev']['allowed_users'])

def test_remove_app():
    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)
    app_remove("permissions_app")

    res = user_permission_list()['permissions']
    assert "permissions_app" not in res

def test_change_url():
    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)

    res = user_permission_list()['permissions']
    assert [maindomain + "/urlpermissionapp"] == res['permissions_app']['main']['URL']
    assert [maindomain + "/urlpermissionapp/admin"] == res['permissions_app']['admin']['URL']
    assert [maindomain + "/urlpermissionapp/dev"] == res['permissions_app']['dev']['URL']

    app_change_url("permissions_app", maindomain, "/newchangeurl")

    res = user_permission_list()['permissions']
    assert [maindomain + "/newchangeurl"] == res['permissions_app']['main']['URL']
    assert [maindomain + "/newchangeurl/admin"] == res['permissions_app']['admin']['URL']
    assert [maindomain + "/newchangeurl/dev"] == res['permissions_app']['dev']['URL']
