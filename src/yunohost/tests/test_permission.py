import requests
import pytest

from yunohost.app import app_install, app_remove, app_change_url, app_list, app_map

from yunohost.user import user_list, user_info, user_create, user_delete, user_update, \
                          user_group_list, user_group_create, user_group_delete, user_group_update, user_group_info
from yunohost.permission import user_permission_update, user_permission_list, user_permission_reset, \
                                permission_create, permission_urls, permission_delete
from yunohost.domain import _get_maindomain
from yunohost.utils.error import YunohostError

# Get main domain
maindomain = _get_maindomain()
dummy_password = "test123Ynh"

def clean_user_groups_permission():
    for u in user_list()['users']:
        user_delete(u)

    for g in user_group_list()['groups']:
        if g not in ["all_users", "visitors"]:
            user_group_delete(g)

    for p in user_permission_list()['permissions']:
        if any(p.startswith(name) for name in ["wiki", "blog", "site", "permissions_app"]):
            permission_delete(p, force=True, sync_perm=False)

def setup_function(function):
    clean_user_groups_permission()

    user_create("alice", "Alice", "White", "alice@" + maindomain, dummy_password)
    user_create("bob", "Bob", "Snow", "bob@" + maindomain, dummy_password)
    permission_create("wiki.main", urls=["/"], sync_perm=False)
    permission_create("blog.main", sync_perm=False)
    user_permission_update("blog.main", remove="all_users", add="alice")

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

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract
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
        group_list = [_ldap_path_extract(m, "cn") for m in user['memberOf']]
        permission_list = [_ldap_path_extract(m, "cn") for m in user.get('permission', [])]

        # This user's DN sould be found in all groups it is a member of
        for group in group_list:
            assert user_dn in group_map[group]['member']

        # This user's DN should be found in all perms it has access to
        for permission in permission_list:
            assert user_dn in permission_map[permission]['inheritPermission']

    for permission in permission_search:
        permission_dn = 'cn=' + permission['cn'][0] + ',ou=permission,dc=yunohost,dc=org'

        # inheritPermission uid's should match memberUids
        user_list = [_ldap_path_extract(m, "uid") for m in permission.get('inheritPermission', [])]
        assert set(user_list) == set(permission.get('memberUid', []))

        # This perm's DN should be found on all related users it is related to
        for user in user_list:
            assert permission_dn in user_map[user]['permission']

        # Same for groups : we should find the permission's DN for all related groups
        group_list = [_ldap_path_extract(m, "cn") for m in permission.get('groupPermission', [])]
        for group in group_list:
            assert permission_dn in group_map[group]['permission']

            # The list of user in the group should be a subset of all users related to the current permission
            users_in_group = [_ldap_path_extract(m, "uid") for m in group_map[group].get("member", [])]
            assert set(users_in_group) <= set(user_list)

    for group in group_search:
        group_dn = 'cn=' + group['cn'][0] + ',ou=groups,dc=yunohost,dc=org'

        user_list = [_ldap_path_extract(m, "uid") for m in group.get("member", [])]
        # For primary groups, we should find that :
        #    - len(user_list) is 1 (a primary group has only 1 member)
        #    - the group name should be an existing yunohost user
        #    - memberUid is empty (meaning no other member than the corresponding user)
        if group['cn'][0] in user_list:
            assert len(user_list) == 1
            assert group["cn"][0] in user_map
            assert group.get('memberUid', []) == []
        # Otherwise, user_list and memberUid should have the same content
        else:
            assert set(user_list) == set(group.get('memberUid', []))

        # For all users members, this group should be in the "memberOf" on the other side
        for user in user_list:
            assert group_dn in user_map[user]['memberOf']

        # For all the permissions of this group, the group should be among the "groupPermission" on the other side
        permission_list = [_ldap_path_extract(m, "cn") for m in group.get('permission', [])]
        for permission in permission_list:
            assert group_dn in permission_map[permission]['groupPermission']

            # And the list of user of this group (user_list) should be a subset of all allowed users for this perm...
            allowed_user_list = [_ldap_path_extract(m, "uid") for m in permission_map[permission].get('inheritPermission', [])]
            assert set(user_list) <= set(allowed_user_list)


def check_permission_for_apps():
    # We check that the for each installed apps we have at last the "main" permission
    # and we don't have any permission linked to no apps. The only exception who is not liked to an app
    # is mail, xmpp, and sftp

    app_perms = user_permission_list(ignore_system_perms=True)["permissions"].keys()

    # Keep only the prefix so that
    # ["foo.main", "foo.pwet", "bar.main"]
    # becomes
    # {"bar", "foo"}
    # and compare this to the list of installed apps ...

    app_perms_prefix = set(p.split(".")[0] for p in app_perms)

    installed_apps = {app['id'] for app in app_list(installed=True)['apps']}

    assert installed_apps == app_perms_prefix


def can_access_webpage(webpath, logged_as=None):

    webpath = webpath.rstrip("/")
    sso_url = "https://"+maindomain+"/yunohost/sso/"

    # Anonymous access
    if not logged_as:
        r = requests.get(webpath, verify=False)
    # Login as a user using dummy password
    else:
        with requests.Session() as session:
            session.post(sso_url,
                         data={"user": logged_as,
                               "password": dummy_password},
                         headers={"Referer": sso_url,
                                  "Content-Type": "application/x-www-form-urlencoded"},
                         verify=False)
            # We should have some cookies related to authentication now
            assert session.cookies
            r = session.get(webpath, verify=False)

    # If we can't access it, we got redirected to the sso
    return not r.url.startswith(sso_url)

#
# List functions
#

def test_permission_list():
    res = user_permission_list(full=True)['permissions']

    assert "wiki.main" in res
    assert "blog.main" in res
    assert "mail.main" in res
    assert "xmpp.main" in res
    assert res['wiki.main']['allowed'] == ["all_users"]
    assert res['blog.main']['allowed'] == ["alice"]
    assert set(res['wiki.main']['corresponding_users']) == set(["alice", "bob"])
    assert res['blog.main']['corresponding_users'] == ["alice"]
    assert res['wiki.main']['urls'] == ["/"]

#
# Create - Remove functions
#

def test_permission_create_main():
    permission_create("site.main")

    res = user_permission_list(full=True)['permissions']
    assert "site.main" in res
    assert res['site.main']['allowed'] == ["all_users"]
    assert set(res['site.main']['corresponding_users']) == set(["alice", "bob"])


def test_permission_create_extra():
    permission_create("site.test")

    res = user_permission_list(full=True)['permissions']
    assert "site.test" in res
    # all_users is only enabled by default on .main perms
    assert "all_users" not in res['site.test']['allowed']
    assert res['site.test']['corresponding_users'] == []

def test_permission_delete():
    permission_delete("wiki.main", force=True)

    res = user_permission_list()['permissions']
    assert "wiki.main" not in res

#
# Error on create - remove function
#

def test_permission_create_already_existing():
    with pytest.raises(YunohostError):
        permission_create("wiki.main")

def test_permission_delete_doesnt_existing():
    with pytest.raises(YunohostError):
        permission_delete("doesnt.exist", force=True)

    res = user_permission_list()['permissions']
    assert "wiki.main" in res
    assert "blog.main" in res
    assert "mail.main" in res
    assert "xmpp.main" in res

def test_permission_delete_main_without_force():
    with pytest.raises(YunohostError):
        permission_delete("blog.main")

    res = user_permission_list()['permissions']
    assert "blog.main" in res

#
# Update functions
#

# user side functions

def test_permission_add_group():
    user_permission_update("wiki.main", add="alice")

    res = user_permission_list(full=True)['permissions']
    assert set(res['wiki.main']['allowed']) == set(["all_users", "alice"])
    assert set(res['wiki.main']['corresponding_users']) == set(["alice", "bob"])

def test_permission_remove_group():
    user_permission_update("blog.main", remove="alice")

    res = user_permission_list(full=True)['permissions']
    assert res['blog.main']['allowed'] == []
    assert res['blog.main']['corresponding_users'] == []

def test_permission_add_and_remove_group():
    user_permission_update("wiki.main", add="alice", remove="all_users")

    res = user_permission_list(full=True)['permissions']
    assert res['wiki.main']['allowed'] == ["alice"]
    assert res['wiki.main']['corresponding_users'] == ["alice"]

def test_permission_add_group_already_allowed():
    user_permission_update("blog.main", add="alice")

    res = user_permission_list(full=True)['permissions']
    assert res['blog.main']['allowed'] == ["alice"]
    assert res['blog.main']['corresponding_users'] == ["alice"]

def test_permission_remove_group_already_not_allowed():
    user_permission_update("blog.main", remove="bob")

    res = user_permission_list(full=True)['permissions']
    assert res['blog.main']['allowed'] == ["alice"]
    assert res['blog.main']['corresponding_users'] == ["alice"]

def test_permission_reset():
    # Reset permission
    user_permission_reset("blog.main")

    res = user_permission_list(full=True)['permissions']
    assert res['blog.main']['allowed'] == ["all_users"]
    assert set(res['blog.main']['corresponding_users']) == set(["alice", "bob"])

#
# Error on update function
#

def test_permission_add_group_that_doesnt_exist():
    with pytest.raises(YunohostError):
        user_permission_update("blog.main", add="doesnt_exist")

    res = user_permission_list(full=True)['permissions']
    assert res['blog.main']['allowed'] == ["alice"]
    assert res['blog.main']['corresponding_users'] == ["alice"]

def test_permission_update_permission_that_doesnt_exist():
    with pytest.raises(YunohostError):
        user_permission_update("doesnt.exist", add="alice")


# Permission url management

def test_permission_add_url():
    permission_urls("blog.main", add=["/testA"])

    res = user_permission_list(full=True)['permissions']
    assert res["blog.main"]["urls"] == ["/testA"]

def test_permission_add_another_url():
    permission_urls("wiki.main", add=["/testA"])

    res = user_permission_list(full=True)['permissions']
    assert set(res["wiki.main"]["urls"]) == set(["/", "/testA"])

def test_permission_remove_url():
    permission_urls("wiki.main", remove=["/"])

    res = user_permission_list(full=True)['permissions']
    assert res["wiki.main"]["urls"] == []

def test_permission_add_url_already_added():
    res = user_permission_list(full=True)['permissions']
    assert res["wiki.main"]["urls"] == ["/"]

    permission_urls("wiki.main", add=["/"])

    res = user_permission_list(full=True)['permissions']
    assert res["wiki.main"]["urls"] == ["/"]

def test_permission_remove_url_not_added():
    permission_urls("wiki.main", remove=["/doesnt_exist"])

    res = user_permission_list(full=True)['permissions']
    assert res['wiki.main']['urls'] == ["/"]

#
# Application interaction
#

def test_permission_app_install():
    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&is_public=0&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)

    res = user_permission_list(full=True)['permissions']
    assert "permissions_app.main" in res
    assert "permissions_app.admin" in res
    assert "permissions_app.dev" in res
    assert res['permissions_app.main']['urls'] == ["/"]
    assert res['permissions_app.admin']['urls'] == ["/admin"]
    assert res['permissions_app.dev']['urls'] == ["/dev"]

    assert res['permissions_app.main']['allowed'] == ["all_users"]
    assert set(res['permissions_app.main']['corresponding_users']) == set(["alice", "bob"])

    assert res['permissions_app.admin']['allowed'] == ["alice"]
    assert res['permissions_app.admin']['corresponding_users'] == ["alice"]

    assert res['permissions_app.dev']['allowed'] == []
    assert set(res['permissions_app.dev']['corresponding_users']) == set()

    # Check that we get the right stuff in app_map, which is used to generate the ssowatconf
    assert maindomain + "/urlpermissionapp" in app_map(user="alice").keys()
    user_permission_update("permissions_app.main", remove="all_users", add="bob")
    assert maindomain + "/urlpermissionapp" not in app_map(user="alice").keys()
    assert maindomain + "/urlpermissionapp" in app_map(user="bob").keys()


def test_permission_app_remove():
    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&is_public=0&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)
    app_remove("permissions_app")

    # Check all permissions for this app got deleted
    res = user_permission_list(full=True)['permissions']
    assert not any(p.startswith("permissions_app.") for p in res.keys())

def test_permission_app_change_url():
    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)

    # FIXME : should rework this test to look for differences in the generated app map / app tiles ...
    res = user_permission_list(full=True)['permissions']
    assert res['permissions_app.main']['urls'] == ["/"]
    assert res['permissions_app.admin']['urls'] == ["/admin"]
    assert res['permissions_app.dev']['urls'] == ["/dev"]

    app_change_url("permissions_app", maindomain, "/newchangeurl")

    res = user_permission_list(full=True)['permissions']
    assert res['permissions_app.main']['urls'] == ["/"]
    assert res['permissions_app.admin']['urls'] == ["/admin"]
    assert res['permissions_app.dev']['urls'] == ["/dev"]


def test_permission_app_propagation_on_ssowat():

    app_install("./tests/apps/permissions_app_ynh",
                args="domain=%s&path=%s&is_public=1&admin=%s" % (maindomain, "/urlpermissionapp", "alice"), force=True)

    res = user_permission_list(full=True)['permissions']
    assert res['permissions_app.main']['allowed'] == ["visitors"]

    app_webroot = "https://%s/urlpermissionapp" % maindomain
    assert can_access_webpage(app_webroot, logged_as=None)
    assert can_access_webpage(app_webroot, logged_as="alice")

    user_permission_update("permissions_app.main", remove="visitors", add="bob")
    res = user_permission_list(full=True)['permissions']

    assert not can_access_webpage(app_webroot, logged_as=None)
    assert not can_access_webpage(app_webroot, logged_as="alice")
    assert can_access_webpage(app_webroot, logged_as="bob")

    # Test admin access, as configured during install, only alice should be able to access it

    assert not can_access_webpage(app_webroot+"/admin", logged_as=None)
    assert can_access_webpage(app_webroot+"/admin", logged_as="alice")
    assert not can_access_webpage(app_webroot+"/admin", logged_as="bob")

def test_permission_legacy_app_propagation_on_ssowat():

    # TODO / FIXME : To be actually implemented later ....
    raise NotImplementedError

    app_install("./tests/apps/legacy_app_ynh",
                args="domain=%s&path=%s" % (maindomain, "/legacy"), force=True)

    # App is configured as public by default using the legacy unprotected_uri mechanics
    # It should automatically be migrated during the install
    assert res['permissions_app.main']['allowed'] == ["visitors"]

    assert can_access_webpage(maindomain + "/legacy", logged_as=None)
    assert can_access_webpage(maindomain + "/legacy", logged_as="alice")

    # Try to update the permission and check that permissions are still consistent
    user_permission_update("legacy_app.main", remove="visitors", add="bob")
    res = user_permission_list(full=True)['permissions']

    assert not can_access_webpage(maindomain + "/legacy", logged_as=None)
    assert not can_access_webpage(maindomain + "/legacy", logged_as="alice")
    assert can_access_webpage(maindomain + "/legacy", logged_as="bob")
