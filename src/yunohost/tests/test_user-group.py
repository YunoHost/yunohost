import pytest

from moulinette.core import init_authenticator, MoulinetteError
from yunohost.user import user_list, user_info, user_group_list, user_create, user_delete, user_update, user_group_add, user_group_delete, user_group_update, user_group_info
from yunohost.domain import _get_maindomain
from yunohost.utils.error import YunohostError

# Get main domain
maindomain = _get_maindomain()

# Instantiate LDAP Authenticator
AUTH_IDENTIFIER = ('ldap', 'as-root')
AUTH_PARAMETERS = {'uri': 'ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi',
                   'base_dn': 'dc=yunohost,dc=org',
                   'user_rdn': 'gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth'}

auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

def clean_user_groups():
    for u in user_list(auth)['users']:
        user_delete(auth, u)

    for g in user_group_list(auth)['groups']:
        if g != "all_users":
            user_group_delete(auth, g)

def setup_function(function):
    clean_user_groups()

    user_create(auth, "alice", "Alice", "White", "alice@" + maindomain, "test123Ynh")
    user_create(auth, "bob", "Bob", "Snow", "bob@" + maindomain, "test123Ynh")
    user_create(auth, "jack", "Jack", "Black", "jack@" + maindomain, "test123Ynh")

    user_group_add(auth, "dev")
    user_group_add(auth, "apps")
    user_group_update(auth, "dev", add_user=["alice"])
    user_group_update(auth, "apps", add_user=["bob"])

def teardown_function(function):
    clean_user_groups()

#
# List functions
#

def test_list_users():
    res = user_list(auth)['users']

    assert "alice" in res
    assert "bob" in res
    assert "jack" in res

def test_list_groups():
    res = user_group_list(auth)['groups']

    assert "all_users" in res
    assert "alice" in res
    assert "bob" in res
    assert "jack" in res
    for u in ["alice", "bob", "jack"]:
        assert u in res
        assert u in res[u]['members']
        assert u in res["all_users"]['members']

#
# Create - Remove functions
#

def test_create_user():
    user_create(auth, "albert", "Albert", "Good", "alber@" + maindomain, "test123Ynh")

    group_res = user_group_list(auth)['groups']
    assert "albert" in user_list(auth)['users']
    assert "albert" in group_res
    assert "albert" in group_res['albert']['members']
    assert "albert" in group_res['all_users']['members']

def test_del_user():
    user_delete(auth, "alice")

    group_res = user_group_list(auth)['groups']
    assert "alice" not in user_list(auth)
    assert "alice" not in group_res
    assert "alice" not in group_res['all_users']['members']

def test_add_group():
    user_group_add(auth, "adminsys")

    group_res = user_group_list(auth)['groups']
    assert "adminsys" in group_res
    assert "members" not in group_res['adminsys']

def test_del_group():
    user_group_delete(auth, "dev")

    group_res = user_group_list(auth)['groups']
    assert "dev" not in group_res

#
# Error on create / remove function
#

def test_add_bad_user_1():
    # Check email already exist
    with pytest.raises(MoulinetteError):
        user_create(auth, "alice2", "Alice", "White", "alice@" + maindomain, "test123Ynh")

def test_add_bad_user_2():
    # Check to short password
    with pytest.raises(MoulinetteError):
        user_create(auth, "other", "Alice", "White", "other@" + maindomain, "12")

def test_add_bad_user_3():
    # Check user already exist
    with pytest.raises(MoulinetteError):
        user_create(auth, "alice", "Alice", "White", "other@" + maindomain, "test123Ynh")

def test_del_bad_user_1():
    # Check user not found
    with pytest.raises(MoulinetteError):
        user_delete(auth, "not_exit")

def test_add_bad_group_1():
    # Check groups already exist with special group "all_users"
    with pytest.raises(YunohostError):
        user_group_add(auth, "all_users")

def test_add_bad_group_2():
    # Check groups already exist (for standard groups)
    with pytest.raises(MoulinetteError):
        user_group_add(auth, "dev")

def test_del_bad_group_1():
    # Check not allowed to remove this groups
    with pytest.raises(YunohostError):
        user_group_delete(auth, "all_users")

def test_del_bad_group_2():
    # Check groups not found
    with pytest.raises(MoulinetteError):
        user_group_delete(auth, "not_exit")

#
# Update function
#

def test_update_user_1():
    user_update(auth, "alice", firstname="NewName", lastname="NewLast")

    info = user_info(auth, "alice")
    assert "NewName" == info['firstname']
    assert "NewLast" == info['lastname']

def test_update_group_1():
    user_group_update(auth, "dev", add_user=["bob"])

    group_res = user_group_list(auth)['groups']
    assert set(["alice", "bob"]) == set(group_res['dev']['members'])

def test_update_group_2():
    # Try to add a user in a group when the user is already in
    user_group_update(auth, "apps", add_user=["bob"])

    group_res = user_group_list(auth)['groups']
    assert ["bob"] == group_res['apps']['members']

def test_update_group_3():
    # Try to remove a user in a group
    user_group_update(auth, "apps", remove_user=["bob"])

    group_res = user_group_list(auth)['groups']
    assert "members" not in group_res['apps']

def test_update_group_4():
    # Try to remove a user in a group when it is not already in
    user_group_update(auth, "apps", remove_user=["jack"])

    group_res = user_group_list(auth)['groups']
    assert ["bob"] == group_res['apps']['members']

#
# Error on update functions
#

def test_bad_update_user_1():
    # Check user not found
    with pytest.raises(YunohostError):
        user_update(auth, "not_exit", firstname="NewName", lastname="NewLast")

def bad_update_group_1():
    # Check groups not found
    with pytest.raises(YunohostError):
        user_group_update(auth, "not_exit", add_user=["alice"])

def test_bad_update_group_2():
    # Check remove user in groups "all_users" not allowed
    with pytest.raises(YunohostError):
        user_group_update(auth, "all_users", remove_user=["alice"])

def test_bad_update_group_3():
    # Check remove user in it own group not allowed
    with pytest.raises(YunohostError):
        user_group_update(auth, "alice", remove_user=["alice"])

def test_bad_update_group_1():
    # Check add bad user in group
    with pytest.raises(YunohostError):
        user_group_update(auth, "dev", add_user=["not_exist"])

    assert "not_exist" not in user_group_list(auth)["groups"]["dev"]
