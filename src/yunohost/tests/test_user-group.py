import pytest

from moulinette.core import MoulinetteError
from yunohost.user import user_list, user_info, user_group_list, user_create, user_delete, user_update, user_group_add, user_group_delete, user_group_update, user_group_info
from yunohost.domain import _get_maindomain
from yunohost.utils.error import YunohostError
from yunohost.tests.test_permission import check_LDAP_db_integrity

# Get main domain
maindomain = _get_maindomain()

def clean_user_groups():
    for u in user_list()['users']:
        user_delete(u)

    for g in user_group_list()['groups']:
        if g != "all_users":
            user_group_delete(g)

def setup_function(function):
    clean_user_groups()

    user_create("alice", "Alice", "White", "alice@" + maindomain, "test123Ynh")
    user_create("bob", "Bob", "Snow", "bob@" + maindomain, "test123Ynh")
    user_create("jack", "Jack", "Black", "jack@" + maindomain, "test123Ynh")

    user_group_add("dev")
    user_group_add("apps")
    user_group_update("dev", add_user=["alice"])
    user_group_update("apps", add_user=["bob"])

def teardown_function(function):
    clean_user_groups()

@pytest.fixture(autouse=True)
def check_LDAP_db_integrity_call():
    check_LDAP_db_integrity()
    yield
    check_LDAP_db_integrity()

#
# List functions
#

def test_list_users():
    res = user_list()['users']

    assert "alice" in res
    assert "bob" in res
    assert "jack" in res

def test_list_groups():
    res = user_group_list()['groups']

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
    user_create("albert", "Albert", "Good", "alber@" + maindomain, "test123Ynh")

    group_res = user_group_list()['groups']
    assert "albert" in user_list()['users']
    assert "albert" in group_res
    assert "albert" in group_res['albert']['members']
    assert "albert" in group_res['all_users']['members']

def test_del_user():
    user_delete("alice")

    group_res = user_group_list()['groups']
    assert "alice" not in user_list()
    assert "alice" not in group_res
    assert "alice" not in group_res['all_users']['members']

def test_add_group():
    user_group_add("adminsys")

    group_res = user_group_list()['groups']
    assert "adminsys" in group_res
    assert "members" not in group_res['adminsys']

def test_del_group():
    user_group_delete("dev")

    group_res = user_group_list()['groups']
    assert "dev" not in group_res

#
# Error on create / remove function
#

def test_add_bad_user_1():
    # Check email already exist
    with pytest.raises(MoulinetteError):
        user_create("alice2", "Alice", "White", "alice@" + maindomain, "test123Ynh")

def test_add_bad_user_2():
    # Check to short password
    with pytest.raises(MoulinetteError):
        user_create("other", "Alice", "White", "other@" + maindomain, "12")

def test_add_bad_user_3():
    # Check user already exist
    with pytest.raises(MoulinetteError):
        user_create("alice", "Alice", "White", "other@" + maindomain, "test123Ynh")

def test_del_bad_user_1():
    # Check user not found
    with pytest.raises(MoulinetteError):
        user_delete("not_exit")

def test_add_bad_group_1():
    # Check groups already exist with special group "all_users"
    with pytest.raises(YunohostError):
        user_group_add("all_users")

def test_add_bad_group_2():
    # Check groups already exist (for standard groups)
    with pytest.raises(MoulinetteError):
        user_group_add("dev")

def test_del_bad_group_1():
    # Check not allowed to remove this groups
    with pytest.raises(YunohostError):
        user_group_delete("all_users")

def test_del_bad_group_2():
    # Check groups not found
    with pytest.raises(MoulinetteError):
        user_group_delete("not_exit")

#
# Update function
#

def test_update_user_1():
    user_update("alice", firstname="NewName", lastname="NewLast")

    info = user_info("alice")
    assert "NewName" == info['firstname']
    assert "NewLast" == info['lastname']

def test_update_group_1():
    user_group_update("dev", add_user=["bob"])

    group_res = user_group_list()['groups']
    assert set(["alice", "bob"]) == set(group_res['dev']['members'])

def test_update_group_2():
    # Try to add a user in a group when the user is already in
    user_group_update("apps", add_user=["bob"])

    group_res = user_group_list()['groups']
    assert ["bob"] == group_res['apps']['members']

def test_update_group_3():
    # Try to remove a user in a group
    user_group_update("apps", remove_user=["bob"])

    group_res = user_group_list()['groups']
    assert "members" not in group_res['apps']

def test_update_group_4():
    # Try to remove a user in a group when it is not already in
    user_group_update("apps", remove_user=["jack"])

    group_res = user_group_list()['groups']
    assert ["bob"] == group_res['apps']['members']

#
# Error on update functions
#

def test_bad_update_user_1():
    # Check user not found
    with pytest.raises(YunohostError):
        user_update("not_exit", firstname="NewName", lastname="NewLast")


def bad_update_group_1():
    # Check groups not found
    with pytest.raises(YunohostError):
        user_group_update("not_exit", add_user=["alice"])

def test_bad_update_group_2():
    # Check remove user in groups "all_users" not allowed
    with pytest.raises(YunohostError):
        user_group_update("all_users", remove_user=["alice"])

def test_bad_update_group_3():
    # Check remove user in it own group not allowed
    with pytest.raises(YunohostError):
        user_group_update("alice", remove_user=["alice"])

def test_bad_update_group_1():
    # Check add bad user in group
    with pytest.raises(YunohostError):
        user_group_update("dev", add_user=["not_exist"])

    assert "not_exist" not in user_group_list()["groups"]["dev"]
