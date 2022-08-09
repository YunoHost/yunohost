import pytest

from .conftest import message, raiseYunohostError

from yunohost.user import (
    user_list,
    user_info,
    user_create,
    user_delete,
    user_update,
    user_import,
    user_export,
    FIELDS_FOR_IMPORT,
    FIRST_ALIASES,
    user_group_list,
    user_group_create,
    user_group_delete,
    user_group_update,
)
from yunohost.domain import _get_maindomain
from yunohost.tests.test_permission import check_LDAP_db_integrity

# Get main domain
maindomain = ""


def clean_user_groups():
    for u in user_list()["users"]:
        user_delete(u, purge=True)

    for g in user_group_list()["groups"]:
        if g not in ["all_users", "visitors"]:
            user_group_delete(g)


def setup_function(function):
    clean_user_groups()

    global maindomain
    maindomain = _get_maindomain()

    user_create("alice", "Alice", "White", maindomain, "test123Ynh")
    user_create("bob", "Bob", "Snow", maindomain, "test123Ynh")
    user_create("jack", "Jack", "Black", maindomain, "test123Ynh")

    user_group_create("dev")
    user_group_create("apps")
    user_group_update("dev", add=["alice"])
    user_group_update("apps", add=["bob"])


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
    res = user_list()["users"]

    assert "alice" in res
    assert "bob" in res
    assert "jack" in res


def test_list_groups():
    res = user_group_list()["groups"]

    assert "all_users" in res
    assert "alice" in res
    assert "bob" in res
    assert "jack" in res
    for u in ["alice", "bob", "jack"]:
        assert u in res
        assert u in res[u]["members"]
        assert u in res["all_users"]["members"]


#
# Create - Remove functions
#


def test_create_user(mocker):

    with message(mocker, "user_created"):
        user_create("albert", "Albert", "Good", maindomain, "test123Ynh")

    group_res = user_group_list()["groups"]
    assert "albert" in user_list()["users"]
    assert "albert" in group_res
    assert "albert" in group_res["albert"]["members"]
    assert "albert" in group_res["all_users"]["members"]


def test_del_user(mocker):

    with message(mocker, "user_deleted"):
        user_delete("alice")

    group_res = user_group_list()["groups"]
    assert "alice" not in user_list()
    assert "alice" not in group_res
    assert "alice" not in group_res["all_users"]["members"]


def test_import_user(mocker):
    import csv
    from io import StringIO

    fieldnames = [
        "username",
        "firstname",
        "lastname",
        "password",
        "mailbox-quota",
        "mail",
        "mail-alias",
        "mail-forward",
        "groups",
    ]
    with StringIO() as csv_io:
        writer = csv.DictWriter(csv_io, fieldnames, delimiter=";", quotechar='"')
        writer.writeheader()
        writer.writerow(
            {
                "username": "albert",
                "firstname": "Albert",
                "lastname": "Good",
                "password": "",
                "mailbox-quota": "1G",
                "mail": "albert@" + maindomain,
                "mail-alias": "albert2@" + maindomain,
                "mail-forward": "albert@example.com",
                "groups": "dev",
            }
        )
        writer.writerow(
            {
                "username": "alice",
                "firstname": "Alice",
                "lastname": "White",
                "password": "",
                "mailbox-quota": "1G",
                "mail": "alice@" + maindomain,
                "mail-alias": "alice1@" + maindomain + ",alice2@" + maindomain,
                "mail-forward": "",
                "groups": "apps",
            }
        )
        csv_io.seek(0)
        with message(mocker, "user_import_success"):
            user_import(csv_io, update=True, delete=True)

    group_res = user_group_list()["groups"]
    user_res = user_list(list(FIELDS_FOR_IMPORT.keys()))["users"]
    assert "albert" in user_res
    assert "alice" in user_res
    assert "bob" not in user_res
    assert len(user_res["alice"]["mail-alias"]) == 2
    assert "albert" in group_res["dev"]["members"]
    assert "alice" in group_res["apps"]["members"]
    assert "alice" not in group_res["dev"]["members"]


def test_export_user(mocker):
    result = user_export()
    aliases = ",".join([alias + maindomain for alias in FIRST_ALIASES])
    should_be = (
        "username;firstname;lastname;password;mail;mail-alias;mail-forward;mailbox-quota;groups\r\n"
        f"alice;Alice;White;;alice@{maindomain};{aliases};;0;dev\r\n"
        f"bob;Bob;Snow;;bob@{maindomain};;;0;apps\r\n"
        f"jack;Jack;Black;;jack@{maindomain};;;0;"
    )
    assert result == should_be


def test_create_group(mocker):

    with message(mocker, "group_created", group="adminsys"):
        user_group_create("adminsys")

    group_res = user_group_list()["groups"]
    assert "adminsys" in group_res
    assert "members" in group_res["adminsys"].keys()
    assert group_res["adminsys"]["members"] == []


def test_del_group(mocker):

    with message(mocker, "group_deleted", group="dev"):
        user_group_delete("dev")

    group_res = user_group_list()["groups"]
    assert "dev" not in group_res


#
# Error on create / remove function
#


def test_create_user_with_password_too_simple(mocker):
    with raiseYunohostError(mocker, "password_listed"):
        user_create("other", "Alice", "White", maindomain, "12")


def test_create_user_already_exists(mocker):
    with raiseYunohostError(mocker, "user_already_exists"):
        user_create("alice", "Alice", "White", maindomain, "test123Ynh")


def test_create_user_with_domain_that_doesnt_exists(mocker):
    with raiseYunohostError(mocker, "domain_unknown"):
        user_create("alice", "Alice", "White", "doesnt.exists", "test123Ynh")


def test_update_user_with_mail_address_already_taken(mocker):
    with raiseYunohostError(mocker, "user_update_failed"):
        user_update("bob", add_mailalias="alice@" + maindomain)


def test_update_user_with_mail_address_with_unknown_domain(mocker):
    with raiseYunohostError(mocker, "mail_domain_unknown"):
        user_update("alice", add_mailalias="alice@doesnt.exists")


def test_del_user_that_does_not_exist(mocker):
    with raiseYunohostError(mocker, "user_unknown"):
        user_delete("doesnt_exist")


def test_create_group_all_users(mocker):
    # Check groups already exist with special group "all_users"
    with raiseYunohostError(mocker, "group_already_exist"):
        user_group_create("all_users")


def test_create_group_already_exists(mocker):
    # Check groups already exist (regular groups)
    with raiseYunohostError(mocker, "group_already_exist"):
        user_group_create("dev")


def test_del_group_all_users(mocker):
    with raiseYunohostError(mocker, "group_cannot_be_deleted"):
        user_group_delete("all_users")


def test_del_group_that_does_not_exist(mocker):
    with raiseYunohostError(mocker, "group_unknown"):
        user_group_delete("doesnt_exist")


#
# Update function
#


def test_update_user(mocker):
    with message(mocker, "user_updated"):
        user_update("alice", firstname="NewName", lastname="NewLast")

    info = user_info("alice")
    assert info["firstname"] == "NewName"
    assert info["lastname"] == "NewLast"


def test_update_group_add_user(mocker):
    with message(mocker, "group_updated", group="dev"):
        user_group_update("dev", add=["bob"])

    group_res = user_group_list()["groups"]
    assert set(group_res["dev"]["members"]) == {"alice", "bob"}


def test_update_group_add_user_already_in(mocker):
    with message(mocker, "group_user_already_in_group", user="bob", group="apps"):
        user_group_update("apps", add=["bob"])

    group_res = user_group_list()["groups"]
    assert group_res["apps"]["members"] == ["bob"]


def test_update_group_remove_user(mocker):
    with message(mocker, "group_updated", group="apps"):
        user_group_update("apps", remove=["bob"])

    group_res = user_group_list()["groups"]
    assert group_res["apps"]["members"] == []


def test_update_group_remove_user_not_already_in(mocker):
    with message(mocker, "group_user_not_in_group", user="jack", group="apps"):
        user_group_update("apps", remove=["jack"])

    group_res = user_group_list()["groups"]
    assert group_res["apps"]["members"] == ["bob"]


#
# Error on update functions
#


def test_update_user_that_doesnt_exist(mocker):
    with raiseYunohostError(mocker, "user_unknown"):
        user_update("doesnt_exist", firstname="NewName", lastname="NewLast")


def test_update_group_that_doesnt_exist(mocker):
    with raiseYunohostError(mocker, "group_unknown"):
        user_group_update("doesnt_exist", add=["alice"])


def test_update_group_all_users_manually(mocker):
    with raiseYunohostError(mocker, "group_cannot_edit_all_users"):
        user_group_update("all_users", remove=["alice"])

    assert "alice" in user_group_list()["groups"]["all_users"]["members"]


def test_update_group_primary_manually(mocker):
    with raiseYunohostError(mocker, "group_cannot_edit_primary_group"):
        user_group_update("alice", remove=["alice"])

    assert "alice" in user_group_list()["groups"]["alice"]["members"]


def test_update_group_add_user_that_doesnt_exist(mocker):
    with raiseYunohostError(mocker, "user_unknown"):
        user_group_update("dev", add=["doesnt_exist"])

    assert "doesnt_exist" not in user_group_list()["groups"]["dev"]["members"]
