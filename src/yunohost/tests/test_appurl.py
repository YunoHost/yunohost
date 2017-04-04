import pytest

from moulinette.core import MoulinetteError, init_authenticator

from yunohost.app import app_install, app_remove
from yunohost.domain import _get_maindomain, domain_url_available, _normalize_domain_path

# Instantiate LDAP Authenticator
auth_identifier = ('ldap', 'ldap-anonymous')
auth_parameters = {'uri': 'ldap://localhost:389', 'base_dn': 'dc=yunohost,dc=org'}
auth = init_authenticator(auth_identifier, auth_parameters)


# Get main domain
maindomain = _get_maindomain()


def setup_function(function):

    try:
        app_remove(auth, "register_url_app")
    except:
        pass

def teardown_function(function):

    try:
        app_remove(auth, "register_url_app")
    except:
        pass


def test_normalize_domain_path():

    assert _normalize_domain_path("https://yolo.swag/", "macnuggets") == ("yolo.swag", "/macnuggets")
    assert _normalize_domain_path("http://yolo.swag", "/macnuggets/") == ("yolo.swag", "/macnuggets")
    assert _normalize_domain_path("yolo.swag/", "macnuggets/") == ("yolo.swag", "/macnuggets")


def test_urlavailable():

    # Except the maindomain/macnuggets to be available
    assert domain_url_available(auth, maindomain, "/macnuggets")

    # We don't know the domain yolo.swag
    with pytest.raises(MoulinetteError):
        assert domain_url_available(auth, "yolo.swag", "/macnuggets")


def test_registerurl():

    app_install(auth, "./tests/apps/register_url_app_ynh",
            args="domain=%s&path=%s" % (maindomain, "/urlregisterapp"))

    assert not domain_url_available(auth, maindomain, "/urlregisterapp")

    # Try installing at same location
    with pytest.raises(MoulinetteError):
        app_install(auth, "./tests/apps/register_url_app_ynh",
                args="domain=%s&path=%s" % (maindomain, "/urlregisterapp"))


def test_registerurl_baddomain():

    with pytest.raises(MoulinetteError):
        app_install(auth, "./tests/apps/register_url_app_ynh",
                args="domain=%s&path=%s" % ("yolo.swag", "/urlregisterapp"))
