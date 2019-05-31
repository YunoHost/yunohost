import pytest

from yunohost.utils.error import YunohostError
from yunohost.app import app_install, app_remove
from yunohost.domain import _get_maindomain, domain_url_available, _normalize_domain_path

# Get main domain
maindomain = _get_maindomain()


def setup_function(function):

    try:
        app_remove("register_url_app")
    except:
        pass


def teardown_function(function):

    try:
        app_remove("register_url_app")
    except:
        pass


def test_normalize_domain_path():

    assert _normalize_domain_path("https://yolo.swag/", "macnuggets") == ("yolo.swag", "/macnuggets")
    assert _normalize_domain_path("http://yolo.swag", "/macnuggets/") == ("yolo.swag", "/macnuggets")
    assert _normalize_domain_path("yolo.swag/", "macnuggets/") == ("yolo.swag", "/macnuggets")


def test_urlavailable():

    # Except the maindomain/macnuggets to be available
    assert domain_url_available(maindomain, "/macnuggets")

    # We don't know the domain yolo.swag
    with pytest.raises(YunohostError):
        assert domain_url_available("yolo.swag", "/macnuggets")


def test_registerurl():

    app_install("./tests/apps/register_url_app_ynh",
                args="domain=%s&path=%s" % (maindomain, "/urlregisterapp"), force=True)

    assert not domain_url_available(maindomain, "/urlregisterapp")

    # Try installing at same location
    with pytest.raises(YunohostError):
        app_install("./tests/apps/register_url_app_ynh",
                    args="domain=%s&path=%s" % (maindomain, "/urlregisterapp"), force=True)


def test_registerurl_baddomain():

    with pytest.raises(YunohostError):
        app_install("./tests/apps/register_url_app_ynh",
                    args="domain=%s&path=%s" % ("yolo.swag", "/urlregisterapp"), force=True)
