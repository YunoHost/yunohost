import pytest

from yunohost.utils.error import YunohostError
from yunohost.app import app_install, app_remove
from yunohost.domain import _get_maindomain, domain_url_available, _normalize_domain_path, _check_and_normalize_permission_path

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


def test_normalize_permission_path():
    # Relative path
    assert _check_and_normalize_permission_path("/wiki/") == "/wiki"
    assert _check_and_normalize_permission_path("/") == "/"
    assert _check_and_normalize_permission_path("//salut/") == "/salut"

    # Full path
    assert _check_and_normalize_permission_path(maindomain + "/hey/") == maindomain + "/hey"
    assert _check_and_normalize_permission_path(maindomain + "//") == maindomain + "/"
    assert _check_and_normalize_permission_path(maindomain + "/") == maindomain + "/"

    # Relative Regex
    assert _check_and_normalize_permission_path("re:/yolo.*/") == "re:/yolo.*/"
    assert _check_and_normalize_permission_path("re:/y.*o(o+)[a-z]*/bo\1y") == "re:/y.*o(o+)[a-z]*/bo\1y"

    # Full Regex
    assert _check_and_normalize_permission_path("re:" + maindomain + "/yolo.*/") == "re:" + maindomain + "/yolo.*/"
    assert _check_and_normalize_permission_path("re:" + maindomain + "/y.*o(o+)[a-z]*/bo\1y") == "re:" + maindomain + "/y.*o(o+)[a-z]*/bo\1y"


def test_normalize_permission_path_with_bad_regex():
    # Relative Regex
    with pytest.raises(YunohostError):
        _check_and_normalize_permission_path("re:/yolo.*[1-7]^?/")
    with pytest.raises(YunohostError):
        _check_and_normalize_permission_path("re:/yolo.*[1-7](]/")

    # Full Regex
    with pytest.raises(YunohostError):
        _check_and_normalize_permission_path("re:" + maindomain + "/yolo?+/")
    with pytest.raises(YunohostError):
        _check_and_normalize_permission_path("re:" + maindomain + "/yolo[1-9]**/")


def test_normalize_permission_path_with_unknown_domain():
    with pytest.raises(YunohostError):
        _check_and_normalize_permission_path("shouldntexist.tld/hey")
    with pytest.raises(YunohostError):
        _check_and_normalize_permission_path("re:shouldntexist.tld/hey.*")
