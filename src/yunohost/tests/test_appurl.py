import pytest
import os

from .conftest import get_test_apps_dir

from yunohost.utils.error import YunohostError
from yunohost.app import app_install, app_remove, _normalize_domain_path
from yunohost.domain import _get_maindomain, domain_url_available
from yunohost.permission import _validate_and_sanitize_permission_url

# Get main domain
maindomain = _get_maindomain()


def setup_function(function):

    try:
        app_remove("register_url_app")
    except Exception:
        pass


def teardown_function(function):

    try:
        app_remove("register_url_app")
    except Exception:
        pass


def test_normalize_domain_path():

    assert _normalize_domain_path("https://yolo.swag/", "macnuggets") == (
        "yolo.swag",
        "/macnuggets",
    )
    assert _normalize_domain_path("http://yolo.swag", "/macnuggets/") == (
        "yolo.swag",
        "/macnuggets",
    )
    assert _normalize_domain_path("yolo.swag/", "macnuggets/") == (
        "yolo.swag",
        "/macnuggets",
    )


def test_urlavailable():

    # Except the maindomain/macnuggets to be available
    assert domain_url_available(maindomain, "/macnuggets")

    # We don't know the domain yolo.swag
    with pytest.raises(YunohostError):
        assert domain_url_available("yolo.swag", "/macnuggets")


def test_registerurl():

    app_install(
        os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
        args="domain=%s&path=%s" % (maindomain, "/urlregisterapp"),
        force=True,
    )

    assert not domain_url_available(maindomain, "/urlregisterapp")

    # Try installing at same location
    with pytest.raises(YunohostError):
        app_install(
            os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
            args="domain=%s&path=%s" % (maindomain, "/urlregisterapp"),
            force=True,
        )


def test_registerurl_baddomain():

    with pytest.raises(YunohostError):
        app_install(
            os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
            args="domain=%s&path=%s" % ("yolo.swag", "/urlregisterapp"),
            force=True,
        )


def test_normalize_permission_path():
    # Relative path
    assert (
        _validate_and_sanitize_permission_url(
            "/wiki/", maindomain + "/path", "test_permission"
        )
        == "/wiki"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "/", maindomain + "/path", "test_permission"
        )
        == "/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "//salut/", maindomain + "/path", "test_permission"
        )
        == "/salut"
    )

    # Full path
    assert (
        _validate_and_sanitize_permission_url(
            maindomain + "/hey/", maindomain + "/path", "test_permission"
        )
        == maindomain + "/hey"
    )
    assert (
        _validate_and_sanitize_permission_url(
            maindomain + "//", maindomain + "/path", "test_permission"
        )
        == maindomain + "/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            maindomain + "/", maindomain + "/path", "test_permission"
        )
        == maindomain + "/"
    )

    # Relative Regex
    assert (
        _validate_and_sanitize_permission_url(
            "re:/yolo.*/", maindomain + "/path", "test_permission"
        )
        == "re:/yolo.*/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "re:/y.*o(o+)[a-z]*/bo\1y", maindomain + "/path", "test_permission"
        )
        == "re:/y.*o(o+)[a-z]*/bo\1y"
    )

    # Full Regex
    assert (
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/yolo.*/", maindomain + "/path", "test_permission"
        )
        == "re:" + maindomain + "/yolo.*/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/y.*o(o+)[a-z]*/bo\1y",
            maindomain + "/path",
            "test_permission",
        )
        == "re:" + maindomain + "/y.*o(o+)[a-z]*/bo\1y"
    )


def test_normalize_permission_path_with_bad_regex():
    # Relative Regex
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:/yolo.*[1-7]^?/", maindomain + "/path", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:/yolo.*[1-7](]/", maindomain + "/path", "test_permission"
        )

    # Full Regex
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/yolo?+/", maindomain + "/path", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/yolo[1-9]**/",
            maindomain + "/path",
            "test_permission",
        )


def test_normalize_permission_path_with_unknown_domain():
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "shouldntexist.tld/hey", maindomain + "/path", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:shouldntexist.tld/hey.*", maindomain + "/path", "test_permission"
        )


def test_normalize_permission_path_conflicting_path():
    app_install(
        os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
        args="domain=%s&path=%s" % (maindomain, "/url/registerapp"),
        force=True,
    )

    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "/registerapp", maindomain + "/url", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            maindomain + "/url/registerapp", maindomain + "/path", "test_permission"
        )
