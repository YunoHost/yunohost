import glob
import os
import shutil
import pytest

from .conftest import get_test_apps_dir

from yunohost.domain import _get_maindomain
from yunohost.app import (
    app_install,
    app_remove,
    _is_installed,
    app_config_get,
    app_config_set,
    app_ssowatconf,
)

from yunohost.utils.errors import YunohostValidationError


def setup_function(function):

    clean()


def teardown_function(function):

    clean()


def clean():

    # Make sure we have a ssowat
    os.system("mkdir -p /etc/ssowat/")
    app_ssowatconf()

    test_apps = ["config_app", "legacy_app"]

    for test_app in test_apps:

        if _is_installed(test_app):
            app_remove(test_app)

        for filepath in glob.glob("/etc/nginx/conf.d/*.d/*%s*" % test_app):
            os.remove(filepath)
        for folderpath in glob.glob("/etc/yunohost/apps/*%s*" % test_app):
            shutil.rmtree(folderpath, ignore_errors=True)
        for folderpath in glob.glob("/var/www/*%s*" % test_app):
            shutil.rmtree(folderpath, ignore_errors=True)

        os.system("bash -c \"mysql -B 2>/dev/null <<< 'DROP DATABASE %s' \"" % test_app)
        os.system(
            "bash -c \"mysql -B 2>/dev/null <<< 'DROP USER %s@localhost'\"" % test_app
        )

    # Reset failed quota for service to avoid running into start-limit rate ?
    os.system("systemctl reset-failed nginx")
    os.system("systemctl start nginx")


@pytest.fixture(scope="module")
def legacy_app(request):

    main_domain = _get_maindomain()

    app_install(
        os.path.join(get_test_apps_dir(), "legacy_app_ynh"),
        args="domain=%s&path=%s&is_public=%s" % (main_domain, "/", 1),
        force=True,
    )

    def remove_app():
        app_remove("legacy_app")

    request.addfinalizer(remove_app)

    return "legacy_app"



@pytest.fixture(scope="module")
def config_app(request):

    app_install(
        os.path.join(get_test_apps_dir(), "config_app_ynh"),
        args="",
        force=True,
    )

    def remove_app():
        app_remove("config_app")

    request.addfinalizer(remove_app)

    return "config_app"


def test_app_config_get(config_app):

    assert isinstance(app_config_get(config_app), dict)
    assert isinstance(app_config_get(config_app, full=True), dict)
    assert isinstance(app_config_get(config_app, export=True), dict)
    assert isinstance(app_config_get(config_app, "main"), dict)
    assert isinstance(app_config_get(config_app, "main.components"), dict)
    # Is it expected that we return None if no value defined yet ?
    # c.f. the whole discussion about "should we have defaults" etc.
    assert app_config_get(config_app, "main.components.boolean") is None


def test_app_config_nopanel(legacy_app):

    with pytest.raises(YunohostValidationError):
        app_config_get(legacy_app)


def test_app_config_get_nonexistentstuff(config_app):

    with pytest.raises(YunohostValidationError):
        app_config_get("nonexistent")

    with pytest.raises(YunohostValidationError):
        app_config_get(config_app, "nonexistent")

    with pytest.raises(YunohostValidationError):
        app_config_get(config_app, "main.nonexistent")

    with pytest.raises(YunohostValidationError):
        app_config_get(config_app, "main.components.nonexistent")


def test_app_config_set_boolean(config_app):

    assert app_config_get(config_app, "main.components.boolean") is None

    app_config_set(config_app, "main.components.boolean", "no")

    assert app_config_get(config_app, "main.components.boolean") == "0"

    app_config_set(config_app, "main.components.boolean", "yes")

    assert app_config_get(config_app, "main.components.boolean") == "1"

    with pytest.raises(YunohostValidationError):
        app_config_set(config_app, "main.components.boolean", "pwet")
