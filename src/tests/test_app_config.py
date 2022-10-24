import glob
import os
import shutil
import pytest
from mock import patch

from .conftest import get_test_apps_dir

from moulinette import Moulinette
from moulinette.utils.filesystem import read_file

from yunohost.domain import _get_maindomain
from yunohost.app import (
    app_setting,
    app_install,
    app_remove,
    _is_installed,
    app_config_get,
    app_config_set,
    app_ssowatconf,
)
from yunohost.user import user_create, user_delete

from yunohost.utils.error import YunohostError, YunohostValidationError


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


@pytest.fixture()
def legacy_app(request):

    main_domain = _get_maindomain()

    app_install(
        os.path.join(get_test_apps_dir(), "legacy_app_ynh"),
        args="domain={}&path={}&is_public={}".format(main_domain, "/", 1),
        force=True,
    )

    def remove_app():
        app_remove("legacy_app")

    request.addfinalizer(remove_app)

    return "legacy_app"


@pytest.fixture()
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

    user_create("alice", _get_maindomain(), "test123Ynh", fullname="Alice White")

    assert isinstance(app_config_get(config_app), dict)
    assert isinstance(app_config_get(config_app, full=True), dict)
    assert isinstance(app_config_get(config_app, export=True), dict)
    assert isinstance(app_config_get(config_app, "main"), dict)
    assert isinstance(app_config_get(config_app, "main.components"), dict)
    assert app_config_get(config_app, "main.components.boolean") == "0"

    user_delete("alice")


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

    app_setting(config_app, "boolean", delete=True)
    with pytest.raises(YunohostError):
        app_config_get(config_app, "main.components.boolean")


def test_app_config_regular_setting(config_app):

    assert app_config_get(config_app, "main.components.boolean") == "0"

    app_config_set(config_app, "main.components.boolean", "no")

    assert app_config_get(config_app, "main.components.boolean") == "0"
    assert app_setting(config_app, "boolean") == "0"

    app_config_set(config_app, "main.components.boolean", "yes")

    assert app_config_get(config_app, "main.components.boolean") == "1"
    assert app_setting(config_app, "boolean") == "1"

    with pytest.raises(YunohostValidationError), patch.object(
        os, "isatty", return_value=False
    ), patch.object(Moulinette, "prompt", return_value="pwet"):
        app_config_set(config_app, "main.components.boolean", "pwet")


def test_app_config_bind_on_file(config_app):

    # c.f. conf/test.php in the config app
    assert '$arg5= "Arg5 value";' in read_file("/var/www/config_app/test.php")
    assert app_config_get(config_app, "bind.variable.arg5") == "Arg5 value"
    assert app_setting(config_app, "arg5") is None

    app_config_set(config_app, "bind.variable.arg5", "Foo Bar")

    assert '$arg5= "Foo Bar";' in read_file("/var/www/config_app/test.php")
    assert app_config_get(config_app, "bind.variable.arg5") == "Foo Bar"
    assert app_setting(config_app, "arg5") == "Foo Bar"


def test_app_config_custom_get(config_app):

    assert app_setting(config_app, "arg9") is None
    assert (
        "Files in /var/www"
        in app_config_get(config_app, "bind.function.arg9")["ask"]["en"]
    )
    assert app_setting(config_app, "arg9") is None


def test_app_config_custom_validator(config_app):

    # c.f. the config script
    # arg8 is a password that must be at least 8 chars
    assert not os.path.exists("/var/www/config_app/password")
    assert app_setting(config_app, "arg8") is None

    with pytest.raises(YunohostValidationError):
        app_config_set(config_app, "bind.function.arg8", "pZo6i7u91h")

    assert not os.path.exists("/var/www/config_app/password")
    assert app_setting(config_app, "arg8") is None


def test_app_config_custom_set(config_app):

    assert not os.path.exists("/var/www/config_app/password")
    assert app_setting(config_app, "arg8") is None

    app_config_set(config_app, "bind.function.arg8", "OneSuperStrongPassword")

    assert os.path.exists("/var/www/config_app/password")
    content = read_file("/var/www/config_app/password")
    assert "OneSuperStrongPassword" not in content
    assert content.startswith("$6$saltsalt$")
    assert app_setting(config_app, "arg8") is None
