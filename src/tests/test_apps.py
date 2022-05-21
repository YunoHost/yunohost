import glob
import os
import pytest
import shutil
import requests

from .conftest import message, raiseYunohostError, get_test_apps_dir

from moulinette.utils.filesystem import mkdir

from yunohost.app import (
    app_install,
    app_remove,
    app_ssowatconf,
    _is_installed,
    app_upgrade,
    app_map,
    app_manifest,
    app_info,
)
from yunohost.domain import _get_maindomain, domain_add, domain_remove, domain_list
from yunohost.utils.error import YunohostError
from yunohost.tests.test_permission import (
    check_LDAP_db_integrity,
    check_permission_for_apps,
)
from yunohost.permission import user_permission_list, permission_delete


def setup_function(function):

    clean()


def teardown_function(function):

    clean()


def clean():

    # Make sure we have a ssowat
    os.system("mkdir -p /etc/ssowat/")
    app_ssowatconf()

    test_apps = [
        "break_yo_system",
        "legacy_app",
        "legacy_app__2",
        "manifestv2_app",
        "full_domain_app",
        "my_webapp",
    ]

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

    # Clean permissions
    for permission_name in user_permission_list(short=True)["permissions"]:
        if any(test_app in permission_name for test_app in test_apps):
            permission_delete(permission_name, force=True)


@pytest.fixture(autouse=True)
def check_LDAP_db_integrity_call():
    check_LDAP_db_integrity()
    yield
    check_LDAP_db_integrity()


@pytest.fixture(autouse=True)
def check_permission_for_apps_call():
    check_permission_for_apps()
    yield
    check_permission_for_apps()


@pytest.fixture(scope="module")
def secondary_domain(request):

    if "example.test" not in domain_list()["domains"]:
        domain_add("example.test")

    def remove_example_domain():
        domain_remove("example.test")

    request.addfinalizer(remove_example_domain)

    return "example.test"


#
# Helpers                                                                    #
#


def app_expected_files(domain, app):

    yield "/etc/nginx/conf.d/{}.d/{}.conf".format(domain, app)
    if app.startswith("legacy_app"):
        yield "/var/www/%s/index.html" % app
    yield "/etc/yunohost/apps/%s/settings.yml" % app
    if "manifestv2" in app:
        yield "/etc/yunohost/apps/%s/manifest.toml" % app
    else:
        yield "/etc/yunohost/apps/%s/manifest.json" % app
    yield "/etc/yunohost/apps/%s/scripts/install" % app
    yield "/etc/yunohost/apps/%s/scripts/remove" % app


def app_is_installed(domain, app):

    return _is_installed(app) and all(
        os.path.exists(f) for f in app_expected_files(domain, app)
    )


def app_is_not_installed(domain, app):

    return not _is_installed(app) and not all(
        os.path.exists(f) for f in app_expected_files(domain, app)
    )


def app_is_exposed_on_http(domain, path, message_in_page):

    try:
        r = requests.get(
            "https://127.0.0.1" + path + "/",
            headers={"Host": domain},
            timeout=10,
            verify=False,
        )
        return r.status_code == 200 and message_in_page in r.text
    except Exception:
        return False


def install_legacy_app(domain, path, public=True):

    app_install(
        os.path.join(get_test_apps_dir(), "legacy_app_ynh"),
        args="domain={}&path={}&is_public={}".format(domain, path, 1 if public else 0),
        force=True,
    )


def install_manifestv2_app(domain, path, public=True):

    app_install(
        os.path.join(get_test_apps_dir(), "manifestv2_app_ynh"),
        args="domain={}&path={}&init_main_permission={}".format(domain, path, "visitors" if public else "all_users"),
        force=True,
    )


def install_full_domain_app(domain):

    app_install(
        os.path.join(get_test_apps_dir(), "full_domain_app_ynh"),
        args="domain=%s" % domain,
        force=True,
    )


def install_break_yo_system(domain, breakwhat):

    app_install(
        os.path.join(get_test_apps_dir(), "break_yo_system_ynh"),
        args="domain={}&breakwhat={}".format(domain, breakwhat),
        force=True,
    )


def test_legacy_app_install_main_domain():

    main_domain = _get_maindomain()

    install_legacy_app(main_domain, "/legacy")

    app_map_ = app_map(raw=True)
    assert main_domain in app_map_
    assert "/legacy" in app_map_[main_domain]
    assert "id" in app_map_[main_domain]["/legacy"]
    assert app_map_[main_domain]["/legacy"]["id"] == "legacy_app"

    assert app_is_installed(main_domain, "legacy_app")
    assert app_is_exposed_on_http(main_domain, "/legacy", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(main_domain, "legacy_app")


def test_legacy_app_manifest_preinstall():

    m = app_manifest(os.path.join(get_test_apps_dir(), "legacy_app_ynh"))
    # v1 manifesto are expected to have been autoconverted to v2

    assert "id" in m
    assert "description" in m
    assert "integration" in m
    assert "install" in m
    assert "doc" in m and not m["doc"]
    assert "notifications" in m and not m["notifications"]


def test_manifestv2_app_manifest_preinstall():

    m = app_manifest(os.path.join(get_test_apps_dir(), "manifestv2_app_ynh"))

    assert "id" in m
    assert "install" in m
    assert "description" in m
    assert "doc" in m
    assert "This is a dummy description of this app features" in m["doc"]["DESCRIPTION"]
    assert "notifications" in m
    assert "This is a dummy disclaimer to display prior to the install" in m["notifications"]["pre_install"]


def test_manifestv2_app_install_main_domain():

    main_domain = _get_maindomain()

    install_manifestv2_app(main_domain, "/manifestv2")

    app_map_ = app_map(raw=True)
    assert main_domain in app_map_
    assert "/manifestv2" in app_map_[main_domain]
    assert "id" in app_map_[main_domain]["/manifestv2"]
    assert app_map_[main_domain]["/manifestv2"]["id"] == "manifestv2_app"

    assert app_is_installed(main_domain, "manifestv2_app")
    assert app_is_exposed_on_http(main_domain, "/manifestv2", "Hextris")

    app_remove("manifestv2_app")

    assert app_is_not_installed(main_domain, "manifestv2_app")


def test_manifestv2_app_info_postinstall():

    main_domain = _get_maindomain()
    install_manifestv2_app(main_domain, "/manifestv2")
    m = app_info("manifestv2_app", full=True)["manifest"]

    assert "id" in m
    assert "install" in m
    assert "description" in m
    assert "doc" in m
    assert "The app install dir is /var/www/manifestv2_app" in m["doc"]["ADMIN"]
    assert "notifications" in m
    assert "The app install dir is /var/www/manifestv2_app" in m["notifications"]["post_install"]
    assert "The app id is manifestv2_app" in m["notifications"]["post_install"]
    assert f"The app url is {main_domain}/manifestv2" in m["notifications"]["post_install"]


def test_manifestv2_app_info_preupgrade(monkeypatch):

    from yunohost.app_catalog import _load_apps_catalog as original_load_apps_catalog
    def custom_load_apps_catalog(*args, **kwargs):

        res = original_load_apps_catalog(*args, **kwargs)
        res["apps"]["manifestv2_app"] = {
            "id": "manifestv2_app",
            "level": 10,
            "lastUpdate": 999999999,
            "maintained": True,
            "manifest": app_manifest(os.path.join(get_test_apps_dir(), "manifestv2_app_ynh")),
        }
        res["apps"]["manifestv2_app"]["manifest"]["version"] = "99999~ynh1"

        return res
    monkeypatch.setattr("yunohost.app._load_apps_catalog", custom_load_apps_catalog)

    main_domain = _get_maindomain()
    install_manifestv2_app(main_domain, "/manifestv2")
    i = app_info("manifestv2_app", full=True)

    assert i["upgradable"] == "yes"
    assert i["new_version"] == "99999~ynh1"
    # FIXME : as I write this test, I realize that this implies the catalog API
    # does provide the notifications, which means the list builder script
    # should parse the files in the original app repo, possibly with proper i18n etc
    assert "This is a dummy disclaimer to display prior to any upgrade" \
            in i["from_catalog"]["manifest"]["notifications"]["pre_upgrade"]

def test_app_from_catalog():
    main_domain = _get_maindomain()

    app_install(
        "my_webapp",
        args=f"domain={main_domain}&path=/site&with_sftp=0&password=superpassword&is_public=1&with_mysql=0",
    )
    app_map_ = app_map(raw=True)
    assert main_domain in app_map_
    assert "/site" in app_map_[main_domain]
    assert "id" in app_map_[main_domain]["/site"]
    assert app_map_[main_domain]["/site"]["id"] == "my_webapp"

    assert app_is_installed(main_domain, "my_webapp")
    assert app_is_exposed_on_http(main_domain, "/site", "Custom Web App")

    # Try upgrade, should do nothing
    app_upgrade("my_webapp")
    # Force upgrade, should upgrade to the same version
    app_upgrade("my_webapp", force=True)

    app_remove("my_webapp")

    assert app_is_not_installed(main_domain, "my_webapp")


def test_legacy_app_install_secondary_domain(secondary_domain):

    install_legacy_app(secondary_domain, "/legacy")

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_exposed_on_http(secondary_domain, "/legacy", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_secondary_domain_on_root(secondary_domain):

    install_legacy_app(secondary_domain, "/")

    app_map_ = app_map(raw=True)
    assert secondary_domain in app_map_
    assert "/" in app_map_[secondary_domain]
    assert "id" in app_map_[secondary_domain]["/"]
    assert app_map_[secondary_domain]["/"]["id"] == "legacy_app"

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_exposed_on_http(secondary_domain, "/", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_private(secondary_domain):

    install_legacy_app(secondary_domain, "/legacy", public=False)

    assert app_is_installed(secondary_domain, "legacy_app")
    assert not app_is_exposed_on_http(
        secondary_domain, "/legacy", "This is a dummy app"
    )

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_unknown_domain(mocker):

    with pytest.raises(YunohostError):
        with message(mocker, "app_argument_invalid"):
            install_legacy_app("whatever.nope", "/legacy")

    assert app_is_not_installed("whatever.nope", "legacy_app")


def test_legacy_app_install_multiple_instances(secondary_domain):

    install_legacy_app(secondary_domain, "/foo")
    install_legacy_app(secondary_domain, "/bar")

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_exposed_on_http(secondary_domain, "/foo", "This is a dummy app")

    assert app_is_installed(secondary_domain, "legacy_app__2")
    assert app_is_exposed_on_http(secondary_domain, "/bar", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")
    assert app_is_installed(secondary_domain, "legacy_app__2")

    app_remove("legacy_app__2")

    assert app_is_not_installed(secondary_domain, "legacy_app")
    assert app_is_not_installed(secondary_domain, "legacy_app__2")


def test_legacy_app_install_path_unavailable(mocker, secondary_domain):

    # These will be removed in teardown
    install_legacy_app(secondary_domain, "/legacy")

    with pytest.raises(YunohostError):
        with message(mocker, "app_location_unavailable"):
            install_legacy_app(secondary_domain, "/")

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_not_installed(secondary_domain, "legacy_app__2")


def test_legacy_app_install_with_nginx_down(mocker, secondary_domain):

    os.system("systemctl stop nginx")

    with raiseYunohostError(
        mocker, "app_action_cannot_be_ran_because_required_services_down"
    ):
        install_legacy_app(secondary_domain, "/legacy")


def test_legacy_app_failed_install(mocker, secondary_domain):

    # This will conflict with the folder that the app
    # attempts to create, making the install fail
    mkdir("/var/www/legacy_app/", 0o750)

    with pytest.raises(YunohostError):
        with message(mocker, "app_install_script_failed"):
            install_legacy_app(secondary_domain, "/legacy")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_failed_remove(mocker, secondary_domain):

    install_legacy_app(secondary_domain, "/legacy")

    # The remove script runs with set -eu and attempt to remove this
    # file without -f, so will fail if it's not there ;)
    os.remove("/etc/nginx/conf.d/{}.d/{}.conf".format(secondary_domain, "legacy_app"))

    # TODO / FIXME : can't easily validate that 'app_not_properly_removed'
    # is triggered for weird reasons ...
    app_remove("legacy_app")

    #
    # Well here, we hit the classical issue where if an app removal script
    # fails, so far there's no obvious way to make sure that all files related
    # to this app got removed ...
    #
    assert app_is_not_installed(secondary_domain, "legacy")


def test_full_domain_app(secondary_domain):

    install_full_domain_app(secondary_domain)

    assert app_is_exposed_on_http(secondary_domain, "/", "This is a dummy app")


def test_full_domain_app_with_conflicts(mocker, secondary_domain):

    install_legacy_app(secondary_domain, "/legacy")

    with raiseYunohostError(mocker, "app_full_domain_unavailable"):
        install_full_domain_app(secondary_domain)


def test_systemfuckedup_during_app_install(mocker, secondary_domain):

    with pytest.raises(YunohostError):
        with message(mocker, "app_install_failed"):
            with message(mocker, "app_action_broke_system"):
                install_break_yo_system(secondary_domain, breakwhat="install")

    assert app_is_not_installed(secondary_domain, "break_yo_system")


def test_systemfuckedup_during_app_remove(mocker, secondary_domain):

    install_break_yo_system(secondary_domain, breakwhat="remove")

    with pytest.raises(YunohostError):
        with message(mocker, "app_action_broke_system"):
            with message(mocker, "app_removed"):
                app_remove("break_yo_system")

    assert app_is_not_installed(secondary_domain, "break_yo_system")


def test_systemfuckedup_during_app_install_and_remove(mocker, secondary_domain):

    with pytest.raises(YunohostError):
        with message(mocker, "app_install_failed"):
            with message(mocker, "app_action_broke_system"):
                install_break_yo_system(secondary_domain, breakwhat="everything")

    assert app_is_not_installed(secondary_domain, "break_yo_system")


def test_systemfuckedup_during_app_upgrade(mocker, secondary_domain):

    install_break_yo_system(secondary_domain, breakwhat="upgrade")

    with pytest.raises(YunohostError):
        with message(mocker, "app_action_broke_system"):
            app_upgrade(
                "break_yo_system",
                file=os.path.join(get_test_apps_dir(), "break_yo_system_ynh"),
            )


def test_failed_multiple_app_upgrade(mocker, secondary_domain):

    install_legacy_app(secondary_domain, "/legacy")
    install_break_yo_system(secondary_domain, breakwhat="upgrade")

    with pytest.raises(YunohostError):
        with message(mocker, "app_not_upgraded"):
            app_upgrade(
                ["break_yo_system", "legacy_app"],
                file={
                    "break_yo_system": os.path.join(
                        get_test_apps_dir(), "break_yo_system_ynh"
                    ),
                    "legacy": os.path.join(get_test_apps_dir(), "legacy_app_ynh"),
                },
            )
