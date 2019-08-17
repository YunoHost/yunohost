import glob
import os
import pytest
import shutil
import requests

from moulinette import m18n
from moulinette.utils.filesystem import mkdir

from yunohost.app import app_install, app_remove, app_ssowatconf, _is_installed
from yunohost.domain import _get_maindomain, domain_add, domain_remove, domain_list
from yunohost.utils.error import YunohostError
from yunohost.tests.test_permission import check_LDAP_db_integrity, check_permission_for_apps


MAIN_DOMAIN = _get_maindomain()


def setup_function(function):

    clean()

def teardown_function(function):

    clean()

def clean():

    # Make sure we have a ssowat
    os.system("mkdir -p /etc/ssowat/")
    app_ssowatconf()

    if _is_installed("legacy_app"):
        app_remove("legacy_app")

    to_remove = []
    to_remove += glob.glob("/etc/nginx/conf.d/*.d/*legacy*")
    for filepath in to_remove:
        os.remove(filepath)

    to_remove = []
    to_remove += glob.glob("/etc/yunohost/apps/*legacy_app*")
    to_remove += glob.glob("/var/www/*legacy*")
    for folderpath in to_remove:
        shutil.rmtree(folderpath, ignore_errors=True)


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

@pytest.fixture(scope="session")
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

    yield "/etc/nginx/conf.d/%s.d/%s.conf" % (domain, app)
    yield "/var/www/%s/index.html" % app
    yield "/etc/yunohost/apps/%s/settings.yml" % app
    yield "/etc/yunohost/apps/%s/manifest.json" % app
    yield "/etc/yunohost/apps/%s/scripts/install" % app
    yield "/etc/yunohost/apps/%s/scripts/remove" % app
    yield "/etc/yunohost/apps/%s/scripts/backup" % app
    yield "/etc/yunohost/apps/%s/scripts/restore" % app


def app_is_installed(domain, app):

    return _is_installed(app) and all(os.path.exists(f) for f in app_expected_files(domain, app))


def app_is_not_installed(domain, app):

    return not _is_installed(app) and not all(os.path.exists(f) for f in app_expected_files(domain, app))


def app_is_exposed_on_http(domain, path, message_in_page):

    try:
        r = requests.get("http://127.0.0.1" + path + "/", headers={"Host": domain}, timeout=10)
        return r.status_code == 200 and message_in_page in r.text
    except Exception:
        return False


def install_legacy_app(domain, path):

    app_install("./tests/apps/legacy_app_ynh",
                args="domain=%s&path=%s" % (domain, path),
                force=True)


def test_legacy_app_install_main_domain():

    install_legacy_app(MAIN_DOMAIN, "/legacy")

    assert app_is_installed(MAIN_DOMAIN, "legacy_app")
    assert app_is_exposed_on_http(MAIN_DOMAIN, "/legacy", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(MAIN_DOMAIN, "legacy_app")


def test_legacy_app_install_secondary_domain(secondary_domain):

    install_legacy_app(secondary_domain, "/legacy")

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_exposed_on_http(secondary_domain, "/legacy", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_secondary_domain_on_root(secondary_domain):

    install_legacy_app(secondary_domain, "/")

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_exposed_on_http(secondary_domain, "/", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_private(secondary_domain):

    install_legacy_app(secondary_domain, "/legacy")

    settings = open("/etc/yunohost/apps/legacy_app/settings.yml", "r").read()
    new_settings = settings.replace("\nunprotected_uris: /", "")
    assert new_settings != settings
    open("/etc/yunohost/apps/legacy_app/settings.yml", "w").write(new_settings)
    app_ssowatconf()

    assert app_is_installed(secondary_domain, "legacy_app")
    assert not app_is_exposed_on_http(secondary_domain, "/legacy", "This is a dummy app")

    app_remove("legacy_app")

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_unknown_domain():

    with pytest.raises(YunohostError):
        install_legacy_app("whatever.nope", "/legacy")
        # TODO check error message

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


def test_legacy_app_install_path_unavailable(secondary_domain):

    # These will be removed in teardown
    install_legacy_app(secondary_domain, "/legacy")

    with pytest.raises(YunohostError):
        install_legacy_app(secondary_domain, "/")
        # TODO check error message

    assert app_is_installed(secondary_domain, "legacy_app")
    assert app_is_not_installed(secondary_domain, "legacy_app__2")


def test_legacy_app_failed_install(secondary_domain):

    mkdir("/var/www/legacy_app/", 0o750)

    with pytest.raises(YunohostError):
        install_legacy_app(secondary_domain, "/legacy")
        # TODO check error message

    assert app_is_not_installed(secondary_domain, "legacy_app")


def test_legacy_app_install_with_nginx_down(secondary_domain):

    os.system("systemctl stop nginx")

    with pytest.raises(YunohostError):
        install_legacy_app(secondary_domain, "/legacy")

    os.system("systemctl start nginx")


def test_legacy_app_failed_remove():

    # FIXME What's supposed to happen lol
    raise NotImplementedError


def test_legacy_app_install_fucksup_nginx():

    # FIXME What's supposed to happen lol
    raise NotImplementedError

def test_legacy_app_install_with_dpkg_fuckedup():

    raise NotImplementedError
