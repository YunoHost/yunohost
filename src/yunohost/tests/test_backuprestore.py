import pytest
import time
import requests
import os

from moulinette.core import init_authenticator
from yunohost.app import app_install, app_remove, app_ssowatconf
from yunohost.app import _is_installed as app_is_installed
from yunohost.backup import backup_create, backup_restore, backup_list, backup_info, backup_delete
from yunohost.domain import _get_maindomain, domain_list
from moulinette.core import MoulinetteError

# Get main domain
maindomain = _get_maindomain()

# Instantiate LDAP Authenticator
AUTH_IDENTIFIER = ('ldap', 'ldap-anonymous')
AUTH_PARAMETERS = {'uri': 'ldap://localhost:389', 'base_dn': 'dc=yunohost,dc=org'}

def setup_function(function):

    os.system("mkdir -p /etc/ssowat/")

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_ssowatconf(auth)

    delete_all_backups()
    uninstall_test_apps_if_needed()


def teardown_function(function):
    delete_all_backups()
    uninstall_test_apps_if_needed()


def delete_all_backups():

    for archive in backup_list()["archives"]:
        backup_delete(archive)


def uninstall_test_apps_if_needed():

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    if app_is_installed("backup_legacy_app"):
        app_remove(auth, "backup_legacy_app")

    if app_is_installed("backup_recommended_app"):
        app_remove(auth, "backup_recommended_app")

    if app_is_installed("wordpress"):
        app_remove(auth, "wordpress")


def install_app(app, path):

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_install(auth, "./tests/apps/%s" % app,
                args="domain=%s&path=%s" % (maindomain, path))


def test_backup_and_restore_sys():

    assert os.system("which archivemount >/dev/null") == 0

    backup_create(ignore_hooks=False, ignore_apps=True)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    assert os.path.exists("/etc/ssowat/conf.json")
    os.system("rm -rf /etc/ssowat/")
    assert not os.path.exists("/etc/ssowat/conf.json")

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    backup_restore(auth, name=archives[0], force=True,
                   ignore_hooks=False, ignore_apps=True)

    assert os.path.exists("/etc/ssowat/conf.json")


def test_backup_and_restore_legacy_app():

    _test_backup_and_restore_app("backup_legacy_app")


def test_backup_and_restore_recommended_app():

    _test_backup_and_restore_app("backup_recommended_app")


def _test_backup_and_restore_app(app):

    assert os.system("which archivemount >/dev/null") == 0

    # These are files we know should be installed by the app
    app_files = []
    app_files.append("/etc/nginx/conf.d/%s.d/%s.conf" % (maindomain, app))
    app_files.append("/var/www/%s/index.html" % app)
    app_files.append("/etc/importantfile")

    assert not app_is_installed(app)
    for f in app_files:
        assert not os.path.exists(f)

    # Install the app
    install_app("%s_ynh" % app, "/yolo")

    assert app_is_installed(app)
    for f in app_files:
        assert os.path.exists(f)

    # Create a backup of this app
    backup_create(ignore_hooks=True, ignore_apps=False, apps=[app])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    # Uninstall the app
    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_remove(auth, app)

    assert not app_is_installed(app)
    for f in app_files:
        assert not os.path.exists(f)

    # Restore the app
    backup_restore(auth, name=archives[0], ignore_hooks=True,
                   ignore_apps=False, apps=[app])

    assert app_is_installed(app)
    for f in app_files:
        assert os.path.exists(f)


def test_restore_wordpress_from_Ynh2p4():

    assert os.system("which archivemount >/dev/null") == 0

    assert len(backup_list()["archives"]) == 0

    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.info.json \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.info.json")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.tar.gz \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.tar.gz")

    archives = backup_list()["archives"]
    assert len(backup_list()["archives"]) == 1

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    backup_restore(auth, name=archives[0], ignore_hooks=True,
                   ignore_apps=False, apps=["wordpress"])


def test_backup_script_failure_handling():
    # TODO
    pass


def test_restore_script_failure_handling():
    #TODO
    pass
