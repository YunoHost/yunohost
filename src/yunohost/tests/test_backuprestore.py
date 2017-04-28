import pytest
import time
import requests
import os

from moulinette.core import init_authenticator
from yunohost.app import app_install, app_remove
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
    delete_all_backups()


def teardown_function(function):
    delete_all_backups()
 
    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    if app_is_installed("backup_legacy_app"):
        app_remove(auth, "backup_legacy_app")

    if app_is_installed("backup_mainstream_app"):
        app_remove(auth, "backup_mainstream_app")


def delete_all_backups():

    for archive in backup_list()["archives"]:
        backup_delete(archive)


def install_app(app, path):

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_install(auth, "./tests/apps/%s" % app,
                args="domain=%s&path=%s" % (maindomain, path))


def test_backup_and_restore_sys():

    backup_create(ignore_hooks=False, ignore_apps=True)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    assert os.path.exists("/etc/ssowat/conf.json")
    os.system("rm -rf /etc/ssowat/")
    assert not os.path.exists("/etc/ssowat/conf.json")

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    backup_restore(auth, name=archives[0], ignore_hooks=False, ignore_apps=True,
            force=True)
    
    assert os.path.exists("/etc/ssowat/conf.json")


def test_backup_and_restore_legacy_app():

    install_app("backup_legacy_app_ynh", "/yolo")
    assert app_is_installed("backup_legacy_app")

    backup_create(ignore_hooks=True, ignore_apps=False, apps=["backup_legacy_app"])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_remove(auth, "backup_legacy_app")
    assert not app_is_installed("backup_legacy_app")

    backup_restore(auth, name=archives[0], ignore_hooks=True, 
                   ignore_apps=False, apps=["backup_legacy_app"])
    assert app_is_installed("backup_legacy_app")
    






