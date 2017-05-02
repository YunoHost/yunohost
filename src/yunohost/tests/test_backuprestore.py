import pytest
import time
import requests
import os
import shutil
from mock import ANY

from moulinette.core import init_authenticator
from yunohost.app import app_install, app_remove, app_ssowatconf
from yunohost.app import _is_installed as app_is_installed
from yunohost.backup import backup_create, backup_restore, backup_list, backup_info, backup_delete
from yunohost.domain import _get_maindomain
from moulinette.core import MoulinetteError

# Get main domain
maindomain = _get_maindomain()

# Instantiate LDAP Authenticator
AUTH_IDENTIFIER = ('ldap', 'ldap-anonymous')
AUTH_PARAMETERS = {'uri': 'ldap://localhost:389', 'base_dn': 'dc=yunohost,dc=org'}

def setup_function(function):

    assert backup_test_dependencies_are_met()

    clean_tmp_backup_directory()
    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

def teardown_function(function):

    assert tmp_backup_directory_is_empty()

    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

###############################################################################
#  Helpers                                                                    #
###############################################################################

def backup_test_dependencies_are_met():

    # We need archivemount installed for the backup features to work
    assert os.system("which archivemount >/dev/null") == 0

    # Dummy test apps (or backup archives)
    assert os.path.exists("./tests/apps/backup_wordpress_from_2p4")
    assert os.path.exists("./tests/apps/backup_legacy_app_ynh")
    assert os.path.exists("./tests/apps/backup_recommended_app_ynh")

    return True

def tmp_backup_directory_is_empty():

    if not os.path.exists("/home/yunohost.backup/tmp/"):
        return True
    else:
        return len(os.listdir('/home/yunohost.backup/tmp/')) == 0

def clean_tmp_backup_directory():

    if tmp_backup_directory_is_empty():
        return

    for f in os.listdir('/home/yunohost.backup/tmp/'):
        print f
        try:
            os.system("umount /home/yunohost.backup/tmp/%s" % f)
        except:
            shutil.rmtree("/home/yunohost.backup/tmp/%s" % f)

    shutil.rmtree("/home/yunohost.backup/tmp/")

def reset_ssowat_conf():

    # Make sure we have a ssowat
    os.system("mkdir -p /etc/ssowat/")
    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_ssowatconf(auth)


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


def add_archive_wordpress_from_2p4():

    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.info.json \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.info.json")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.tar.gz \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.tar.gz")

###############################################################################
#  Actual tests                                                               #
###############################################################################

def test_backup_and_restore_sys():

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

    # These are files we know should be installed by the app
    app_files = []
    app_files.append("/etc/nginx/conf.d/%s.d/%s.conf" % (maindomain, app))
    app_files.append("/var/www/%s/index.html" % app)
    app_files.append("/etc/importantfile")

    assert not app_is_installed(app)
    assert all(not os.path.exists(f) for f in app_files)

    # Install the app
    install_app("%s_ynh" % app, "/yolo")

    assert app_is_installed(app)
    assert all(os.path.exists(f) for f in app_files)

    # Create a backup of this app
    backup_create(ignore_hooks=True, ignore_apps=False, apps=[app])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    # Uninstall the app
    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    app_remove(auth, app)

    assert not app_is_installed(app)
    assert all(not os.path.exists(f) for f in app_files)

    # Restore the app
    backup_restore(auth, name=archives[0], ignore_hooks=True,
                   ignore_apps=False, apps=[app])

    assert app_is_installed(app)
    assert all(os.path.exists(f) for f in app_files)


def test_restore_wordpress_from_Ynh2p4():

    assert len(backup_list()["archives"]) == 0
    add_archive_wordpress_from_2p4()
    assert len(backup_list()["archives"]) == 1

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)
    backup_restore(auth, name=backup_list()["archives"][0],
                         ignore_hooks=True,
                         ignore_apps=False,
                         apps=["wordpress"])


def test_backup_script_failure_handling(monkeypatch, mocker):

    def custom_hook_exec(name, *args, **kwargs):

        if os.path.basename(name).startswith("backup_"):
            raise Exception
        else:
            return True

    # Install the app
    app = "backup_recommended_app"
    install_app("%s_ynh" % app, "/yolo")
    assert app_is_installed(app)

    # Create a backup of this app and simulate a crash (patching the backup
    # call with monkeypatch). We also patch m18n to check later it's been called
    # with the expected error message key
    monkeypatch.setattr("yunohost.backup.hook_exec", custom_hook_exec)
    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_create(ignore_hooks=True, ignore_apps=False, apps=[app])

    m18n.n.assert_any_call('backup_app_failed', app='backup_recommended_app')


def test_restore_script_failure_handling(monkeypatch, mocker):

    def custom_hook_exec(name, *args, **kwargs):
        if os.path.basename(name).startswith("restore"):
            monkeypatch.undo()
            raise Exception

    assert len(backup_list()["archives"]) == 0
    add_archive_wordpress_from_2p4()
    assert len(backup_list()["archives"]) == 1

    monkeypatch.setattr("yunohost.backup.hook_exec", custom_hook_exec)
    mocker.spy(m18n, "n")

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

    assert not app_is_installed("wordpress")

    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_hooks=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('restore_app_failed', app='wordpress')
    m18n.n.assert_any_call('restore_nothings_done')
    assert not app_is_installed("wordpress")


def test_backup_not_enough_free_space(monkeypatch, mocker):

    def custom_subprocess(command):
        if command[0] == "df":
            return "lol? 0"
        elif command[0] == "du":
            return "999999999999999999999"
        else:
            raise Exception("subprocess called with something else than df or du")

    # Install the app
    app = "backup_recommended_app"
    install_app("%s_ynh" % app, "/yolo")
    assert app_is_installed(app)

    monkeypatch.setattr("subprocess.check_output", custom_subprocess)
    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_create(ignore_hooks=True, ignore_apps=False, apps=[app])

    m18n.n.assert_any_call('not_enough_disk_space', path=ANY)



def test_restore_not_enough_free_space(monkeypatch, mocker):

    def custom_os_statvfs(path):
        class Stat:
            f_frsize = 0
            f_bavail = 0
        return Stat()

    assert len(backup_list()["archives"]) == 0
    add_archive_wordpress_from_2p4()
    assert len(backup_list()["archives"]) == 1

    monkeypatch.setattr("os.statvfs", custom_os_statvfs)
    mocker.spy(m18n, "n")

    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

    assert not app_is_installed("wordpress")

    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_hooks=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('may_be_not_enough_disk_space', path="/home/yunohost.backup")
    m18n.n.assert_any_call('restore_nothings_done')
    assert not app_is_installed("wordpress")


# Test that system hooks are not executed with --ignore--hooks

# Test the copy method, not just the tar method ?


