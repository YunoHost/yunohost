import pytest
import time
import requests
import os
import shutil
import subprocess
from mock import ANY

from moulinette.core import init_authenticator
from yunohost.app import app_install, app_remove, app_ssowatconf
from yunohost.app import _is_installed
from yunohost.backup import backup_create, backup_restore, backup_list, backup_info, backup_delete
from yunohost.domain import _get_maindomain
from moulinette.core import MoulinetteError

# Get main domain
maindomain = _get_maindomain()

# Instantiate LDAP Authenticator
AUTH_IDENTIFIER = ('ldap', 'ldap-anonymous')
AUTH_PARAMETERS = {'uri': 'ldap://localhost:389', 'base_dn': 'dc=yunohost,dc=org'}
auth = None

def setup_function(function):

    global auth
    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

    assert backup_test_dependencies_are_met()

    clean_tmp_backup_directory()
    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

    assert len(backup_list()["archives"]) == 0

    markers = function.__dict__.keys()

    if "with_wordpress_archive_from_2p4" in markers:
        add_archive_wordpress_from_2p4()
        assert len(backup_list()["archives"]) == 1

    if "with_backup_legacy_app_installed" in markers:
        assert not app_is_installed("backup_legacy_app")
        install_app("backup_legacy_app_ynh", "/yolo")
        assert app_is_installed("backup_legacy_app")

    if "with_backup_recommended_app_installed" in markers:
        assert not app_is_installed("backup_recommended_app")
        install_app("backup_recommended_app_ynh", "/yolo")
        assert app_is_installed("backup_recommended_app")

    print ""

def teardown_function(function):

    global auth
    auth = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

    assert tmp_backup_directory_is_empty()

    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

###############################################################################
#  Helpers                                                                    #
###############################################################################

def app_is_installed(app):

    # These are files we know should be installed by the app
    app_files = []
    app_files.append("/etc/nginx/conf.d/%s.d/%s.conf" % (maindomain, app))
    app_files.append("/var/www/%s/index.html" % app)
    app_files.append("/etc/importantfile")

    return _is_installed(app) and all(os.path.exists(f) for f in app_files)


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

    mount_lines = subprocess.check_output("mount").split("\n")

    points_to_umount = [ line.split(" ")[2]
                         for line in mount_lines
                            if  len(line) >= 3
                            and line.split(" ")[2].startswith("/home/yunohost.backup/tmp") ]

    for point in reversed(points_to_umount):
        os.system("umount %s" % point)

    for f in os.listdir('/home/yunohost.backup/tmp/'):
        shutil.rmtree("/home/yunohost.backup/tmp/%s" % f)

    shutil.rmtree("/home/yunohost.backup/tmp/")

def reset_ssowat_conf():

    # Make sure we have a ssowat
    os.system("mkdir -p /etc/ssowat/")
    app_ssowatconf(auth)


def delete_all_backups():

    for archive in backup_list()["archives"]:
        backup_delete(archive)


def uninstall_test_apps_if_needed():

    if _is_installed("backup_legacy_app"):
        app_remove(auth, "backup_legacy_app")

    if _is_installed("backup_recommended_app"):
        app_remove(auth, "backup_recommended_app")

    if _is_installed("wordpress"):
        app_remove(auth, "wordpress")


def install_app(app, path):

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

def test_backup_only_ldap():

    # Crate the backup
    backup_create(ignore_hooks=False, ignore_apps=True, hooks=["conf_ldap"])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["hooks"].keys()) == 1
    assert "conf_ldap" in archives_info["hooks"].keys()


def test_backup_sys_stuff_that_does_not_exists():

    # Crate the backup
    backup_create(ignore_hooks=False, ignore_apps=True, hooks=["yolol"])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert archives_info["hooks"] == {}


def test_backup_and_restore_all_sys():

    # Crate the backup
    backup_create(ignore_hooks=False, ignore_apps=True)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert (len(archives_info["hooks"].keys()) ==
            len(os.listdir("/usr/share/yunohost/hooks/backup/")))

    # Remove ssowat conf
    assert os.path.exists("/etc/ssowat/conf.json")
    os.system("rm -rf /etc/ssowat/")
    assert not os.path.exists("/etc/ssowat/conf.json")

    # Restore the backup
    backup_restore(auth, name=archives[0], force=True,
                   ignore_hooks=False, ignore_apps=True)

    # Check ssowat conf is back
    assert os.path.exists("/etc/ssowat/conf.json")


@pytest.mark.with_backup_legacy_app_installed
def test_backup_and_restore_legacy_app():

    _test_backup_and_restore_app("backup_legacy_app")


@pytest.mark.with_backup_recommended_app_installed
def test_backup_and_restore_recommended_app():

    _test_backup_and_restore_app("backup_recommended_app")


def _test_backup_and_restore_app(app):

    # Create a backup of this app
    backup_create(ignore_hooks=True, ignore_apps=False, apps=[app])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["hooks"] == {}
    assert len(archives_info["apps"].keys()) == 1
    assert "app" in archives_info["apps"].keys()

    # Uninstall the app
    app_remove(auth, app)
    assert not app_is_installed(app)

    # Restore the app
    backup_restore(auth, name=archives[0], ignore_hooks=True,
                   ignore_apps=False, apps=[app])

    assert app_is_installed(app)


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_wordpress_from_Ynh2p4():

    backup_restore(auth, name=backup_list()["archives"][0],
                         ignore_hooks=True,
                         ignore_apps=False,
                         apps=["wordpress"])


@pytest.mark.with_backup_recommended_app_installed
def test_backup_script_failure_handling(monkeypatch, mocker):

    def custom_hook_exec(name, *args, **kwargs):

        if os.path.basename(name).startswith("backup_"):
            raise Exception
        else:
            return True

    # Create a backup of this app and simulate a crash (patching the backup
    # call with monkeypatch). We also patch m18n to check later it's been called
    # with the expected error message key
    monkeypatch.setattr("yunohost.backup.hook_exec", custom_hook_exec)
    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_create(ignore_hooks=True, ignore_apps=False, apps=["backup_recommended_app"])

    m18n.n.assert_any_call('backup_app_failed', app='backup_recommended_app')


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_script_failure_handling(monkeypatch, mocker):

    def custom_hook_exec(name, *args, **kwargs):
        if os.path.basename(name).startswith("restore"):
            monkeypatch.undo()
            raise Exception

    monkeypatch.setattr("yunohost.backup.hook_exec", custom_hook_exec)
    mocker.spy(m18n, "n")

    assert not _is_installed("wordpress")

    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_hooks=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('restore_app_failed', app='wordpress')
    m18n.n.assert_any_call('restore_nothings_done')
    assert not _is_installed("wordpress")


@pytest.mark.with_backup_recommended_app_installed
def test_backup_not_enough_free_space(monkeypatch, mocker):

    def custom_subprocess(command):
        if command[0] == "df":
            return "lol? 0"
        elif command[0] == "du":
            return "999999999999999999999"
        else:
            raise Exception("subprocess called with something else than df or du")

    monkeypatch.setattr("subprocess.check_output", custom_subprocess)
    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_create(ignore_hooks=True, ignore_apps=False, apps=["backup_recommended_app"])

    m18n.n.assert_any_call('not_enough_disk_space', path=ANY)


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_not_enough_free_space(monkeypatch, mocker):

    def custom_os_statvfs(path):
        class Stat:
            f_frsize = 0
            f_bavail = 0
        return Stat()

    monkeypatch.setattr("os.statvfs", custom_os_statvfs)
    mocker.spy(m18n, "n")

    assert not _is_installed("wordpress")

    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_hooks=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('restore_not_enough_disk_space',
        free_space=0,
        margin=ANY,
        needed_space=ANY)
    assert not _is_installed("wordpress")


# Test that system hooks are not executed with --ignore--hooks

# Test ynh_restore

# Test the copy method, not just the tar method ?
