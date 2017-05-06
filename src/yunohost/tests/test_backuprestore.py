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

    print ""

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
        install_app("backup_recommended_app_ynh", "/yolo",
                    "&helper_to_test=ynh_restore_file")
        assert app_is_installed("backup_recommended_app")

    if "with_backup_recommended_app_installed_with_ynh_restore" in markers:
        assert not app_is_installed("backup_recommended_app")
        install_app("backup_recommended_app_ynh", "/yolo",
                    "&helper_to_test=ynh_restore")
        assert app_is_installed("backup_recommended_app")

def teardown_function(function):

    print ""
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


def install_app(app, path, additionnal_args=""):

    app_install(auth, "./tests/apps/%s" % app,
                args="domain=%s&path=%s%s" % (maindomain, path,
                                              additionnal_args))


def add_archive_wordpress_from_2p4():

    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.info.json \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.info.json")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.tar.gz \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.tar.gz")

###############################################################################
#  System backup                                                              #
###############################################################################

def test_backup_only_ldap():

    # Crate the backup
    backup_create(ignore_system=False, ignore_apps=True, system=["conf_ldap"])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["system"].keys()) == 1
    assert "conf_ldap" in archives_info["system"].keys()


def test_backup_system_part_that_does_not_exists(mocker):

    mocker.spy(m18n, "n")

    # Crate the backup
    with pytest.raises(MoulinetteError):
        backup_create(ignore_system=False, ignore_apps=True, system=["yolol"])

    m18n.n.assert_any_call('backup_hook_unknown', hook="yolol")
    m18n.n.assert_any_call('backup_nothings_done')

###############################################################################
#  System backup and restore                                                  #
###############################################################################

def test_backup_and_restore_all_sys():

    # Crate the backup
    backup_create(ignore_system=False, ignore_apps=True)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert (len(archives_info["system"].keys()) ==
            len(os.listdir("/usr/share/yunohost/hooks/backup/")))

    # Remove ssowat conf
    assert os.path.exists("/etc/ssowat/conf.json")
    os.system("rm -rf /etc/ssowat/")
    assert not os.path.exists("/etc/ssowat/conf.json")

    # Restore the backup
    backup_restore(auth, name=archives[0], force=True,
                   ignore_system=False, ignore_apps=True)

    # Check ssowat conf is back
    assert os.path.exists("/etc/ssowat/conf.json")


###############################################################################
#  App backup                                                                 #
###############################################################################

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
        backup_create(ignore_system=True, ignore_apps=False, apps=["backup_recommended_app"])

    m18n.n.assert_any_call('backup_app_failed', app='backup_recommended_app')

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
        backup_create(ignore_system=True, ignore_apps=False, apps=["backup_recommended_app"])

    m18n.n.assert_any_call('not_enough_disk_space', path=ANY)


def test_backup_app_not_installed(mocker):

    assert not _is_installed("wordpress")

    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_create(ignore_system=True, ignore_apps=False, apps=["wordpress"])

    m18n.n.assert_any_call("unbackup_app", app="wordpress")
    m18n.n.assert_any_call('backup_nothings_done')


@pytest.mark.with_backup_recommended_app_installed
def test_backup_app_with_no_backup_script(mocker):

    backup_script = "/etc/yunohost/apps/backup_recommended_app/scripts/backup"
    os.system("rm %s" % backup_script)
    assert not os.path.exists(backup_script)

    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_create(ignore_system=True, ignore_apps=False, apps=["backup_recommended_app"])

    m18n.n.assert_any_call("backup_with_no_backup_script_for_app", app="backup_recommended_app")
    m18n.n.assert_any_call('backup_nothings_done')


@pytest.mark.with_backup_recommended_app_installed
def test_backup_app_with_no_restore_script(mocker):

    restore_script = "/etc/yunohost/apps/backup_recommended_app/scripts/restore"
    os.system("rm %s" % restore_script)
    assert not os.path.exists(restore_script)

    mocker.spy(m18n, "n")

    # Backuping an app with no restore script will only display a warning to the
    # user...

    backup_create(ignore_system=True, ignore_apps=False, apps=["backup_recommended_app"])

    m18n.n.assert_any_call("backup_with_no_restore_script_for_app", app="backup_recommended_app")


@pytest.mark.skip(reason="Test not implemented yet.")
def test_backup_with_different_output_directory():
    pass

@pytest.mark.skip(reason="Test not implemented yet.")
def test_backup_with_no_compress():
    # Or "copy" method
    pass


###############################################################################
#  App restore                                                                #
###############################################################################

@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_wordpress_from_Ynh2p4():

    backup_restore(auth, name=backup_list()["archives"][0],
                         ignore_system=True,
                         ignore_apps=False,
                         apps=["wordpress"])


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_script_failure_handling(monkeypatch, mocker):

    def custom_hook_exec(name, *args, **kwargs):
        if os.path.basename(name).startswith("restore"):
            monkeypatch.undo()
            raise Exception

    monkeypatch.setattr("yunohost.backup.hook_exec", custom_hook_exec)
    mocker.spy(m18n, "n")

    assert not _is_installed("wordpress")

    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_system=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('restore_app_failed', app='wordpress')
    m18n.n.assert_any_call('restore_nothings_done')
    assert not _is_installed("wordpress")


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_not_enough_free_space(monkeypatch, mocker):

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
                             ignore_system=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('restore_not_enough_disk_space',
        free_space=0,
        margin=ANY,
        needed_space=ANY)
    assert not _is_installed("wordpress")


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_not_in_backup(mocker):

    assert not _is_installed("wordpress")
    assert not _is_installed("yoloswag")

    mocker.spy(m18n, "n")

    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_system=True,
                             ignore_apps=False,
                             apps=["yoloswag"])

    m18n.n.assert_any_call('backup_archive_app_not_found', app="yoloswag")
    assert not _is_installed("wordpress")
    assert not _is_installed("yoloswag")


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_already_installed(mocker):

    assert not _is_installed("wordpress")

    backup_restore(auth, name=backup_list()["archives"][0],
                         ignore_system=True,
                         ignore_apps=False,
                         apps=["wordpress"])

    assert _is_installed("wordpress")

    mocker.spy(m18n, "n")
    with pytest.raises(MoulinetteError):
        backup_restore(auth, name=backup_list()["archives"][0],
                             ignore_system=True,
                             ignore_apps=False,
                             apps=["wordpress"])

    m18n.n.assert_any_call('restore_already_installed_app', app="wordpress")
    m18n.n.assert_any_call('restore_nothings_done')

    assert _is_installed("wordpress")


@pytest.mark.with_backup_legacy_app_installed
def test_backup_and_restore_legacy_app():

    _test_backup_and_restore_app("backup_legacy_app")


@pytest.mark.with_backup_recommended_app_installed
def test_backup_and_restore_recommended_app():

    _test_backup_and_restore_app("backup_recommended_app")


@pytest.mark.with_backup_recommended_app_installed_with_ynh_restore
def test_backup_and_restore_with_ynh_restore():

    _test_backup_and_restore_app("backup_recommended_app")


def _test_backup_and_restore_app(app):

    # Create a backup of this app
    backup_create(ignore_system=True, ignore_apps=False, apps=[app])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["system"] == {}
    assert len(archives_info["apps"].keys()) == 1
    assert app in archives_info["apps"].keys()

    # Uninstall the app
    app_remove(auth, app)
    assert not app_is_installed(app)

    # Restore the app
    backup_restore(auth, name=archives[0], ignore_system=True,
                   ignore_apps=False, apps=[app])

    assert app_is_installed(app)



