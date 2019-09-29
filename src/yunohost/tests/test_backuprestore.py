import pytest
import os
import shutil
import subprocess
from mock import ANY

from moulinette import m18n
from yunohost.app import app_install, app_remove, app_ssowatconf
from yunohost.app import _is_installed
from yunohost.backup import backup_create, backup_restore, backup_list, backup_info, backup_delete, _recursive_umount
from yunohost.domain import _get_maindomain
from yunohost.utils.error import YunohostError
from yunohost.user import user_permission_list
from yunohost.tests.test_permission import check_LDAP_db_integrity, check_permission_for_apps

# Get main domain
maindomain = ""

def setup_function(function):

    global maindomain
    maindomain = _get_maindomain()

    print ""

    assert backup_test_dependencies_are_met()

    clean_tmp_backup_directory()
    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

    assert len(backup_list()["archives"]) == 0

    markers = [m.name for m in function.__dict__.get("pytestmark",[])]

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

    if "with_system_archive_from_2p4" in markers:
        add_archive_system_from_2p4()
        assert len(backup_list()["archives"]) == 1


def teardown_function(function):

    assert tmp_backup_directory_is_empty()

    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

    markers = [m.name for m in function.__dict__.get("pytestmark",[])]

    if "clean_opt_dir" in markers:
        shutil.rmtree("/opt/test_backup_output_directory")


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

#
# Helpers                                                                    #
#

def app_is_installed(app):

    # These are files we know should be installed by the app
    app_files = []
    app_files.append("/etc/nginx/conf.d/%s.d/%s.conf" % (maindomain, app))
    app_files.append("/var/www/%s/index.html" % app)
    app_files.append("/etc/importantfile")

    return _is_installed(app) and all(os.path.exists(f) for f in app_files)


def backup_test_dependencies_are_met():

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

    points_to_umount = [line.split(" ")[2]
                        for line in mount_lines
                        if len(line) >= 3
                        and line.split(" ")[2].startswith("/home/yunohost.backup/tmp")]

    for point in reversed(points_to_umount):
        os.system("umount %s" % point)

    for f in os.listdir('/home/yunohost.backup/tmp/'):
        shutil.rmtree("/home/yunohost.backup/tmp/%s" % f)

    shutil.rmtree("/home/yunohost.backup/tmp/")


def reset_ssowat_conf():

    # Make sure we have a ssowat
    os.system("mkdir -p /etc/ssowat/")
    app_ssowatconf()


def delete_all_backups():

    for archive in backup_list()["archives"]:
        backup_delete(archive)


def uninstall_test_apps_if_needed():

    if _is_installed("backup_legacy_app"):
        app_remove("backup_legacy_app")

    if _is_installed("backup_recommended_app"):
        app_remove("backup_recommended_app")

    if _is_installed("wordpress"):
        app_remove("wordpress")


def install_app(app, path, additionnal_args=""):

    app_install("./tests/apps/%s" % app,
                args="domain=%s&path=%s%s" % (maindomain, path,
                                              additionnal_args), force=True)


def add_archive_wordpress_from_2p4():

    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.info.json \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.info.json")

    os.system("cp ./tests/apps/backup_wordpress_from_2p4/backup.tar.gz \
               /home/yunohost.backup/archives/backup_wordpress_from_2p4.tar.gz")


def add_archive_system_from_2p4():

    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system("cp ./tests/apps/backup_system_from_2p4/backup.info.json \
               /home/yunohost.backup/archives/backup_system_from_2p4.info.json")

    os.system("cp ./tests/apps/backup_system_from_2p4/backup.tar.gz \
               /home/yunohost.backup/archives/backup_system_from_2p4.tar.gz")

#
# System backup                                                              #
#


def test_backup_only_ldap():

    # Create the backup
    backup_create(system=["conf_ldap"], apps=None)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["system"].keys()) == 1
    assert "conf_ldap" in archives_info["system"].keys()


def test_backup_system_part_that_does_not_exists(mocker):

    mocker.spy(m18n, "n")

    # Create the backup
    with pytest.raises(YunohostError):
        backup_create(system=["yolol"], apps=None)

    m18n.n.assert_any_call('backup_hook_unknown', hook="yolol")
    m18n.n.assert_any_call('backup_nothings_done')

#
# System backup and restore                                                  #
#


def test_backup_and_restore_all_sys():

    # Create the backup
    backup_create(system=[], apps=None)

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
    backup_restore(name=archives[0], force=True,
                   system=[], apps=None)

    # Check ssowat conf is back
    assert os.path.exists("/etc/ssowat/conf.json")


#
# System restore from 2.4                                                    #
#

@pytest.mark.with_system_archive_from_2p4
def test_restore_system_from_Ynh2p4(monkeypatch, mocker):

    # Backup current system
    backup_create(system=[], apps=None)
    archives = backup_list()["archives"]
    assert len(archives) == 2

    # Restore system archive from 2.4
    try:
        backup_restore(name=backup_list()["archives"][1],
                       system=[],
                       apps=None,
                       force=True)
    finally:
        # Restore system as it was
        backup_restore(name=backup_list()["archives"][0],
                       system=[],
                       apps=None,
                       force=True)

#
# App backup                                                                 #
#


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

    with pytest.raises(YunohostError):
        backup_create(system=None, apps=["backup_recommended_app"])

    m18n.n.assert_any_call('backup_app_failed', app='backup_recommended_app')


@pytest.mark.with_backup_recommended_app_installed
def test_backup_not_enough_free_space(monkeypatch, mocker):

    def custom_disk_usage(path):
        return 99999999999999999

    def custom_free_space_in_directory(dirpath):
        return 0

    monkeypatch.setattr("yunohost.backup.disk_usage", custom_disk_usage)
    monkeypatch.setattr("yunohost.backup.free_space_in_directory",
                        custom_free_space_in_directory)

    mocker.spy(m18n, "n")

    with pytest.raises(YunohostError):
        backup_create(system=None, apps=["backup_recommended_app"])

    m18n.n.assert_any_call('not_enough_disk_space', path=ANY)


def test_backup_app_not_installed(mocker):

    assert not _is_installed("wordpress")

    mocker.spy(m18n, "n")

    with pytest.raises(YunohostError):
        backup_create(system=None, apps=["wordpress"])

    m18n.n.assert_any_call("unbackup_app", app="wordpress")
    m18n.n.assert_any_call('backup_nothings_done')


@pytest.mark.with_backup_recommended_app_installed
def test_backup_app_with_no_backup_script(mocker):

    backup_script = "/etc/yunohost/apps/backup_recommended_app/scripts/backup"
    os.system("rm %s" % backup_script)
    assert not os.path.exists(backup_script)

    mocker.spy(m18n, "n")

    with pytest.raises(YunohostError):
        backup_create(system=None, apps=["backup_recommended_app"])

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

    backup_create(system=None, apps=["backup_recommended_app"])

    m18n.n.assert_any_call("backup_with_no_restore_script_for_app", app="backup_recommended_app")


@pytest.mark.clean_opt_dir
def test_backup_with_different_output_directory():

    # Create the backup
    backup_create(system=["conf_ssh"], apps=None,
                  output_directory="/opt/test_backup_output_directory",
                  name="backup")

    assert os.path.exists("/opt/test_backup_output_directory/backup.tar.gz")

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["system"].keys()) == 1
    assert "conf_ssh" in archives_info["system"].keys()


@pytest.mark.clean_opt_dir
def test_backup_with_no_compress():
    # Create the backup
    backup_create(system=["conf_nginx"], apps=None,
                  output_directory="/opt/test_backup_output_directory",
                  no_compress=True,
                  name="backup")

    assert os.path.exists("/opt/test_backup_output_directory/info.json")


#
# App restore                                                                #
#

@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_wordpress_from_Ynh2p4():

    backup_restore(system=None, name=backup_list()["archives"][0],
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

    with pytest.raises(YunohostError):
        backup_restore(system=None, name=backup_list()["archives"][0],
                       apps=["wordpress"])

    m18n.n.assert_any_call('restore_app_failed', app='wordpress')
    m18n.n.assert_any_call('restore_nothings_done')
    assert not _is_installed("wordpress")


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_not_enough_free_space(monkeypatch, mocker):

    def custom_free_space_in_directory(dirpath):
        return 0

    monkeypatch.setattr("yunohost.backup.free_space_in_directory",
                        custom_free_space_in_directory)
    mocker.spy(m18n, "n")

    assert not _is_installed("wordpress")

    with pytest.raises(YunohostError):
        backup_restore(system=None, name=backup_list()["archives"][0],
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

    with pytest.raises(YunohostError):
        backup_restore(system=None, name=backup_list()["archives"][0],
                       apps=["yoloswag"])

    m18n.n.assert_any_call('backup_archive_app_not_found', app="yoloswag")
    assert not _is_installed("wordpress")
    assert not _is_installed("yoloswag")


@pytest.mark.with_wordpress_archive_from_2p4
def test_restore_app_already_installed(mocker):

    assert not _is_installed("wordpress")

    backup_restore(system=None, name=backup_list()["archives"][0],
                   apps=["wordpress"])

    assert _is_installed("wordpress")

    mocker.spy(m18n, "n")
    with pytest.raises(YunohostError):
        backup_restore(system=None, name=backup_list()["archives"][0],
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
    backup_create(system=None, apps=[app])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["system"] == {}
    assert len(archives_info["apps"].keys()) == 1
    assert app in archives_info["apps"].keys()

    # Uninstall the app
    app_remove(app)
    assert not app_is_installed(app)
    assert app not in user_permission_list()['permissions']

    # Restore the app
    backup_restore(system=None, name=archives[0],
                   apps=[app])

    assert app_is_installed(app)

    # Check permission
    per_list = user_permission_list()['permissions']
    assert app in per_list
    assert "main" in per_list[app]

#
# Some edge cases                                                            #
#


def test_restore_archive_with_no_json(mocker):

    # Create a backup with no info.json associated
    os.system("touch /tmp/afile")
    os.system("tar -czvf /home/yunohost.backup/archives/badbackup.tar.gz /tmp/afile")

    assert "badbackup" in backup_list()["archives"]

    mocker.spy(m18n, "n")
    with pytest.raises(YunohostError):
        backup_restore(name="badbackup", force=True)
    m18n.n.assert_any_call('backup_invalid_archive')


def test_backup_binds_are_readonly(monkeypatch):

    def custom_mount_and_backup(self, backup_manager):
        self.manager = backup_manager
        self._organize_files()

        confssh = os.path.join(self.work_dir, "conf/ssh")
        output = subprocess.check_output("touch %s/test 2>&1 || true" % confssh,
                                         shell=True, env={'LANG': 'en_US.UTF-8'})

        assert "Read-only file system" in output

        if not _recursive_umount(self.work_dir):
            raise Exception("Backup cleaning failed !")

        self.clean()

    monkeypatch.setattr("yunohost.backup.BackupMethod.mount_and_backup",
                        custom_mount_and_backup)

    # Create the backup
    backup_create(system=[])
