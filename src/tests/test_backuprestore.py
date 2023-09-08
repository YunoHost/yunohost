import pytest
import os
import shutil
import subprocess
from mock import patch

from .conftest import message, raiseYunohostError, get_test_apps_dir

from moulinette.utils.text import random_ascii

from yunohost.app import app_install, app_remove, app_ssowatconf
from yunohost.app import _is_installed
from yunohost.backup import (
    backup_create,
    backup_restore,
    backup_list,
    backup_info,
    backup_delete,
    _recursive_umount,
)
from yunohost.domain import _get_maindomain, domain_list, domain_add, domain_remove
from yunohost.user import user_create, user_list, user_delete
from yunohost.permission import user_permission_list
from yunohost.tests.test_permission import (
    check_LDAP_db_integrity,
    check_permission_for_apps,
)
from yunohost.hook import CUSTOM_HOOK_FOLDER

# Get main domain
maindomain = ""


def setup_function(function):
    global maindomain
    maindomain = _get_maindomain()

    assert backup_test_dependencies_are_met()

    clean_tmp_backup_directory()
    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

    assert len(backup_list()["archives"]) == 0

    markers = {
        m.name: {"args": m.args, "kwargs": m.kwargs}
        for m in function.__dict__.get("pytestmark", [])
    }

    if "with_wordpress_archive_from_11p2" in markers:
        add_archive_wordpress_from_11p2()
        assert len(backup_list()["archives"]) == 1

    if "with_legacy_app_installed" in markers:
        assert not app_is_installed("legacy_app")
        install_app("legacy_app_ynh", "/yolo", "&is_public=true")
        assert app_is_installed("legacy_app")

    if "with_backup_recommended_app_installed" in markers:
        assert not app_is_installed("backup_recommended_app")
        install_app(
            "backup_recommended_app_ynh", "/yolo", "&helper_to_test=ynh_restore_file"
        )
        assert app_is_installed("backup_recommended_app")

    if "with_backup_recommended_app_installed_with_ynh_restore" in markers:
        assert not app_is_installed("backup_recommended_app")
        install_app(
            "backup_recommended_app_ynh", "/yolo", "&helper_to_test=ynh_restore"
        )
        assert app_is_installed("backup_recommended_app")

    if "with_system_archive_from11p2" in markers:
        add_archive_system_from_11p2()
        assert len(backup_list()["archives"]) == 1

    if "with_permission_app_installed" in markers:
        assert not app_is_installed("permissions_app")
        user_create("alice", maindomain, "test123Ynh", fullname="Alice White")
        with patch.object(os, "isatty", return_value=False):
            install_app("permissions_app_ynh", "/urlpermissionapp" "&admin=alice")
        assert app_is_installed("permissions_app")

    if "with_custom_domain" in markers:
        domain = markers["with_custom_domain"]["args"][0]
        if domain not in domain_list()["domains"]:
            domain_add(domain)


def teardown_function(function):
    assert tmp_backup_directory_is_empty()

    reset_ssowat_conf()
    delete_all_backups()
    uninstall_test_apps_if_needed()

    markers = {
        m.name: {"args": m.args, "kwargs": m.kwargs}
        for m in function.__dict__.get("pytestmark", [])
    }

    if "clean_opt_dir" in markers:
        shutil.rmtree("/opt/test_backup_output_directory")

    if "alice" in user_list()["users"]:
        user_delete("alice")

    if "with_custom_domain" in markers:
        domain = markers["with_custom_domain"]["args"][0]
        if domain != maindomain:
            domain_remove(domain)


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
    if app == "permissions_app":
        return _is_installed(app)

    # These are files we know should be installed by the app
    app_files = []
    app_files.append("/etc/nginx/conf.d/{}.d/{}.conf".format(maindomain, app))
    app_files.append("/var/www/%s/index.html" % app)
    app_files.append("/etc/importantfile")

    return _is_installed(app) and all(os.path.exists(f) for f in app_files)


def backup_test_dependencies_are_met():
    # Dummy test apps (or backup archives)
    assert os.path.exists(
        os.path.join(get_test_apps_dir(), "backup_wordpress_from_11p2")
    )
    assert os.path.exists(os.path.join(get_test_apps_dir(), "legacy_app_ynh"))
    assert os.path.exists(
        os.path.join(get_test_apps_dir(), "backup_recommended_app_ynh")
    )

    return True


def tmp_backup_directory_is_empty():
    if not os.path.exists("/home/yunohost.backup/tmp/"):
        return True
    else:
        return len(os.listdir("/home/yunohost.backup/tmp/")) == 0


def clean_tmp_backup_directory():
    if tmp_backup_directory_is_empty():
        return

    mount_lines = subprocess.check_output("mount").decode().split("\n")

    points_to_umount = [
        line.split(" ")[2]
        for line in mount_lines
        if len(line) >= 3 and line.split(" ")[2].startswith("/home/yunohost.backup/tmp")
    ]

    for point in reversed(points_to_umount):
        os.system("umount %s" % point)

    for f in os.listdir("/home/yunohost.backup/tmp/"):
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
    for app in ["legacy_app", "backup_recommended_app", "wordpress", "permissions_app"]:
        if _is_installed(app):
            app_remove(app)


def install_app(app, path, additionnal_args=""):
    app_install(
        os.path.join(get_test_apps_dir(), app),
        args="domain={}&path={}{}".format(maindomain, path, additionnal_args),
        force=True,
    )


def add_archive_wordpress_from_11p2():
    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system(
        "cp "
        + os.path.join(get_test_apps_dir(), "backup_wordpress_from_11p2/backup.tar")
        + " /home/yunohost.backup/archives/backup_wordpress_from_11p2.tar"
    )


def add_archive_system_from_11p2():
    os.system("mkdir -p /home/yunohost.backup/archives")

    os.system(
        "cp "
        + os.path.join(get_test_apps_dir(), "backup_system_from_11p2/backup.tar")
        + " /home/yunohost.backup/archives/backup_system_from_11p2.tar"
    )


#
# System backup                                                              #
#


def test_backup_only_ldap():
    # Create the backup
    name = random_ascii(8)
    with message("backup_created", name=name):
        backup_create(name=name, system=["conf_ldap"], apps=None)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["system"].keys()) == 1
    assert "conf_ldap" in archives_info["system"].keys()


def test_backup_system_part_that_does_not_exists(mocker):
    # Create the backup
    with message("backup_hook_unknown", hook="doesnt_exist"):
        with raiseYunohostError(mocker, "backup_nothings_done"):
            backup_create(system=["doesnt_exist"], apps=None)


#
# System backup and restore                                                  #
#


def test_backup_and_restore_all_sys():
    name = random_ascii(8)
    # Create the backup
    with message("backup_created", name=name):
        backup_create(name=name, system=[], apps=None)

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["system"].keys()) == len(
        os.listdir("/usr/share/yunohost/hooks/backup/")
    )

    # Remove ssowat conf
    assert os.path.exists("/etc/ssowat/conf.json")
    os.system("rm -rf /etc/ssowat/")
    assert not os.path.exists("/etc/ssowat/conf.json")

    # Restore the backup
    with message("restore_complete"):
        backup_restore(name=archives[0], force=True, system=[], apps=None)

    # Check ssowat conf is back
    assert os.path.exists("/etc/ssowat/conf.json")


#
# System restore from 11.2                                                    #
#


@pytest.mark.with_system_archive_from_11p2
def test_restore_system_from_Ynh11p2(monkeypatch):
    name = random_ascii(8)
    # Backup current system
    with message("backup_created", name=name):
        backup_create(name=name, system=[], apps=None)
    archives = backup_list()["archives"]
    assert len(archives) == 2

    # Restore system archive from 11.2
    try:
        with message("restore_complete"):
            backup_restore(
                name=backup_list()["archives"][1], system=[], apps=None, force=True
            )
    finally:
        # Restore system as it was
        backup_restore(
            name=backup_list()["archives"][0], system=[], apps=None, force=True
        )


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

    with message("backup_app_failed", app="backup_recommended_app"):
        with raiseYunohostError(mocker, "backup_nothings_done"):
            backup_create(system=None, apps=["backup_recommended_app"])


@pytest.mark.with_backup_recommended_app_installed
def test_backup_not_enough_free_space(monkeypatch, mocker):
    def custom_space_used_by_directory(path, *args, **kwargs):
        return 99999999999999999

    def custom_free_space_in_directory(dirpath):
        return 0

    monkeypatch.setattr(
        "yunohost.backup.space_used_by_directory", custom_space_used_by_directory
    )
    monkeypatch.setattr(
        "yunohost.backup.free_space_in_directory", custom_free_space_in_directory
    )

    with raiseYunohostError(mocker, "not_enough_disk_space"):
        backup_create(system=None, apps=["backup_recommended_app"])


def test_backup_app_not_installed(mocker):
    assert not _is_installed("wordpress")

    with message("unbackup_app", app="wordpress"):
        with raiseYunohostError(mocker, "backup_nothings_done"):
            backup_create(system=None, apps=["wordpress"])


@pytest.mark.with_backup_recommended_app_installed
def test_backup_app_with_no_backup_script(mocker):
    backup_script = "/etc/yunohost/apps/backup_recommended_app/scripts/backup"
    os.system("rm %s" % backup_script)
    assert not os.path.exists(backup_script)

    with message(
        "backup_with_no_backup_script_for_app", app="backup_recommended_app"
    ):
        with raiseYunohostError(mocker, "backup_nothings_done"):
            backup_create(system=None, apps=["backup_recommended_app"])


@pytest.mark.with_backup_recommended_app_installed
def test_backup_app_with_no_restore_script():
    restore_script = "/etc/yunohost/apps/backup_recommended_app/scripts/restore"
    os.system("rm %s" % restore_script)
    assert not os.path.exists(restore_script)

    # Backuping an app with no restore script will only display a warning to the
    # user...

    with message(
        "backup_with_no_restore_script_for_app", app="backup_recommended_app"
    ):
        backup_create(system=None, apps=["backup_recommended_app"])


@pytest.mark.clean_opt_dir
def test_backup_with_different_output_directory():
    name = random_ascii(8)
    # Create the backup
    with message("backup_created", name=name):
        backup_create(
            system=["conf_ynh_settings"],
            apps=None,
            output_directory="/opt/test_backup_output_directory",
            name=name,
        )

    assert os.path.exists(f"/opt/test_backup_output_directory/{name}.tar")

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["apps"] == {}
    assert len(archives_info["system"].keys()) == 1
    assert "conf_ynh_settings" in archives_info["system"].keys()


@pytest.mark.clean_opt_dir
def test_backup_using_copy_method():
    # Create the backup
    name = random_ascii(8)
    with message("backup_created", name=name):
        backup_create(
            system=["conf_ynh_settings"],
            apps=None,
            output_directory="/opt/test_backup_output_directory",
            methods=["copy"],
            name=name,
        )

    assert os.path.exists("/opt/test_backup_output_directory/info.json")


#
# App restore                                                                #
#

@pytest.mark.with_wordpress_archive_from_11p2
@pytest.mark.with_custom_domain("yolo.test")
def test_restore_app_wordpress_from_Ynh11p2():
    with message("restore_complete"):
        backup_restore(
            system=None, name=backup_list()["archives"][0], apps=["wordpress"]
        )


@pytest.mark.with_wordpress_archive_from_11p2
@pytest.mark.with_custom_domain("yolo.test")
def test_restore_app_script_failure_handling(monkeypatch, mocker):
    def custom_hook_exec(name, *args, **kwargs):
        if os.path.basename(name).startswith("restore"):
            monkeypatch.undo()
            return (1, None)

    monkeypatch.setattr("yunohost.hook.hook_exec", custom_hook_exec)

    assert not _is_installed("wordpress")

    with message("app_restore_script_failed"):
        with raiseYunohostError(mocker, "restore_nothings_done"):
            backup_restore(
                system=None, name=backup_list()["archives"][0], apps=["wordpress"]
            )

    assert not _is_installed("wordpress")


@pytest.mark.with_wordpress_archive_from_11p2
def test_restore_app_not_enough_free_space(monkeypatch, mocker):
    def custom_free_space_in_directory(dirpath):
        return 0

    monkeypatch.setattr(
        "yunohost.backup.free_space_in_directory", custom_free_space_in_directory
    )

    assert not _is_installed("wordpress")

    with raiseYunohostError(mocker, "restore_not_enough_disk_space"):
        backup_restore(
            system=None, name=backup_list()["archives"][0], apps=["wordpress"]
        )

    assert not _is_installed("wordpress")


@pytest.mark.with_wordpress_archive_from_11p2
def test_restore_app_not_in_backup(mocker):
    assert not _is_installed("wordpress")
    assert not _is_installed("yoloswag")

    with message("backup_archive_app_not_found", app="yoloswag"):
        with raiseYunohostError(mocker, "restore_nothings_done"):
            backup_restore(
                system=None, name=backup_list()["archives"][0], apps=["yoloswag"]
            )

    assert not _is_installed("wordpress")
    assert not _is_installed("yoloswag")


@pytest.mark.with_wordpress_archive_from_11p2
@pytest.mark.with_custom_domain("yolo.test")
def test_restore_app_already_installed(mocker):
    assert not _is_installed("wordpress")

    with message("restore_complete"):
        backup_restore(
            system=None, name=backup_list()["archives"][0], apps=["wordpress"]
        )

    assert _is_installed("wordpress")

    with raiseYunohostError(mocker, "restore_already_installed_apps"):
        backup_restore(
            system=None, name=backup_list()["archives"][0], apps=["wordpress"]
        )

    assert _is_installed("wordpress")


@pytest.mark.with_legacy_app_installed
def test_backup_and_restore_legacy_app():
    _test_backup_and_restore_app("legacy_app")


@pytest.mark.with_backup_recommended_app_installed
def test_backup_and_restore_recommended_app():
    _test_backup_and_restore_app("backup_recommended_app")


@pytest.mark.with_backup_recommended_app_installed_with_ynh_restore
def test_backup_and_restore_with_ynh_restore():
    _test_backup_and_restore_app("backup_recommended_app")


@pytest.mark.with_permission_app_installed
def test_backup_and_restore_permission_app():
    res = user_permission_list(full=True)["permissions"]
    assert "permissions_app.main" in res
    assert "permissions_app.admin" in res
    assert "permissions_app.dev" in res
    assert res["permissions_app.main"]["url"] == "/"
    assert res["permissions_app.admin"]["url"] == "/admin"
    assert res["permissions_app.dev"]["url"] == "/dev"

    assert "visitors" in res["permissions_app.main"]["allowed"]
    assert "all_users" in res["permissions_app.main"]["allowed"]
    assert res["permissions_app.admin"]["allowed"] == ["alice"]
    assert res["permissions_app.dev"]["allowed"] == []

    _test_backup_and_restore_app("permissions_app")

    res = user_permission_list(full=True)["permissions"]
    assert "permissions_app.main" in res
    assert "permissions_app.admin" in res
    assert "permissions_app.dev" in res
    assert res["permissions_app.main"]["url"] == "/"
    assert res["permissions_app.admin"]["url"] == "/admin"
    assert res["permissions_app.dev"]["url"] == "/dev"

    assert "visitors" in res["permissions_app.main"]["allowed"]
    assert "all_users" in res["permissions_app.main"]["allowed"]
    assert res["permissions_app.admin"]["allowed"] == ["alice"]
    assert res["permissions_app.dev"]["allowed"] == []


def _test_backup_and_restore_app(app):
    # Create a backup of this app
    name = random_ascii(8)
    with message("backup_created", name=name):
        backup_create(name=name, system=None, apps=[app])

    archives = backup_list()["archives"]
    assert len(archives) == 1

    archives_info = backup_info(archives[0], with_details=True)
    assert archives_info["system"] == {}
    assert len(archives_info["apps"].keys()) == 1
    assert app in archives_info["apps"].keys()

    # Uninstall the app
    app_remove(app)
    assert not app_is_installed(app)
    assert app + ".main" not in user_permission_list()["permissions"]

    # Restore the app
    with message("restore_complete"):
        backup_restore(system=None, name=archives[0], apps=[app])

    assert app_is_installed(app)

    # Check permission
    per_list = user_permission_list()["permissions"]
    assert app + ".main" in per_list


#
# Some edge cases                                                            #
#


def test_restore_archive_with_no_json(mocker):
    # Create a backup with no info.json associated
    os.system("touch /tmp/afile")
    os.system("tar -cvf /home/yunohost.backup/archives/badbackup.tar /tmp/afile")

    assert "badbackup" in backup_list()["archives"]

    with raiseYunohostError(mocker, "backup_archive_cant_retrieve_info_json"):
        backup_restore(name="badbackup", force=True)


@pytest.mark.with_wordpress_archive_from_11p2
def test_restore_archive_with_bad_archive(mocker):
    # Break the archive
    os.system(
        "head -n 1000 /home/yunohost.backup/archives/backup_wordpress_from_11p2.tar > /home/yunohost.backup/archives/backup_wordpress_from_11p2_bad.tar"
    )

    assert "backup_wordpress_from_11p2_bad" in backup_list()["archives"]

    with raiseYunohostError(mocker, "backup_archive_corrupted"):
        backup_restore(name="backup_wordpress_from_11p2_bad", force=True)

    clean_tmp_backup_directory()


def test_restore_archive_with_custom_hook():
    custom_restore_hook_folder = os.path.join(CUSTOM_HOOK_FOLDER, "restore")
    os.system("touch %s/99-yolo" % custom_restore_hook_folder)

    # Backup with custom hook system
    name = random_ascii(8)
    with message("backup_created", name=name):
        backup_create(name=name, system=[], apps=None)
    archives = backup_list()["archives"]
    assert len(archives) == 1

    # Restore system with custom hook
    with message("restore_complete"):
        backup_restore(
            name=backup_list()["archives"][0], system=[], apps=None, force=True
        )

    os.system("rm %s/99-yolo" % custom_restore_hook_folder)


def test_backup_binds_are_readonly(monkeypatch):
    def custom_mount_and_backup(self):
        self._organize_files()

        conf = os.path.join(self.work_dir, "conf/ynh/dkim")
        output = subprocess.check_output(
            "touch %s/test 2>&1 || true" % conf,
            shell=True,
            env={"LANG": "en_US.UTF-8"},
        )
        output = output.decode()

        assert "Read-only file system" in output

        if not _recursive_umount(self.work_dir):
            raise Exception("Backup cleaning failed !")

        self.clean()

    monkeypatch.setattr(
        "yunohost.backup.BackupMethod.mount_and_backup", custom_mount_and_backup
    )

    # Create the backup
    name = random_ascii(8)
    with message("backup_created", name=name):
        backup_create(name=name, system=[])
