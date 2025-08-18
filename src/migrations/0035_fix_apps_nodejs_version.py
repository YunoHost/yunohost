import os
from logging import getLogger

from ..app import app_setting

from ..tools import Migration
from ..utils.process import check_output
from ..utils.app_utils import _installed_apps, _get_app_settings

logger = getLogger("yunohost.migration")


def get_installed_nodejs_versions():
    n = "/usr/share/yunohost/helpers.v2.1.d/vendor/n/n"
    N_INSTALL_DIR = "/opt/node_n"
    installed_versions_raw = check_output(f"{n} ls", env={"N_PREFIX": N_INSTALL_DIR})
    installed_versions = [version.split("/")[-1] for version in installed_versions_raw.strip().split("\n")]
    return installed_versions


def patch_app(app, base_dir=""):

    settings = _get_app_settings(app)
    nodejs_version = settings.get("nodejs_version")
    if nodejs_version is None or "." in str(nodejs_version):
        return

    nodejs_version = str(nodejs_version)

    installed_versions = get_installed_nodejs_versions()
    matching_versions = [
        v
        for v in installed_versions
        if v == nodejs_version or v.startswith(nodejs_version + ".")
    ]
    if not matching_versions:
        logger.warning(f"Uhoh, no matching version found among {installed_versions} for nodejs {nodejs_version} for app {app} ?")

    sorted_versions = sorted(matching_versions, key=lambda s: list(map(int, s.split("."))))
    actual_version = sorted_versions[-1]

    logger.debug(f"Updating nodejs version setting for {app} from {nodejs_version} to {actual_version}")
    app_setting(app, "nodejs_version", actual_version)

    service_files_for_this_app = check_output(f'grep -lr "^User={app}$" "{base_dir}/etc/systemd/system"').strip().split("\n")
    service_files_manually_modified = []
    for file in service_files_for_this_app:
        cleaned_file = file.replace(base_dir, "") if base_dir else file
        setting_name = f"checksum_{cleaned_file.replace('/', '_')}"
        md5 = check_output(f"md5sum '{file}'").strip().split()[0]
        if md5 != settings.get(setting_name):
            service_files_manually_modified.append(cleaned_file)

    logger.debug(f"Patching nodejs version for app {app} in {', '.join(service_files_for_this_app)} ...")
    old_node_path = f"/opt/node_n/n/versions/node/{nodejs_version}/bin"
    new_node_path = f"/opt/node_n/n/versions/node/{actual_version}/bin"
    os.system(f"sed -i 's@{old_node_path}@{new_node_path}@g' {' '.join(service_files_for_this_app)}")
    for file in service_files_for_this_app:
        cleaned_file = file.replace(base_dir, "") if base_dir else file
        if cleaned_file in service_files_manually_modified:
            continue
        setting_name = f"checksum_{cleaned_file.replace('/', '_')}"
        md5 = check_output(f"md5sum '{file}'").strip().split()[0]
        app_setting(app, setting_name, md5)


class MyMigration(Migration):
    introduced_in_version = "12.1"
    dependencies = []

    def run(self, *args):
        for app in _installed_apps():
            patch_app(app)

    def run_before_app_restore(self, app, app_backup_in_archive):
        return patch_app(app, base_dir=app_backup_in_archive)
