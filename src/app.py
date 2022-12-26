#
# Copyright (c) 2022 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import glob
import os
import toml
import json
import shutil
import yaml
import time
import re
import subprocess
import tempfile
import copy
from collections import OrderedDict
from typing import List, Tuple, Dict, Any, Iterator
from packaging import version

from moulinette import Moulinette, m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import run_commands, check_output
from moulinette.utils.filesystem import (
    read_file,
    read_json,
    read_toml,
    read_yaml,
    write_to_file,
    write_to_json,
    cp,
    rm,
    chown,
    chmod,
)

from yunohost.utils.config import (
    ConfigPanel,
    ask_questions_and_parse_answers,
    DomainQuestion,
    PathQuestion,
    hydrate_questions_with_choices,
)
from yunohost.utils.i18n import _value_for_locale
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.system import (
    free_space_in_directory,
    dpkg_is_broken,
    get_ynh_package_version,
    system_arch,
    human_to_binary,
    binary_to_human,
    ram_available,
)
from yunohost.log import is_unit_operation, OperationLogger
from yunohost.app_catalog import (  # noqa
    app_catalog,
    app_search,
    _load_apps_catalog,
)

logger = getActionLogger("yunohost.app")

APPS_SETTING_PATH = "/etc/yunohost/apps/"
APP_TMP_WORKDIRS = "/var/cache/yunohost/app_tmp_work_dirs"

re_app_instance_name = re.compile(
    r"^(?P<appid>[\w-]+?)(__(?P<appinstancenb>[1-9][0-9]*))?$"
)

APP_REPO_URL = re.compile(
    r"^https://[a-zA-Z0-9-_.]+/[a-zA-Z0-9-_./~]+/[a-zA-Z0-9-_.]+_ynh(/?(-/)?tree/[a-zA-Z0-9-_.]+)?(\.git)?/?$"
)

APP_FILES_TO_COPY = [
    "manifest.json",
    "manifest.toml",
    "actions.json",
    "actions.toml",
    "config_panel.toml",
    "scripts",
    "conf",
    "hooks",
    "doc",
]


def app_list(full=False, upgradable=False):
    """
    List installed apps
    """

    out = []
    for app_id in sorted(_installed_apps()):
        try:
            app_info_dict = app_info(app_id, full=full, upgradable=upgradable)
        except Exception as e:
            logger.error(f"Failed to read info for {app_id} : {e}")
            continue
        app_info_dict["id"] = app_id
        if upgradable and app_info_dict.get("upgradable") != "yes":
            continue
        out.append(app_info_dict)

    return {"apps": out}


def app_info(app, full=False, upgradable=False):
    """
    Get info for a specific app
    """
    from yunohost.permission import user_permission_list
    from yunohost.domain import domain_config_get

    _assert_is_installed(app)

    setting_path = os.path.join(APPS_SETTING_PATH, app)
    local_manifest = _get_manifest_of_app(setting_path)
    permissions = user_permission_list(full=True, absolute_urls=True, apps=[app])[
        "permissions"
    ]

    settings = _get_app_settings(app)

    ret = {
        "description": _value_for_locale(local_manifest["description"]),
        "name": permissions.get(app + ".main", {}).get("label", local_manifest["name"]),
        "version": local_manifest.get("version", "-"),
    }

    if "domain" in settings and "path" in settings:
        ret["domain_path"] = settings["domain"] + settings["path"]

    if not upgradable and not full:
        return ret

    absolute_app_name, _ = _parse_app_instance_name(app)
    from_catalog = _load_apps_catalog()["apps"].get(absolute_app_name, {})

    ret["upgradable"] = _app_upgradable({**ret, "from_catalog": from_catalog})

    if ret["upgradable"] == "yes":
        ret["current_version"] = ret.get("version", "?")
        ret["new_version"] = from_catalog.get("manifest", {}).get("version", "?")

        if ret["current_version"] == ret["new_version"]:
            current_revision = settings.get("current_revision", "?")[:7]
            new_revision = from_catalog.get("git", {}).get("revision", "?")[:7]

            ret["current_version"] = f" ({current_revision})"
            ret["new_version"] = f" ({new_revision})"

    ret["settings"] = settings

    if not full:
        return ret

    ret["setting_path"] = setting_path
    ret["manifest"] = local_manifest

    # FIXME: maybe this is not needed ? default ask questions are
    # already set during the _get_manifest_of_app earlier ?
    ret["manifest"]["install"] = _set_default_ask_questions(
        ret["manifest"].get("install", {})
    )

    ret["from_catalog"] = from_catalog

    # Hydrate app notifications and doc
    for pagename, content_per_lang in ret["manifest"]["doc"].items():
        for lang, content in content_per_lang.items():
            ret["manifest"]["doc"][pagename][lang] = _hydrate_app_template(
                content, settings
            )
    for step, notifications in ret["manifest"]["notifications"].items():
        for name, content_per_lang in notifications.items():
            for lang, content in content_per_lang.items():
                notifications[name][lang] = _hydrate_app_template(content, settings)

    ret["is_webapp"] = "domain" in settings and "path" in settings

    if ret["is_webapp"]:
        ret["is_default"] = (
            domain_config_get(settings["domain"], "feature.app.default_app") == app
        )

    ret["supports_change_url"] = os.path.exists(
        os.path.join(setting_path, "scripts", "change_url")
    )
    ret["supports_backup_restore"] = os.path.exists(
        os.path.join(setting_path, "scripts", "backup")
    ) and os.path.exists(os.path.join(setting_path, "scripts", "restore"))
    ret["supports_multi_instance"] = local_manifest.get("integration", {}).get(
        "multi_instance", False
    )
    ret["supports_config_panel"] = os.path.exists(
        os.path.join(setting_path, "config_panel.toml")
    )

    ret["permissions"] = permissions
    ret["label"] = permissions.get(app + ".main", {}).get("label")

    if not ret["label"]:
        logger.warning(f"Failed to get label for app {app} ?")
        ret["label"] = local_manifest["name"]
    return ret


def _app_upgradable(app_infos):

    # Determine upgradability

    app_in_catalog = app_infos.get("from_catalog")
    installed_version = version.parse(app_infos.get("version", "0~ynh0"))
    version_in_catalog = version.parse(
        app_infos.get("from_catalog", {}).get("manifest", {}).get("version", "0~ynh0")
    )

    if not app_in_catalog:
        return "url_required"

    # Do not advertise upgrades for bad-quality apps
    level = app_in_catalog.get("level", -1)
    if (
        not (isinstance(level, int) and level >= 5)
        or app_in_catalog.get("state") != "working"
    ):
        return "bad_quality"

    # If the app uses the standard version scheme, use it to determine
    # upgradability
    if "~ynh" in str(installed_version) and "~ynh" in str(version_in_catalog):
        if installed_version < version_in_catalog:
            return "yes"
        else:
            return "no"

    # Legacy stuff for app with old / non-standard version numbers...

    # In case there is neither update_time nor install_time, we assume the app can/has to be upgraded
    if not app_infos["from_catalog"].get("lastUpdate") or not app_infos[
        "from_catalog"
    ].get("git"):
        return "url_required"

    settings = app_infos["settings"]
    local_update_time = settings.get("update_time", settings.get("install_time", 0))
    if app_infos["from_catalog"]["lastUpdate"] > local_update_time:
        return "yes"
    else:
        return "no"


def app_map(app=None, raw=False, user=None):
    """
    Returns a map of url <-> app id such as :

    {
       "domain.tld/foo": "foo__2",
       "domain.tld/mail: "rainloop",
       "other.tld/": "bar",
       "sub.other.tld/pwet": "pwet",
    }

    When using "raw", the structure changes to :

    {
        "domain.tld": {
            "/foo": {"label": "App foo", "id": "foo__2"},
            "/mail": {"label": "Rainloop", "id: "rainloop"},
        },
        "other.tld": {
            "/": {"label": "Bar", "id": "bar"},
        },
        "sub.other.tld": {
            "/pwet": {"label": "Pwet", "id": "pwet"}
        }
    }
    """

    from yunohost.permission import user_permission_list

    apps = []
    result = {}

    if app is not None:
        if not _is_installed(app):
            raise YunohostValidationError(
                "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
            )
        apps = [
            app,
        ]
    else:
        apps = _installed_apps()

    permissions = user_permission_list(full=True, absolute_urls=True, apps=apps)[
        "permissions"
    ]
    for app in apps:
        app_settings = _get_app_settings(app)
        if not app_settings:
            continue
        if "domain" not in app_settings:
            continue
        if "path" not in app_settings:
            # we assume that an app that doesn't have a path doesn't have an HTTP api
            continue
        # This 'no_sso' settings sound redundant to not having $path defined ....
        # At least from what I can see, all apps using it don't have a path defined ...
        if (
            "no_sso" in app_settings
        ):  # I don't think we need to check for the value here
            continue
        # Users must at least have access to the main permission to have access to extra permissions
        if user:
            if not app + ".main" in permissions:
                logger.warning(
                    f"Uhoh, no main permission was found for app {app} ... sounds like an app was only partially removed due to another bug :/"
                )
                continue
            main_perm = permissions[app + ".main"]
            if user not in main_perm["corresponding_users"]:
                continue

        this_app_perms = {
            p: i
            for p, i in permissions.items()
            if p.startswith(app + ".") and (i["url"] or i["additional_urls"])
        }

        for perm_name, perm_info in this_app_perms.items():
            # If we're building the map for a specific user, check the user
            # actually is allowed for this specific perm
            if user and user not in perm_info["corresponding_users"]:
                continue

            perm_label = perm_info["label"]
            perm_all_urls = (
                []
                + ([perm_info["url"]] if perm_info["url"] else [])
                + perm_info["additional_urls"]
            )

            for url in perm_all_urls:

                # Here, we decide to completely ignore regex-type urls ...
                # Because :
                # - displaying them in regular "yunohost app map" output creates
                # a pretty big mess when there are multiple regexes for the same
                # app ? (c.f. for example lufi)
                # - it doesn't really make sense when checking app conflicts to
                # compare regexes ? (Or it could in some cases but ugh ?)
                #
                if url.startswith("re:"):
                    continue

                if not raw:
                    result[url] = perm_label
                else:
                    if "/" in url:
                        perm_domain, perm_path = url.split("/", 1)
                        perm_path = "/" + perm_path
                    else:
                        perm_domain = url
                        perm_path = "/"
                    if perm_domain not in result:
                        result[perm_domain] = {}
                    result[perm_domain][perm_path] = {"label": perm_label, "id": app}

    return result


@is_unit_operation()
def app_change_url(operation_logger, app, domain, path):
    """
    Modify the URL at which an application is installed.

    Keyword argument:
        app -- Taget app instance name
        domain -- New app domain on which the application will be moved
        path -- New path at which the application will be move

    """
    from yunohost.hook import hook_exec, hook_callback
    from yunohost.service import service_reload_or_restart

    installed = _is_installed(app)
    if not installed:
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )

    if not os.path.exists(
        os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url")
    ):
        raise YunohostValidationError("app_change_url_no_script", app_name=app)

    old_domain = app_setting(app, "domain")
    old_path = app_setting(app, "path")

    # Normalize path and domain format

    domain = DomainQuestion.normalize(domain)
    old_domain = DomainQuestion.normalize(old_domain)
    path = PathQuestion.normalize(path)
    old_path = PathQuestion.normalize(old_path)

    if (domain, path) == (old_domain, old_path):
        raise YunohostValidationError(
            "app_change_url_identical_domains", domain=domain, path=path
        )

    app_setting_path = os.path.join(APPS_SETTING_PATH, app)
    path_requirement = _guess_webapp_path_requirement(app_setting_path)
    _validate_webpath_requirement(
        {"domain": domain, "path": path}, path_requirement, ignore_app=app
    )

    tmp_workdir_for_app = _make_tmp_workdir_for_app(app=app)

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(
        app, workdir=tmp_workdir_for_app, action="change_url"
    )
    env_dict["YNH_APP_OLD_DOMAIN"] = old_domain
    env_dict["YNH_APP_OLD_PATH"] = old_path
    env_dict["YNH_APP_NEW_DOMAIN"] = domain
    env_dict["YNH_APP_NEW_PATH"] = path

    if domain != old_domain:
        operation_logger.related_to.append(("domain", old_domain))
    operation_logger.extra.update({"env": env_dict})
    operation_logger.start()

    change_url_script = os.path.join(tmp_workdir_for_app, "scripts/change_url")

    # Execute App change_url script
    ret = hook_exec(change_url_script, env=env_dict)[0]
    if ret != 0:
        msg = f"Failed to change '{app}' url."
        logger.error(msg)
        operation_logger.error(msg)

        # restore values modified by app_checkurl
        # see begining of the function
        app_setting(app, "domain", value=old_domain)
        app_setting(app, "path", value=old_path)
        return
    shutil.rmtree(tmp_workdir_for_app)

    # this should idealy be done in the change_url script but let's avoid common mistakes
    app_setting(app, "domain", value=domain)
    app_setting(app, "path", value=path)

    app_ssowatconf()

    service_reload_or_restart("nginx")

    logger.success(m18n.n("app_change_url_success", app=app, domain=domain, path=path))

    hook_callback("post_app_change_url", env=env_dict)


def app_upgrade(app=[], url=None, file=None, force=False, no_safety_backup=False):
    """
    Upgrade app

    Keyword argument:
        file -- Folder or tarball for upgrade
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade
        no_safety_backup -- Disable the safety backup during upgrade

    """
    from yunohost.hook import (
        hook_add,
        hook_remove,
        hook_callback,
        hook_exec_with_script_debug_if_failure,
    )
    from yunohost.permission import permission_sync_to_user
    from yunohost.regenconf import manually_modified_files
    from yunohost.utils.legacy import _patch_legacy_php_versions, _patch_legacy_helpers
    from yunohost.backup import (
        backup_list,
        backup_create,
        backup_delete,
        backup_restore,
    )

    apps = app
    # Check if disk space available
    if free_space_in_directory("/") <= 512 * 1000 * 1000:
        raise YunohostValidationError("disk_space_not_sufficient_update")
    # If no app is specified, upgrade all apps
    if not apps:
        # FIXME : not sure what's supposed to happen if there is a url and a file but no apps...
        if not url and not file:
            apps = _installed_apps()
    elif not isinstance(app, list):
        apps = [app]

    # Remove possible duplicates
    apps = [app_ for i, app_ in enumerate(apps) if app_ not in apps[:i]]

    # Abort if any of those app is in fact not installed..
    for app_ in apps:
        _assert_is_installed(app_)

    if len(apps) == 0:
        raise YunohostValidationError("apps_already_up_to_date")
    if len(apps) > 1:
        logger.info(m18n.n("app_upgrade_several_apps", apps=", ".join(apps)))

    notifications = {}

    for number, app_instance_name in enumerate(apps):
        logger.info(m18n.n("app_upgrade_app_name", app=app_instance_name))

        app_dict = app_info(app_instance_name, full=True)

        if file and isinstance(file, dict):
            # We use this dirty hack to test chained upgrades in unit/functional tests
            new_app_src = file[app_instance_name]
        elif file:
            new_app_src = file
        elif url:
            new_app_src = url
        elif app_dict["upgradable"] == "url_required":
            logger.warning(m18n.n("custom_app_url_required", app=app_instance_name))
            continue
        elif app_dict["upgradable"] == "yes" or force:
            new_app_src = app_dict["manifest"]["id"]
        else:
            logger.success(m18n.n("app_already_up_to_date", app=app_instance_name))
            continue

        manifest, extracted_app_folder = _extract_app(new_app_src)

        # Manage upgrade type and avoid any upgrade if there is nothing to do
        upgrade_type = "UNKNOWN"
        # Get current_version and new version
        app_new_version = version.parse(manifest.get("version", "?"))
        app_current_version = version.parse(app_dict.get("version", "?"))
        if "~ynh" in str(app_current_version) and "~ynh" in str(app_new_version):
            if app_current_version >= app_new_version and not force:
                # In case of upgrade from file or custom repository
                # No new version available
                logger.success(m18n.n("app_already_up_to_date", app=app_instance_name))
                # Save update time
                now = int(time.time())
                app_setting(app_instance_name, "update_time", now)
                app_setting(
                    app_instance_name,
                    "current_revision",
                    manifest.get("remote", {}).get("revision", "?"),
                )
                continue
            elif app_current_version > app_new_version:
                upgrade_type = "DOWNGRADE_FORCED"
            elif app_current_version == app_new_version:
                upgrade_type = "UPGRADE_FORCED"
            else:
                app_current_version_upstream, app_current_version_pkg = str(
                    app_current_version
                ).split("~ynh")
                app_new_version_upstream, app_new_version_pkg = str(
                    app_new_version
                ).split("~ynh")
                if app_current_version_upstream == app_new_version_upstream:
                    upgrade_type = "UPGRADE_PACKAGE"
                elif app_current_version_pkg == app_new_version_pkg:
                    upgrade_type = "UPGRADE_APP"
                else:
                    upgrade_type = "UPGRADE_FULL"

        # Check requirements
        for name, passed, values, err in _check_manifest_requirements(
            manifest, action="upgrade"
        ):
            if not passed:
                if name == "ram":
                    _ask_confirmation(
                        "confirm_app_insufficient_ram", params=values, force=force
                    )
                else:
                    raise YunohostValidationError(err, **values)

        # Display pre-upgrade notifications and ask for simple confirm
        if (
            manifest["notifications"]["pre_upgrade"]
            and Moulinette.interface.type == "cli"
        ):
            settings = _get_app_settings(app_instance_name)
            notifications = _filter_and_hydrate_notifications(
                manifest["notifications"]["pre_upgrade"],
                current_version=app_current_version,
                data=settings,
            )
            _display_notifications(notifications, force=force)

        if manifest["packaging_format"] >= 2:
            if no_safety_backup:
                # FIXME: i18n
                logger.warning(
                    "Skipping the creation of a backup prior to the upgrade."
                )
            else:
                # FIXME: i18n
                logger.info("Creating a safety backup prior to the upgrade")

                # Switch between pre-upgrade1 or pre-upgrade2
                safety_backup_name = f"{app_instance_name}-pre-upgrade1"
                other_safety_backup_name = f"{app_instance_name}-pre-upgrade2"
                if safety_backup_name in backup_list()["archives"]:
                    safety_backup_name = f"{app_instance_name}-pre-upgrade2"
                    other_safety_backup_name = f"{app_instance_name}-pre-upgrade1"

                backup_create(name=safety_backup_name, apps=[app_instance_name])

                if safety_backup_name in backup_list()["archives"]:
                    # if the backup suceeded, delete old safety backup to save space
                    if other_safety_backup_name in backup_list()["archives"]:
                        backup_delete(other_safety_backup_name)
                else:
                    # Is this needed ? Shouldn't backup_create report an expcetion if backup failed ?
                    raise YunohostError(
                        "Uhoh the safety backup failed ?! Aborting the upgrade process.",
                        raw_msg=True,
                    )

        _assert_system_is_sane_for_app(manifest, "pre")

        # We'll check that the app didn't brutally edit some system configuration
        manually_modified_files_before_install = manually_modified_files()

        app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)

        # Attempt to patch legacy helpers ...
        _patch_legacy_helpers(extracted_app_folder)

        # Apply dirty patch to make php5 apps compatible with php7
        _patch_legacy_php_versions(extracted_app_folder)

        # Prepare env. var. to pass to script
        env_dict = _make_environment_for_app_script(
            app_instance_name, workdir=extracted_app_folder, action="upgrade"
        )
        env_dict["YNH_APP_UPGRADE_TYPE"] = upgrade_type
        env_dict["YNH_APP_MANIFEST_VERSION"] = str(app_new_version)
        env_dict["YNH_APP_CURRENT_VERSION"] = str(app_current_version)
        if manifest["packaging_format"] < 2:
            env_dict["NO_BACKUP_UPGRADE"] = "1" if no_safety_backup else "0"

        # Start register change on system
        related_to = [("app", app_instance_name)]
        operation_logger = OperationLogger("app_upgrade", related_to, env=env_dict)
        operation_logger.start()

        if manifest["packaging_format"] >= 2:
            from yunohost.utils.resources import AppResourceManager

            AppResourceManager(
                app_instance_name, wanted=manifest, current=app_dict["manifest"]
            ).apply(rollback_and_raise_exception_if_failure=True, operation_logger=operation_logger)

        # Execute the app upgrade script
        upgrade_failed = True
        try:
            (
                upgrade_failed,
                failure_message_with_debug_instructions,
            ) = hook_exec_with_script_debug_if_failure(
                extracted_app_folder + "/scripts/upgrade",
                env=env_dict,
                operation_logger=operation_logger,
                error_message_if_script_failed=m18n.n("app_upgrade_script_failed"),
                error_message_if_failed=lambda e: m18n.n(
                    "app_upgrade_failed", app=app_instance_name, error=e
                ),
            )
        finally:

            # If upgrade failed, try to restore the safety backup
            if (
                upgrade_failed
                and manifest["packaging_format"] >= 2
                and not no_safety_backup
            ):
                logger.warning(
                    "Upgrade failed ... attempting to restore the satefy backup (Yunohost first need to remove the app for this) ..."
                )

                app_remove(app_instance_name)
                backup_restore(
                    name=safety_backup_name, apps=[app_instance_name], force=True
                )
                if not _is_installed(app_instance_name):
                    logger.error(
                        "Uhoh ... Yunohost failed to restore the app to the way it was before the failed upgrade :|"
                    )

            # Whatever happened (install success or failure) we check if it broke the system
            # and warn the user about it
            try:
                broke_the_system = False
                _assert_system_is_sane_for_app(manifest, "post")
            except Exception as e:
                broke_the_system = True
                logger.error(
                    m18n.n("app_upgrade_failed", app=app_instance_name, error=str(e))
                )
                failure_message_with_debug_instructions = operation_logger.error(str(e))

            # We'll check that the app didn't brutally edit some system configuration
            manually_modified_files_after_install = manually_modified_files()
            manually_modified_files_by_app = set(
                manually_modified_files_after_install
            ) - set(manually_modified_files_before_install)
            if manually_modified_files_by_app:
                logger.error(
                    "Packagers /!\\ This app manually modified some system configuration files! This should not happen! If you need to do so, you should implement a proper conf_regen hook. Those configuration were affected:\n    - "
                    + "\n     -".join(manually_modified_files_by_app)
                )

            # If upgrade failed or broke the system,
            # raise an error and interrupt all other pending upgrades
            if upgrade_failed or broke_the_system:

                # display this if there are remaining apps
                if apps[number + 1 :]:
                    not_upgraded_apps = apps[number:]
                    logger.error(
                        m18n.n(
                            "app_not_upgraded",
                            failed_app=app_instance_name,
                            apps=", ".join(not_upgraded_apps),
                        )
                    )

                raise YunohostError(
                    failure_message_with_debug_instructions, raw_msg=True
                )

            # Otherwise we're good and keep going !
            now = int(time.time())
            app_setting(app_instance_name, "update_time", now)
            app_setting(
                app_instance_name,
                "current_revision",
                manifest.get("remote", {}).get("revision", "?"),
            )

            # Clean hooks and add new ones
            hook_remove(app_instance_name)
            if "hooks" in os.listdir(extracted_app_folder):
                for hook in os.listdir(extracted_app_folder + "/hooks"):
                    hook_add(app_instance_name, extracted_app_folder + "/hooks/" + hook)

            # Replace scripts and manifest and conf (if exists)
            # Move scripts and manifest to the right place
            for file_to_copy in APP_FILES_TO_COPY:
                rm(f"{app_setting_path}/{file_to_copy}", recursive=True, force=True)
                if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
                    cp(
                        f"{extracted_app_folder}/{file_to_copy}",
                        f"{app_setting_path}/{file_to_copy}",
                        recursive=True,
                    )

            # Clean and set permissions
            shutil.rmtree(extracted_app_folder)
            chmod(app_setting_path, 0o600)
            chmod(f"{app_setting_path}/settings.yml", 0o400)
            chown(app_setting_path, "root", recursive=True)

            # So much win
            logger.success(m18n.n("app_upgraded", app=app_instance_name))

            # Format post-upgrade notifications
            if manifest["notifications"]["post_upgrade"]:
                # Get updated settings to hydrate notifications
                settings = _get_app_settings(app_instance_name)
                notifications = _filter_and_hydrate_notifications(
                    manifest["notifications"]["post_upgrade"],
                    current_version=app_current_version,
                    data=settings,
                )
                if Moulinette.interface.type == "cli":
                    # ask for simple confirm
                    _display_notifications(notifications, force=force)

            hook_callback("post_app_upgrade", env=env_dict)
            operation_logger.success()

    permission_sync_to_user()

    logger.success(m18n.n("upgrade_complete"))

    if Moulinette.interface.type == "api":
        return {"notifications": {"post_upgrade": notifications}}


def app_manifest(app, with_screenshot=False):

    manifest, extracted_app_folder = _extract_app(app)

    raw_questions = manifest.get("install", {}).values()
    manifest["install"] = hydrate_questions_with_choices(raw_questions)

    # Add a base64 image to be displayed in web-admin
    if with_screenshot and Moulinette.interface.type == "api":
        import base64

        manifest["screenshot"] = None
        screenshots_folder = os.path.join(extracted_app_folder, "doc", "screenshots")

        if os.path.exists(screenshots_folder):
            with os.scandir(screenshots_folder) as it:
                for entry in it:
                    ext = os.path.splitext(entry.name)[1].replace(".", "").lower()
                    if entry.is_file() and ext in ("png", "jpg", "jpeg", "webp", "gif"):
                        with open(entry.path, "rb") as img_file:
                            data = base64.b64encode(img_file.read()).decode("utf-8")
                            manifest["screenshot"] = f"data:image/{ext};charset=utf-8;base64,{data}"
                        break

    shutil.rmtree(extracted_app_folder)

    manifest["requirements"] = {}
    for name, passed, values, err in _check_manifest_requirements(
        manifest, action="install"
    ):
        if Moulinette.interface.type == "api":
            manifest["requirements"][name] = {
                "pass": passed,
                "values": values,
            }
        else:
            manifest["requirements"][name] = "ok" if passed else m18n.n(err, **values)

    return manifest


def _confirm_app_install(app, force=False):

    # Ignore if there's nothing for confirm (good quality app), if --force is used
    # or if request on the API (confirm already implemented on the API side)
    if force or Moulinette.interface.type == "api":
        return

    quality = _app_quality(app)
    if quality == "success":
        return

    # i18n: confirm_app_install_warning
    # i18n: confirm_app_install_danger
    # i18n: confirm_app_install_thirdparty

    if quality in ["danger", "thirdparty"]:
        _ask_confirmation("confirm_app_install_" + quality, kind="hard")
    else:
        _ask_confirmation("confirm_app_install_" + quality, kind="soft")


@is_unit_operation()
def app_install(
    operation_logger,
    app,
    label=None,
    args=None,
    no_remove_on_failure=False,
    force=False,
):
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation
        no_remove_on_failure -- Debug option to avoid removing the app on a failed installation
        force -- Do not ask for confirmation when installing experimental / low-quality apps
    """

    from yunohost.hook import (
        hook_add,
        hook_remove,
        hook_callback,
        hook_exec,
        hook_exec_with_script_debug_if_failure,
    )
    from yunohost.log import OperationLogger
    from yunohost.permission import (
        user_permission_list,
        permission_create,
        permission_delete,
        permission_sync_to_user,
    )
    from yunohost.regenconf import manually_modified_files
    from yunohost.utils.legacy import _patch_legacy_php_versions, _patch_legacy_helpers

    # Check if disk space available
    if free_space_in_directory("/") <= 512 * 1000 * 1000:
        raise YunohostValidationError("disk_space_not_sufficient_install")

    _confirm_app_install(app, force)
    manifest, extracted_app_folder = _extract_app(app)

    # Display pre_install notices in cli mode
    if manifest["notifications"]["pre_install"] and Moulinette.interface.type == "cli":
        notifications = _filter_and_hydrate_notifications(
            manifest["notifications"]["pre_install"]
        )
        _display_notifications(notifications, force=force)

    packaging_format = manifest["packaging_format"]

    # Check ID
    if "id" not in manifest or "__" in manifest["id"] or "." in manifest["id"]:
        raise YunohostValidationError("app_id_invalid")

    app_id = manifest["id"]

    # Check requirements
    for name, passed, values, err in _check_manifest_requirements(
        manifest, action="install"
    ):
        if not passed:
            if name == "ram":
                _ask_confirmation(
                    "confirm_app_insufficient_ram", params=values, force=force
                )
            else:
                raise YunohostValidationError(err, **values)

    _assert_system_is_sane_for_app(manifest, "pre")

    # Check if app can be forked
    instance_number = _next_instance_number_for_app(app_id)
    if instance_number > 1:
        # Change app_id to the forked app id
        app_instance_name = app_id + "__" + str(instance_number)
    else:
        app_instance_name = app_id

    app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)

    # Retrieve arguments list for install script
    raw_questions = manifest["install"]
    questions = ask_questions_and_parse_answers(raw_questions, prefilled_answers=args)
    args = {
        question.name: question.value
        for question in questions
        if question.value is not None
    }

    # Validate domain / path availability for webapps
    # (ideally this should be handled by the resource system for manifest v >= 2
    path_requirement = _guess_webapp_path_requirement(extracted_app_folder)
    _validate_webpath_requirement(args, path_requirement)

    if packaging_format < 2:
        # Attempt to patch legacy helpers ...
        _patch_legacy_helpers(extracted_app_folder)

    # Apply dirty patch to make php5 apps compatible with php7
    _patch_legacy_php_versions(extracted_app_folder)

    # We'll check that the app didn't brutally edit some system configuration
    manually_modified_files_before_install = manually_modified_files()

    operation_logger.related_to = [
        s for s in operation_logger.related_to if s[0] != "app"
    ]
    operation_logger.related_to.append(("app", app_id))
    operation_logger.start()

    logger.info(m18n.n("app_start_install", app=app_id))

    # Create app directory
    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)
    os.makedirs(app_setting_path)

    # Set initial app settings
    app_settings = {
        "id": app_instance_name,
        "install_time": int(time.time()),
        "current_revision": manifest.get("remote", {}).get("revision", "?"),
    }

    # If packaging_format v2+, save all install questions as settings
    if packaging_format >= 2:
        for question in questions:

            # Except user-provider passwords
            if question.type == "password":
                continue

            app_settings[question.name] = question.value

    _set_app_settings(app_instance_name, app_settings)

    # Move scripts and manifest to the right place
    for file_to_copy in APP_FILES_TO_COPY:
        if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
            cp(
                f"{extracted_app_folder}/{file_to_copy}",
                f"{app_setting_path}/{file_to_copy}",
                recursive=True,
            )

    # Override manifest name by given label
    # This info is also later picked-up by the 'permission' resource initialization
    if label:
        manifest["name"] = label

    if packaging_format >= 2:
        from yunohost.utils.resources import AppResourceManager

        AppResourceManager(app_instance_name, wanted=manifest, current={}).apply(
            rollback_and_raise_exception_if_failure=True, operation_logger=operation_logger
        )
    else:
        # Initialize the main permission for the app
        # The permission is initialized with no url associated, and with tile disabled
        # For web app, the root path of the app will be added as url and the tile
        # will be enabled during the app install. C.f. 'app_register_url()' below
        # or the webpath resource
        permission_create(
            app_instance_name + ".main",
            allowed=["all_users"],
            label=manifest["name"],
            show_tile=False,
            protected=False,
        )

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(
        app_instance_name, args=args, workdir=extracted_app_folder, action="install"
    )

    env_dict_for_logging = env_dict.copy()
    for question in questions:
        # Or should it be more generally question.redact ?
        if question.type == "password":
            del env_dict_for_logging[f"YNH_APP_ARG_{question.name.upper()}"]

    operation_logger.extra.update({"env": env_dict_for_logging})

    # Execute the app install script
    install_failed = True
    try:
        (
            install_failed,
            failure_message_with_debug_instructions,
        ) = hook_exec_with_script_debug_if_failure(
            os.path.join(extracted_app_folder, "scripts/install"),
            env=env_dict,
            operation_logger=operation_logger,
            error_message_if_script_failed=m18n.n("app_install_script_failed"),
            error_message_if_failed=lambda e: m18n.n(
                "app_install_failed", app=app_id, error=e
            ),
        )
    finally:
        # If success so far, validate that app didn't break important stuff
        if not install_failed:
            try:
                broke_the_system = False
                _assert_system_is_sane_for_app(manifest, "post")
            except Exception as e:
                broke_the_system = True
                logger.error(m18n.n("app_install_failed", app=app_id, error=str(e)))
                failure_message_with_debug_instructions = operation_logger.error(str(e))

        # We'll check that the app didn't brutally edit some system configuration
        manually_modified_files_after_install = manually_modified_files()
        manually_modified_files_by_app = set(
            manually_modified_files_after_install
        ) - set(manually_modified_files_before_install)
        if manually_modified_files_by_app:
            logger.error(
                "Packagers /!\\ This app manually modified some system configuration files! This should not happen! If you need to do so, you should implement a proper conf_regen hook. Those configuration were affected:\n    - "
                + "\n     -".join(manually_modified_files_by_app)
            )
            # Actually forbid this for app packaging >= 2
            if packaging_format >= 2:
                broke_the_system = True

        # If the install failed or broke the system, we remove it
        if install_failed or broke_the_system:

            # This option is meant for packagers to debug their apps more easily
            if no_remove_on_failure:
                raise YunohostError(
                    f"The installation of {app_id} failed, but was not cleaned up as requested by --no-remove-on-failure.",
                    raw_msg=True,
                )
            else:
                logger.warning(m18n.n("app_remove_after_failed_install"))

            # Setup environment for remove script
            env_dict_remove = _make_environment_for_app_script(
                app_instance_name, workdir=extracted_app_folder, action="remove"
            )

            # Execute remove script
            operation_logger_remove = OperationLogger(
                "remove_on_failed_install",
                [("app", app_instance_name)],
                env=env_dict_remove,
            )
            operation_logger_remove.start()

            # Try to remove the app
            try:
                remove_retcode = hook_exec(
                    os.path.join(extracted_app_folder, "scripts/remove"),
                    args=[app_instance_name],
                    env=env_dict_remove,
                )[0]

            # Here again, calling hook_exec could fail miserably, or get
            # manually interrupted (by mistake or because script was stuck)
            # In that case we still want to proceed with the rest of the
            # removal (permissions, /etc/yunohost/apps/{app} ...)
            except (KeyboardInterrupt, EOFError, Exception):
                remove_retcode = -1
                import traceback

                logger.error(
                    m18n.n("unexpected_error", error="\n" + traceback.format_exc())
                )

            if packaging_format >= 2:
                from yunohost.utils.resources import AppResourceManager

                AppResourceManager(
                    app_instance_name, wanted={}, current=manifest
                ).apply(rollback_and_raise_exception_if_failure=False)
            else:
                # Remove all permission in LDAP
                for permission_name in user_permission_list()["permissions"].keys():
                    if permission_name.startswith(app_instance_name + "."):
                        permission_delete(permission_name, force=True, sync_perm=False)

            if remove_retcode != 0:
                msg = m18n.n("app_not_properly_removed", app=app_instance_name)
                logger.warning(msg)
                operation_logger_remove.error(msg)
            else:
                try:
                    _assert_system_is_sane_for_app(manifest, "post")
                except Exception as e:
                    operation_logger_remove.error(e)
                else:
                    operation_logger_remove.success()

            # Clean tmp folders
            shutil.rmtree(app_setting_path)
            shutil.rmtree(extracted_app_folder)

            permission_sync_to_user()

            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)

    # Clean hooks and add new ones
    hook_remove(app_instance_name)
    if "hooks" in os.listdir(extracted_app_folder):
        for file in os.listdir(extracted_app_folder + "/hooks"):
            hook_add(app_instance_name, extracted_app_folder + "/hooks/" + file)

    # Clean and set permissions
    shutil.rmtree(extracted_app_folder)
    chmod(app_setting_path, 0o600)
    chmod(f"{app_setting_path}/settings.yml", 0o400)
    chown(app_setting_path, "root", recursive=True)

    logger.success(m18n.n("installation_complete"))

    # Get the generated settings to hydrate notifications
    settings = _get_app_settings(app_instance_name)
    notifications = _filter_and_hydrate_notifications(
        manifest["notifications"]["post_install"], data=settings
    )

    # Display post_install notices in cli mode
    if notifications and Moulinette.interface.type == "cli":
        _display_notifications(notifications, force=force)

    # Call postinstall hook
    hook_callback("post_app_install", env=env_dict)

    # Return hydrated post install notif for API
    if Moulinette.interface.type == "api":
        return {"notifications": notifications}


@is_unit_operation()
def app_remove(operation_logger, app, purge=False):
    """
    Remove app

    Keyword arguments:
        app -- App(s) to delete
        purge -- Remove with all app data

    """
    from yunohost.utils.legacy import _patch_legacy_php_versions, _patch_legacy_helpers
    from yunohost.hook import hook_exec, hook_remove, hook_callback
    from yunohost.permission import (
        user_permission_list,
        permission_delete,
        permission_sync_to_user,
    )
    from yunohost.domain import domain_list, domain_config_get, domain_config_set

    if not _is_installed(app):
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )

    operation_logger.start()

    logger.info(m18n.n("app_start_remove", app=app))

    app_setting_path = os.path.join(APPS_SETTING_PATH, app)

    # Attempt to patch legacy helpers ...
    _patch_legacy_helpers(app_setting_path)

    # Apply dirty patch to make php5 apps compatible with php7 (e.g. the remove
    # script might date back from jessie install)
    _patch_legacy_php_versions(app_setting_path)

    manifest = _get_manifest_of_app(app_setting_path)
    tmp_workdir_for_app = _make_tmp_workdir_for_app(app=app)
    remove_script = f"{tmp_workdir_for_app}/scripts/remove"

    env_dict = {}
    env_dict = _make_environment_for_app_script(
        app, workdir=tmp_workdir_for_app, action="remove"
    )
    env_dict["YNH_APP_PURGE"] = str(1 if purge else 0)

    operation_logger.extra.update({"env": env_dict})
    operation_logger.flush()

    try:
        ret = hook_exec(remove_script, env=env_dict)[0]
    # Here again, calling hook_exec could fail miserably, or get
    # manually interrupted (by mistake or because script was stuck)
    # In that case we still want to proceed with the rest of the
    # removal (permissions, /etc/yunohost/apps/{app} ...)
    except (KeyboardInterrupt, EOFError, Exception):
        ret = -1
        import traceback

        logger.error(m18n.n("unexpected_error", error="\n" + traceback.format_exc()))
    finally:
        shutil.rmtree(tmp_workdir_for_app)

    packaging_format = manifest["packaging_format"]
    if packaging_format >= 2:
        from yunohost.utils.resources import AppResourceManager

        AppResourceManager(app, wanted={}, current=manifest).apply(
            rollback_and_raise_exception_if_failure=False, purge_data_dir=purge
        )
    else:
        # Remove all permission in LDAP
        for permission_name in user_permission_list(apps=[app])["permissions"].keys():
            permission_delete(permission_name, force=True, sync_perm=False)

    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)

    hook_remove(app)

    for domain in domain_list()["domains"]:
        if domain_config_get(domain, "feature.app.default_app") == app:
            domain_config_set(domain, "feature.app.default_app", "_none")

    if ret == 0:
        logger.success(m18n.n("app_removed", app=app))
        hook_callback("post_app_remove", env=env_dict)
    else:
        logger.warning(m18n.n("app_not_properly_removed", app=app))

    permission_sync_to_user()
    _assert_system_is_sane_for_app(manifest, "post")


@is_unit_operation()
def app_makedefault(operation_logger, app, domain=None, undo=False):
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from yunohost.domain import _assert_domain_exists, domain_config_set

    app_settings = _get_app_settings(app)
    app_domain = app_settings["domain"]

    if domain is None:
        domain = app_domain

    _assert_domain_exists(domain)

    operation_logger.related_to.append(("domain", domain))

    operation_logger.start()

    if undo:
        domain_config_set(domain, "feature.app.default_app", "_none")
    else:
        domain_config_set(domain, "feature.app.default_app", app)


def app_setting(app, key, value=None, delete=False):
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """
    app_settings = _get_app_settings(app) or {}

    #
    # Legacy permission setting management
    # (unprotected, protected, skipped_uri/regex)
    #

    is_legacy_permission_setting = any(
        key.startswith(word + "_") for word in ["unprotected", "protected", "skipped"]
    )

    if is_legacy_permission_setting:

        from yunohost.permission import (
            user_permission_list,
            user_permission_update,
            permission_create,
            permission_delete,
            permission_url,
        )

        permissions = user_permission_list(full=True, apps=[app])["permissions"]
        key_ = key.split("_")[0]
        permission_name = f"{app}.legacy_{key_}_uris"
        permission = permissions.get(permission_name)

        # GET
        if value is None and not delete:
            return (
                ",".join(permission.get("uris", []) + permission["additional_urls"])
                if permission
                else None
            )

        # DELETE
        if delete:
            # If 'is_public' setting still exists, we interpret this as
            # coming from a legacy app (because new apps shouldn't manage the
            # is_public state themselves anymore...)
            #
            # In that case, we interpret the request for "deleting
            # unprotected/skipped" setting as willing to make the app
            # private
            if (
                "is_public" in app_settings
                and "visitors" in permissions[app + ".main"]["allowed"]
            ):
                if key.startswith("unprotected_") or key.startswith("skipped_"):
                    user_permission_update(app + ".main", remove="visitors")

            if permission:
                permission_delete(permission_name)

        # SET
        else:

            urls = value
            # If the request is about the root of the app (/), ( = the vast majority of cases)
            # we interpret this as a change for the main permission
            # (i.e. allowing/disallowing visitors)
            if urls == "/":
                if key.startswith("unprotected_") or key.startswith("skipped_"):
                    permission_url(app + ".main", url="/", sync_perm=False)
                    user_permission_update(app + ".main", add="visitors")
                else:
                    user_permission_update(app + ".main", remove="visitors")
            else:

                urls = urls.split(",")
                if key.endswith("_regex"):
                    urls = ["re:" + url for url in urls]

                if permission:
                    # In case of new regex, save the urls, to add a new time in the additional_urls
                    # In case of new urls, we do the same thing but inversed
                    if key.endswith("_regex"):
                        # List of urls to save
                        current_urls_or_regex = [
                            url
                            for url in permission["additional_urls"]
                            if not url.startswith("re:")
                        ]
                    else:
                        # List of regex to save
                        current_urls_or_regex = [
                            url
                            for url in permission["additional_urls"]
                            if url.startswith("re:")
                        ]

                    new_urls = urls + current_urls_or_regex
                    # We need to clear urls because in the old setting the new setting override the old one and dont just add some urls
                    permission_url(permission_name, clear_urls=True, sync_perm=False)
                    permission_url(permission_name, add_url=new_urls)
                else:
                    from yunohost.utils.legacy import legacy_permission_label

                    # Let's create a "special" permission for the legacy settings
                    permission_create(
                        permission=permission_name,
                        # FIXME find a way to limit to only the user allowed to the main permission
                        allowed=["all_users"]
                        if key.startswith("protected_")
                        else ["all_users", "visitors"],
                        url=None,
                        additional_urls=urls,
                        auth_header=not key.startswith("skipped_"),
                        label=legacy_permission_label(app, key.split("_")[0]),
                        show_tile=False,
                        protected=True,
                    )

        return

    #
    # Regular setting management
    #

    # GET
    if value is None and not delete:
        return app_settings.get(key, None)

    # DELETE
    if delete:
        if key in app_settings:
            del app_settings[key]

    # SET
    else:
        if key in ["redirected_urls", "redirected_regex"]:
            value = yaml.safe_load(value)
        app_settings[key] = value

    _set_app_settings(app, app_settings)


def app_register_url(app, domain, path):
    """
    Book/register a web path for a given app

    Keyword argument:
        app -- App which will use the web path
        domain -- The domain on which the app should be registered (e.g. your.domain.tld)
        path -- The path to be registered (e.g. /coffee)
    """
    from yunohost.permission import (
        permission_url,
        user_permission_update,
        permission_sync_to_user,
    )

    domain = DomainQuestion.normalize(domain)
    path = PathQuestion.normalize(path)

    # We cannot change the url of an app already installed simply by changing
    # the settings...

    if _is_installed(app):
        settings = _get_app_settings(app)
        if "path" in settings.keys() and "domain" in settings.keys():
            raise YunohostValidationError("app_already_installed_cant_change_url")

    # Check the url is available
    _assert_no_conflicting_apps(domain, path, ignore_app=app)

    app_setting(app, "domain", value=domain)
    app_setting(app, "path", value=path)

    # Initially, the .main permission is created with no url at all associated
    # When the app register/books its web url, we also add the url '/'
    # (meaning the root of the app, domain.tld/path/)
    # and enable the tile to the SSO, and both of this should match 95% of apps
    # For more specific cases, the app is free to change / add urls or disable
    # the tile using the permission helpers.
    permission_url(app + ".main", url="/", sync_perm=False)
    user_permission_update(app + ".main", show_tile=True, sync_perm=False)
    permission_sync_to_user()


def app_ssowatconf():
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import domain_list, _get_maindomain, domain_config_get
    from yunohost.permission import user_permission_list
    from yunohost.settings import settings_get

    main_domain = _get_maindomain()
    domains = domain_list()["domains"]
    all_permissions = user_permission_list(
        full=True, ignore_system_perms=True, absolute_urls=True
    )["permissions"]

    permissions = {
        "core_skipped": {
            "users": [],
            "label": "Core permissions - skipped",
            "show_tile": False,
            "auth_header": False,
            "public": True,
            "uris": [domain + "/yunohost/admin" for domain in domains]
            + [domain + "/yunohost/api" for domain in domains]
            + [
                "re:^[^/]/502%.html$",
                "re:^[^/]*/%.well%-known/ynh%-diagnosis/.*$",
                "re:^[^/]*/%.well%-known/acme%-challenge/.*$",
                "re:^[^/]*/%.well%-known/autoconfig/mail/config%-v1%.1%.xml.*$",
            ],
        }
    }
    redirected_regex = {
        main_domain + r"/yunohost[\/]?$": "https://" + main_domain + "/yunohost/sso/"
    }
    redirected_urls = {}

    for app in _installed_apps():

        app_settings = read_yaml(APPS_SETTING_PATH + app + "/settings.yml") or {}

        # Redirected
        redirected_urls.update(app_settings.get("redirected_urls", {}))
        redirected_regex.update(app_settings.get("redirected_regex", {}))

    from .utils.legacy import (
        translate_legacy_default_app_in_ssowant_conf_json_persistent,
    )

    translate_legacy_default_app_in_ssowant_conf_json_persistent()

    for domain in domains:
        default_app = domain_config_get(domain, "feature.app.default_app")
        if default_app != "_none" and _is_installed(default_app):
            app_settings = _get_app_settings(default_app)
            app_domain = app_settings["domain"]
            app_path = app_settings["path"]

            # Prevent infinite redirect loop...
            if domain + "/" != app_domain + app_path:
                redirected_urls[domain + "/"] = app_domain + app_path

    # New permission system
    for perm_name, perm_info in all_permissions.items():

        uris = (
            []
            + ([perm_info["url"]] if perm_info["url"] else [])
            + perm_info["additional_urls"]
        )

        # Ignore permissions for which there's no url defined
        if not uris:
            continue

        permissions[perm_name] = {
            "users": perm_info["corresponding_users"],
            "label": perm_info["label"],
            "show_tile": perm_info["show_tile"]
            and perm_info["url"]
            and (not perm_info["url"].startswith("re:")),
            "auth_header": perm_info["auth_header"],
            "public": "visitors" in perm_info["allowed"],
            "uris": uris,
        }

    conf_dict = {
        "theme": settings_get("misc.portal.portal_theme"),
        "portal_domain": main_domain,
        "portal_path": "/yunohost/sso/",
        "additional_headers": {
            "Auth-User": "uid",
            "Remote-User": "uid",
            "Name": "cn",
            "Email": "mail",
        },
        "domains": domains,
        "redirected_urls": redirected_urls,
        "redirected_regex": redirected_regex,
        "permissions": permissions,
    }

    write_to_json("/etc/ssowat/conf.json", conf_dict, sort_keys=True, indent=4)

    logger.debug(m18n.n("ssowat_conf_generated"))


def app_change_label(app, new_label):
    from yunohost.permission import user_permission_update

    installed = _is_installed(app)
    if not installed:
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )
    logger.warning(m18n.n("app_label_deprecated"))
    user_permission_update(app + ".main", label=new_label)


# actions todo list:
# * docstring


def app_action_list(app):

    return AppConfigPanel(app).list_actions()


@is_unit_operation()
def app_action_run(operation_logger, app, action, args=None, args_file=None):

    return AppConfigPanel(app).run_action(
        action, args=args, args_file=args_file, operation_logger=operation_logger
    )


def app_config_get(app, key="", full=False, export=False):
    """
    Display an app configuration in classic, full or export mode
    """
    if full and export:
        raise YunohostValidationError(
            "You can't use --full and --export together.", raw_msg=True
        )

    if full:
        mode = "full"
    elif export:
        mode = "export"
    else:
        mode = "classic"

    try:
        config_ = AppConfigPanel(app)
        return config_.get(key, mode)
    except YunohostValidationError as e:
        if Moulinette.interface.type == "api" and e.key == "config_no_panel":
            # Be more permissive when no config panel found
            return {}
        else:
            raise


@is_unit_operation()
def app_config_set(
    operation_logger, app, key=None, value=None, args=None, args_file=None
):
    """
    Apply a new app configuration
    """

    config_ = AppConfigPanel(app)

    return config_.set(key, value, args, args_file, operation_logger=operation_logger)


class AppConfigPanel(ConfigPanel):
    entity_type = "app"
    save_path_tpl = os.path.join(APPS_SETTING_PATH, "{entity}/settings.yml")
    config_path_tpl = os.path.join(APPS_SETTING_PATH, "{entity}/config_panel.toml")

    def _load_current_values(self):
        self.values = self._call_config_script("show")

    def _run_action(self, action):
        env = {key: str(value) for key, value in self.new_values.items()}
        self._call_config_script(action, env=env)

    def _apply(self):
        env = {key: str(value) for key, value in self.new_values.items()}
        return_content = self._call_config_script("apply", env=env)

        # If the script returned validation error
        # raise a ValidationError exception using
        # the first key
        if return_content:
            for key, message in return_content.get("validation_errors").items():
                raise YunohostValidationError(
                    "app_argument_invalid",
                    name=key,
                    error=message,
                )

    def _call_config_script(self, action, env=None):
        from yunohost.hook import hook_exec

        if env is None:
            env = {}

        # Add default config script if needed
        config_script = os.path.join(
            APPS_SETTING_PATH, self.entity, "scripts", "config"
        )
        if not os.path.exists(config_script):
            logger.debug("Adding a default config script")
            default_script = """#!/bin/bash
source /usr/share/yunohost/helpers
ynh_abort_if_errors
ynh_app_config_run $1
"""
            write_to_file(config_script, default_script)

        # Call config script to extract current values
        logger.debug(f"Calling '{action}' action from config script")
        app = self.entity
        app_id, app_instance_nb = _parse_app_instance_name(app)
        settings = _get_app_settings(app)
        env.update(
            {
                "app_id": app_id,
                "app": app,
                "app_instance_nb": str(app_instance_nb),
                "final_path": settings.get("final_path", ""),
                "install_dir": settings.get("install_dir", ""),
                "YNH_APP_BASEDIR": os.path.join(APPS_SETTING_PATH, app),
            }
        )

        ret, values = hook_exec(config_script, args=[action], env=env)
        if ret != 0:
            if action == "show":
                raise YunohostError("app_config_unable_to_read")
            elif action == "apply":
                raise YunohostError("app_config_unable_to_apply")
            else:
                raise YunohostError("app_action_failed", action=action, app=app)
        return values


def _get_app_actions(app_id):
    "Get app config panel stored in json or in toml"
    actions_toml_path = os.path.join(APPS_SETTING_PATH, app_id, "actions.toml")
    actions_json_path = os.path.join(APPS_SETTING_PATH, app_id, "actions.json")

    if os.path.exists(actions_toml_path):
        toml_actions = toml.load(open(actions_toml_path, "r"), _dict=OrderedDict)

        # transform toml format into json format
        actions = []

        for key, value in toml_actions.items():
            action = dict(**value)
            action["id"] = key
            action["arguments"] = value.get("arguments", {})
            actions.append(action)

        return actions

    elif os.path.exists(actions_json_path):
        return json.load(open(actions_json_path))

    return None


def _get_app_settings(app):
    """
    Get settings of an installed app

    Keyword arguments:
        app -- The app id (like nextcloud__2)

    """
    if not _is_installed(app):
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )
    try:
        with open(os.path.join(APPS_SETTING_PATH, app, "settings.yml")) as f:
            settings = yaml.safe_load(f) or {}
        # If label contains unicode char, this may later trigger issues when building strings...
        # FIXME: this should be propagated to read_yaml so that this fix applies everywhere I think...
        settings = {k: v for k, v in settings.items()}

        # App settings should never be empty, there should always be at least some standard, internal keys like id, install_time etc.
        # Otherwise, this probably means that the app settings disappeared somehow...
        if not settings:
            logger.error(
                f"It looks like settings.yml for {app} is empty ... This should not happen ..."
            )
            logger.error(m18n.n("app_not_correctly_installed", app=app))
            return {}

        # Stupid fix for legacy bullshit
        # In the past, some setups did not have proper normalization for app domain/path
        # Meaning some setups (as of January 2021) still have path=/foobar/ (with a trailing slash)
        # resulting in stupid issue unless apps using ynh_app_normalize_path_stuff
        # So we yolofix the settings if such an issue is found >_>
        # A simple call  to `yunohost app list` (which happens quite often) should be enough
        # to migrate all app settings ... so this can probably be removed once we're past Bullseye...
        if settings.get("path") != "/" and (
            settings.get("path", "").endswith("/")
            or not settings.get("path", "/").startswith("/")
        ):
            settings["path"] = "/" + settings["path"].strip("/")
            _set_app_settings(app, settings)

        if app == settings["id"]:
            return settings
    except (IOError, TypeError, KeyError):
        logger.error(m18n.n("app_not_correctly_installed", app=app))
    return {}


def _set_app_settings(app, settings):
    """
    Set settings of an app

    Keyword arguments:
        app_id -- The app id (like nextcloud__2)
        settings -- Dict with app settings

    """
    with open(os.path.join(APPS_SETTING_PATH, app, "settings.yml"), "w") as f:
        yaml.safe_dump(settings, f, default_flow_style=False)


def _get_manifest_of_app(path):
    "Get app manifest stored in json or in toml"

    # sample data to get an idea of what is going on
    # this toml extract:
    #
    # license = "free"
    # url = "https://example.com"
    # multi_instance = true
    # version = "1.0~ynh1"
    # packaging_format = 1
    # services = ["nginx", "php7.0-fpm", "mysql"]
    # id = "ynhexample"
    # name = "YunoHost example app"
    #
    # [requirements]
    # yunohost = ">= 3.5"
    #
    # [maintainer]
    # url = "http://example.com"
    # name = "John doe"
    # email = "john.doe@example.com"
    #
    # [description]
    # fr = "Exemple de package d'application pour YunoHost."
    # en = "Example package for YunoHost application."
    #
    # [arguments]
    #     [arguments.install.domain]
    #     type = "domain"
    #     example = "example.com"
    #         [arguments.install.domain.ask]
    #         fr = "Choisissez un nom de domaine pour ynhexample"
    #         en = "Choose a domain name for ynhexample"
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'license', u'free'),
    #              (u'url', u'https://example.com'),
    #              (u'multi_instance', True),
    #              (u'version', u'1.0~ynh1'),
    #              (u'packaging_format', 1),
    #              (u'services', [u'nginx', u'php7.0-fpm', u'mysql']),
    #              (u'id', u'ynhexample'),
    #              (u'name', u'YunoHost example app'),
    #              (u'requirements', OrderedDict([(u'yunohost', u'>= 3.5')])),
    #              (u'maintainer',
    #               OrderedDict([(u'url', u'http://example.com'),
    #                            (u'name', u'John doe'),
    #                            (u'email', u'john.doe@example.com')])),
    #              (u'description',
    #               OrderedDict([(u'fr',
    #                             u"Exemple de package d'application pour YunoHost."),
    #                            (u'en',
    #                             u'Example package for YunoHost application.')])),
    #              (u'arguments',
    #               OrderedDict([(u'install',
    #                             OrderedDict([(u'domain',
    #                                           OrderedDict([(u'type', u'domain'),
    #                                                        (u'example',
    #                                                         u'example.com'),
    #                                                        (u'ask',
    #                                                         OrderedDict([(u'fr',
    #                                                                       u'Choisissez un nom de domaine pour ynhexample'),
    #                                                                      (u'en',
    #                                                                       u'Choose a domain name for ynhexample')]))])),
    #
    # and needs to be converted into this:
    #
    # {
    #     "name": "YunoHost example app",
    #     "id": "ynhexample",
    #     "packaging_format": 1,
    #     "description": {
    #     ¦   "en": "Example package for YunoHost application.",
    #     ¦   "fr": "Exemple de package d’application pour YunoHost."
    #     },
    #     "version": "1.0~ynh1",
    #     "url": "https://example.com",
    #     "license": "free",
    #     "maintainer": {
    #     ¦   "name": "John doe",
    #     ¦   "email": "john.doe@example.com",
    #     ¦   "url": "http://example.com"
    #     },
    #     "requirements": {
    #     ¦   "yunohost": ">= 3.5"
    #     },
    #     "multi_instance": true,
    #     "services": [
    #     ¦   "nginx",
    #     ¦   "php7.0-fpm",
    #     ¦   "mysql"
    #     ],
    #     "arguments": {
    #     ¦   "install" : [
    #     ¦   ¦   {
    #     ¦   ¦   ¦   "name": "domain",
    #     ¦   ¦   ¦   "type": "domain",
    #     ¦   ¦   ¦   "ask": {
    #     ¦   ¦   ¦   ¦   "en": "Choose a domain name for ynhexample",
    #     ¦   ¦   ¦   ¦   "fr": "Choisissez un nom de domaine pour ynhexample"
    #     ¦   ¦   ¦   },
    #     ¦   ¦   ¦   "example": "example.com"
    #     ¦   ¦   },

    if os.path.exists(os.path.join(path, "manifest.toml")):
        manifest = read_toml(os.path.join(path, "manifest.toml"))
    elif os.path.exists(os.path.join(path, "manifest.json")):
        manifest = read_json(os.path.join(path, "manifest.json"))
    else:
        raise YunohostError(
            f"There doesn't seem to be any manifest file in {path} ... It looks like an app was not correctly installed/removed.",
            raw_msg=True,
        )

    manifest["packaging_format"] = float(
        str(manifest.get("packaging_format", "")).strip() or "0"
    )

    if manifest["packaging_format"] < 2:
        manifest = _convert_v1_manifest_to_v2(manifest)

    manifest["install"] = _set_default_ask_questions(manifest.get("install", {}))
    manifest["doc"], manifest["notifications"] = _parse_app_doc_and_notifications(path)

    return manifest


def _parse_app_doc_and_notifications(path):

    doc = {}

    for filepath in glob.glob(os.path.join(path, "doc") + "/*.md"):

        # to be improved : [a-z]{2,3} is a clumsy way of parsing the
        # lang code ... some lang code are more complex that this é_è
        m = re.match("([A-Z]*)(_[a-z]{2,3})?.md", filepath.split("/")[-1])

        if not m:
            # FIXME: shall we display a warning ? idk
            continue
        pagename, lang = m.groups()
        lang = lang.strip("_") if lang else "en"

        if pagename not in doc:
            doc[pagename] = {}
        doc[pagename][lang] = read_file(filepath).strip()

    notifications = {}

    for step in ["pre_install", "post_install", "pre_upgrade", "post_upgrade"]:
        notifications[step] = {}
        for filepath in glob.glob(
            os.path.join(path, "doc", "notifications", f"{step}*.md")
        ):
            m = re.match(step + "(_[a-z]{2,3})?.md", filepath.split("/")[-1])
            if not m:
                continue
            pagename = "main"
            lang = m.groups()[0].strip("_") if m.groups()[0] else "en"
            if pagename not in notifications[step]:
                notifications[step][pagename] = {}
            notifications[step][pagename][lang] = read_file(filepath).strip()

        for filepath in glob.glob(
            os.path.join(path, "doc", "notifications", f"{step}.d") + "/*.md"
        ):
            m = re.match(
                r"([A-Za-z0-9\.\~]*)(_[a-z]{2,3})?.md", filepath.split("/")[-1]
            )
            if not m:
                continue
            pagename, lang = m.groups()
            lang = lang.strip("_") if lang else "en"
            if pagename not in notifications[step]:
                notifications[step][pagename] = {}
            notifications[step][pagename][lang] = read_file(filepath).strip()

    return doc, notifications


def _hydrate_app_template(template, data):

    stuff_to_replace = set(re.findall(r"__[A-Z0-9]+?[A-Z0-9_]*?[A-Z0-9]*?__", template))

    for stuff in stuff_to_replace:

        varname = stuff.strip("_").lower()

        if varname in data:
            template = template.replace(stuff, data[varname])

    return template


def _convert_v1_manifest_to_v2(manifest):

    manifest = copy.deepcopy(manifest)

    if "upstream" not in manifest:
        manifest["upstream"] = {}

    if "license" in manifest and "license" not in manifest["upstream"]:
        manifest["upstream"]["license"] = manifest["license"]

    if "url" in manifest and "website" not in manifest["upstream"]:
        manifest["upstream"]["website"] = manifest["url"]

    manifest["integration"] = {
        "yunohost": manifest.get("requirements", {})
        .get("yunohost", "")
        .replace(">", "")
        .replace("=", "")
        .replace(" ", ""),
        "architectures": "?",
        "multi_instance": manifest.get("multi_instance", False),
        "ldap": "?",
        "sso": "?",
        "disk": "?",
        "ram": {"build": "?", "runtime": "?"},
    }

    maintainers = manifest.get("maintainer", {})
    if isinstance(maintainers, list):
        maintainers = [m["name"] for m in maintainers]
    else:
        maintainers = [maintainers["name"]] if maintainers.get("name") else []

    manifest["maintainers"] = maintainers

    install_questions = manifest["arguments"]["install"]

    manifest["install"] = {}
    for question in install_questions:
        name = question.pop("name")
        if "ask" in question and name in [
            "domain",
            "path",
            "admin",
            "is_public",
            "password",
        ]:
            question.pop("ask")
        if question.get("example") and question.get("type") in [
            "domain",
            "path",
            "user",
            "boolean",
            "password",
        ]:
            question.pop("example")

        manifest["install"][name] = question

    manifest["resources"] = {"system_user": {}, "install_dir": {"alias": "final_path"}}

    keys_to_keep = [
        "packaging_format",
        "id",
        "name",
        "description",
        "version",
        "maintainers",
        "upstream",
        "integration",
        "install",
        "resources",
    ]

    keys_to_del = [key for key in manifest.keys() if key not in keys_to_keep]
    for key in keys_to_del:
        del manifest[key]

    return manifest


def _set_default_ask_questions(questions, script_name="install"):

    # arguments is something like
    # { "domain":
    #       {
    #         "type": "domain",
    #         ....
    #       },
    #    "path": {
    #         "type": "path",
    #         ...
    #       },
    #       ...
    # }

    # We set a default for any question with these matching (type, name)
    #                           type       namei
    # N.B. : this is only for install script ... should be reworked for other
    # scripts if we supports args for other scripts in the future...
    questions_with_default = [
        ("domain", "domain"),  # i18n: app_manifest_install_ask_domain
        ("path", "path"),  # i18n: app_manifest_install_ask_path
        ("password", "password"),  # i18n: app_manifest_install_ask_password
        ("user", "admin"),  # i18n: app_manifest_install_ask_admin
        ("boolean", "is_public"),  # i18n: app_manifest_install_ask_is_public
        (
            "group",
            "init_main_permission",
        ),  # i18n: app_manifest_install_ask_init_main_permission
        (
            "group",
            "init_admin_permission",
        ),  # i18n: app_manifest_install_ask_init_admin_permission
    ]

    for question_name, question in questions.items():
        question["name"] = question_name

        # If this question corresponds to a question with default ask message...
        if any(
            (question.get("type"), question["name"]) == question_with_default
            for question_with_default in questions_with_default
        ):
            # The key is for example "app_manifest_install_ask_domain"
            question["ask"] = m18n.n(
                f"app_manifest_{script_name}_ask_{question['name']}"
            )

            # Also it in fact doesn't make sense for any of those questions to have an example value nor a default value...
            if question.get("type") in ["domain", "user", "password"]:
                if "example" in question:
                    del question["example"]
                if "default" in question:
                    del question["default"]

    return questions


def _is_app_repo_url(string: str) -> bool:

    string = string.strip()

    # Dummy test for ssh-based stuff ... should probably be improved somehow
    if "@" in string:
        return True

    return bool(APP_REPO_URL.match(string))


def _app_quality(src: str) -> str:
    """
    app may in fact be an app name, an url, or a path
    """

    raw_app_catalog = _load_apps_catalog()["apps"]
    if src in raw_app_catalog or _is_app_repo_url(src):

        # If we got an app name directly (e.g. just "wordpress"), we gonna test this name
        if src in raw_app_catalog:
            app_name_to_test = src
        # If we got an url like "https://github.com/foo/bar_ynh, we want to
        # extract "bar" and test if we know this app
        elif ("http://" in src) or ("https://" in src):
            app_name_to_test = src.strip("/").split("/")[-1].replace("_ynh", "")
        else:
            # FIXME : watdo if '@' in app ?
            return "thirdparty"

        if app_name_to_test in raw_app_catalog:

            state = raw_app_catalog[app_name_to_test].get("state", "notworking")
            level = raw_app_catalog[app_name_to_test].get("level", None)
            if state in ["working", "validated"]:
                if isinstance(level, int) and level >= 5:
                    return "success"
                elif isinstance(level, int) and level > 0:
                    return "warning"
            return "danger"
        else:
            return "thirdparty"

    elif os.path.exists(src):
        return "thirdparty"
    else:
        if "http://" in src or "https://" in src:
            logger.error(
                f"{src} is not a valid app url: app url are expected to look like https://domain.tld/path/to/repo_ynh"
            )
        raise YunohostValidationError("app_unknown")


def _extract_app(src: str) -> Tuple[Dict, str]:
    """
    src may be an app name, an url, or a path
    """

    raw_app_catalog = _load_apps_catalog()["apps"]

    # App is an appname in the catalog
    if src in raw_app_catalog:
        if "git" not in raw_app_catalog[src]:
            raise YunohostValidationError("app_unsupported_remote_type")

        app_info = raw_app_catalog[src]
        url = app_info["git"]["url"]
        branch = app_info["git"]["branch"]
        revision = str(app_info["git"]["revision"])
        return _extract_app_from_gitrepo(url, branch, revision, app_info)
    # App is a git repo url
    elif _is_app_repo_url(src):
        url = src.strip().strip("/")
        branch = "master"
        revision = "HEAD"
        # gitlab urls may look like 'https://domain/org/group/repo/-/tree/testing'
        # compated to github urls looking like 'https://domain/org/repo/tree/testing'
        if "/-/" in url:
            url = url.replace("/-/", "/")
        if "/tree/" in url:
            url, branch = url.split("/tree/", 1)
        return _extract_app_from_gitrepo(url, branch, revision, {})
    # App is a local folder
    elif os.path.exists(src):
        return _extract_app_from_folder(src)
    else:
        if "http://" in src or "https://" in src:
            logger.error(
                f"{src} is not a valid app url: app url are expected to look like https://domain.tld/path/to/repo_ynh"
            )
        raise YunohostValidationError("app_unknown")


def _extract_app_from_folder(path: str) -> Tuple[Dict, str]:
    """
    Unzip / untar / copy application tarball or directory to a tmp work directory

    Keyword arguments:
        path -- Path of the tarball or directory
    """
    logger.debug(m18n.n("extracting"))

    path = os.path.abspath(path)

    extracted_app_folder = _make_tmp_workdir_for_app()

    if os.path.isdir(path):
        shutil.rmtree(extracted_app_folder)
        if path[-1] != "/":
            path = path + "/"
        cp(path, extracted_app_folder, recursive=True)
    else:
        try:
            shutil.unpack_archive(path, extracted_app_folder)
        except Exception:
            raise YunohostError("app_extraction_failed")

    try:
        if len(os.listdir(extracted_app_folder)) == 1:
            for folder in os.listdir(extracted_app_folder):
                extracted_app_folder = extracted_app_folder + "/" + folder
    except IOError:
        raise YunohostError("app_install_files_invalid")

    manifest = _get_manifest_of_app(extracted_app_folder)
    manifest["lastUpdate"] = int(time.time())

    logger.debug(m18n.n("done"))

    manifest["remote"] = {"type": "file", "path": path}
    manifest["quality"] = {"level": -1, "state": "thirdparty"}
    manifest["antifeatures"] = []
    manifest["potential_alternative_to"] = []

    return manifest, extracted_app_folder


def _extract_app_from_gitrepo(
    url: str, branch: str, revision: str, app_info: Dict = {}
) -> Tuple[Dict, str]:

    logger.debug(m18n.n("downloading"))

    extracted_app_folder = _make_tmp_workdir_for_app()

    # Download only this commit
    try:
        # We don't use git clone because, git clone can't download
        # a specific revision only
        ref = branch if revision == "HEAD" else revision
        run_commands([["git", "init", extracted_app_folder]], shell=False)
        run_commands(
            [
                ["git", "remote", "add", "origin", url],
                ["git", "fetch", "--depth=1", "origin", ref],
                ["git", "reset", "--hard", "FETCH_HEAD"],
            ],
            cwd=extracted_app_folder,
            shell=False,
        )
    except subprocess.CalledProcessError:
        raise YunohostError("app_sources_fetch_failed")
    else:
        logger.debug(m18n.n("done"))

    manifest = _get_manifest_of_app(extracted_app_folder)

    # Store remote repository info into the returned manifest
    manifest["remote"] = {"type": "git", "url": url, "branch": branch}
    if revision == "HEAD":
        try:
            # Get git last commit hash
            cmd = f"git ls-remote --exit-code {url} {branch} | awk '{{print $1}}'"
            manifest["remote"]["revision"] = check_output(cmd)
        except Exception as e:
            logger.warning(f"cannot get last commit hash because: {e}")
    else:
        manifest["remote"]["revision"] = revision
        manifest["lastUpdate"] = app_info.get("lastUpdate")

    manifest["quality"] = {
        "level": app_info.get("level", -1),
        "state": app_info.get("state", "thirdparty"),
    }
    manifest["antifeatures"] = app_info.get("antifeatures", [])
    manifest["potential_alternative_to"] = app_info.get("potential_alternative_to", [])

    return manifest, extracted_app_folder


def _list_upgradable_apps():
    upgradable_apps = list(app_list(upgradable=True)["apps"])

    # Retrieve next manifest pre_upgrade notifications
    for app in upgradable_apps:
        absolute_app_name, _ = _parse_app_instance_name(app["id"])
        manifest, extracted_app_folder = _extract_app(absolute_app_name)
        current_version = version.parse(app["current_version"])
        app["notifications"] = {}
        if manifest["notifications"]["pre_upgrade"]:
            app["notifications"]["pre_upgrade"] = _filter_and_hydrate_notifications(
                manifest["notifications"]["pre_upgrade"],
                current_version,
                app["settings"],
            )
        del app["settings"]
        shutil.rmtree(extracted_app_folder)

    return upgradable_apps


#
# ############################### #
#        Small utilities          #
# ############################### #
#


def _is_installed(app: str) -> bool:
    """
    Check if application is installed

    Keyword arguments:
        app -- id of App to check

    Returns:
        Boolean

    """
    return os.path.isdir(APPS_SETTING_PATH + app)


def _assert_is_installed(app: str) -> None:
    if not _is_installed(app):
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )


def _installed_apps() -> List[str]:
    return os.listdir(APPS_SETTING_PATH)


def _get_all_installed_apps_id():
    """
    Return something like:
       ' * app1
         * app2
         * ...'
    """

    all_apps_ids = sorted(_installed_apps())

    all_apps_ids_formatted = "\n * ".join(all_apps_ids)
    all_apps_ids_formatted = "\n * " + all_apps_ids_formatted

    return all_apps_ids_formatted


def _check_manifest_requirements(
    manifest: Dict, action: str = ""
) -> Iterator[Tuple[str, bool, object, str]]:
    """Check if required packages are met from the manifest"""

    app_id = manifest["id"]
    logger.debug(m18n.n("app_requirements_checking", app=app_id))

    # Packaging format
    if manifest["packaging_format"] not in [1, 2]:
        raise YunohostValidationError("app_packaging_format_not_supported")

    # Yunohost version
    required_yunohost_version = manifest["integration"].get("yunohost", "4.3").strip(">= ")
    current_yunohost_version = get_ynh_package_version("yunohost")["version"]

    yield (
        "required_yunohost_version",
        version.parse(required_yunohost_version)
        <= version.parse(current_yunohost_version),
        {"current": current_yunohost_version, "required": required_yunohost_version},
        "app_yunohost_version_not_supported",  # i18n: app_yunohost_version_not_supported
    )

    # Architectures
    arch_requirement = manifest["integration"]["architectures"]
    arch = system_arch()

    yield (
        "arch",
        arch_requirement in ["all", "?"] or arch in arch_requirement,
        {"current": arch, "required": arch_requirement},
        "app_arch_not_supported",  # i18n: app_arch_not_supported
    )

    # Multi-instance
    if action == "install":
        multi_instance = manifest["integration"]["multi_instance"] is True
        if not multi_instance:
            apps = _installed_apps()
            sibling_apps = [
                a for a in apps if a == app_id or a.startswith(f"{app_id}__")
            ]
            multi_instance = len(sibling_apps) == 0

        yield (
            "install",
            multi_instance,
            {"app": app_id},
            "app_already_installed",  # i18n: app_already_installed
        )

    # Disk
    if action == "install":
        root_free_space = free_space_in_directory("/")
        var_free_space = free_space_in_directory("/var")
        if manifest["integration"]["disk"] == "?":
            has_enough_disk = True
        else:
            disk_req_bin = human_to_binary(manifest["integration"]["disk"])
            has_enough_disk = (
                root_free_space > disk_req_bin and var_free_space > disk_req_bin
            )
        free_space = binary_to_human(min(root_free_space, var_free_space))

        yield (
            "disk",
            has_enough_disk,
            {"current": free_space, "required": manifest["integration"]["disk"]},
            "app_not_enough_disk",  # i18n: app_not_enough_disk
        )

    # Ram
    ram_requirement = manifest["integration"]["ram"]
    ram, swap = ram_available()
    # Is "include_swap" really useful ? We should probably decide wether to always include it or not instead
    if ram_requirement.get("include_swap", False):
        ram += swap
    can_build = ram_requirement["build"] == "?" or ram > human_to_binary(ram_requirement["build"])
    can_run = ram_requirement["runtime"] == "?" or ram > human_to_binary(ram_requirement["runtime"])

    yield (
        "ram",
        can_build and can_run,
        {"current": binary_to_human(ram), "required": ram_requirement["build"]},
        "app_not_enough_ram",  # i18n: app_not_enough_ram
    )


def _guess_webapp_path_requirement(app_folder: str) -> str:

    # If there's only one "domain" and "path", validate that domain/path
    # is an available url and normalize the path.

    manifest = _get_manifest_of_app(app_folder)
    raw_questions = manifest["install"]

    domain_questions = [
        question
        for question in raw_questions.values()
        if question.get("type") == "domain"
    ]
    path_questions = [
        question
        for question in raw_questions.values()
        if question.get("type") == "path"
    ]

    if len(domain_questions) == 0 and len(path_questions) == 0:
        return ""
    if len(domain_questions) == 1 and len(path_questions) == 1:
        return "domain_and_path"
    if len(domain_questions) == 1 and len(path_questions) == 0:
        # This is likely to be a full-domain app...

        # Confirm that this is a full-domain app This should cover most cases
        # ...  though anyway the proper solution is to implement some mechanism
        # in the manifest for app to declare that they require a full domain
        # (among other thing) so that we can dynamically check/display this
        # requirement on the webadmin form and not miserably fail at submit time

        # Full-domain apps typically declare something like path_url="/" or path=/
        # and use ynh_webpath_register or yunohost_app_checkurl inside the install script
        install_script_content = read_file(os.path.join(app_folder, "scripts/install"))

        if re.search(
            r"\npath(_url)?=[\"']?/[\"']?", install_script_content
        ) and re.search(r"ynh_webpath_register", install_script_content):
            return "full_domain"

    return "?"


def _validate_webpath_requirement(
    args: Dict[str, Any], path_requirement: str, ignore_app=None
) -> None:

    domain = args.get("domain")
    path = args.get("path")

    if path_requirement == "domain_and_path":
        _assert_no_conflicting_apps(domain, path, ignore_app=ignore_app)

    elif path_requirement == "full_domain":
        _assert_no_conflicting_apps(
            domain, "/", full_domain=True, ignore_app=ignore_app
        )


def _get_conflicting_apps(domain, path, ignore_app=None):
    """
    Return a list of all conflicting apps with a domain/path (it can be empty)

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
        ignore_app -- An optional app id to ignore (c.f. the change_url usecase)
    """

    from yunohost.domain import _assert_domain_exists

    domain = DomainQuestion.normalize(domain)
    path = PathQuestion.normalize(path)

    # Abort if domain is unknown
    _assert_domain_exists(domain)

    # Fetch apps map
    apps_map = app_map(raw=True)

    # Loop through all apps to check if path is taken by one of them
    conflicts = []
    if domain in apps_map:
        # Loop through apps
        for p, a in apps_map[domain].items():
            if a["id"] == ignore_app:
                continue
            if path == p or path == "/" or p == "/":
                conflicts.append((p, a["id"], a["label"]))

    return conflicts


def _assert_no_conflicting_apps(domain, path, ignore_app=None, full_domain=False):

    conflicts = _get_conflicting_apps(domain, path, ignore_app)

    if conflicts:
        apps = []
        for path, app_id, app_label in conflicts:
            apps.append(f" * {domain}{path} → {app_label} ({app_id})")

        if full_domain:
            raise YunohostValidationError("app_full_domain_unavailable", domain=domain)
        else:
            raise YunohostValidationError(
                "app_location_unavailable", apps="\n".join(apps)
            )


def _make_environment_for_app_script(
    app, args={}, args_prefix="APP_ARG_", workdir=None, action=None
):

    app_setting_path = os.path.join(APPS_SETTING_PATH, app)

    manifest = _get_manifest_of_app(app_setting_path)
    app_id, app_instance_nb = _parse_app_instance_name(app)

    env_dict = {
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
        "YNH_APP_MANIFEST_VERSION": manifest.get("version", "?"),
        "YNH_APP_PACKAGING_FORMAT": str(manifest["packaging_format"]),
        "YNH_ARCH": system_arch(),
    }

    if workdir:
        env_dict["YNH_APP_BASEDIR"] = workdir

    if action:
        env_dict["YNH_APP_ACTION"] = action

    for arg_name, arg_value in args.items():
        arg_name_upper = arg_name.upper()
        env_dict[f"YNH_{args_prefix}{arg_name_upper}"] = str(arg_value)

    # If packaging format v2, load all settings
    if manifest["packaging_format"] >= 2:
        env_dict["app"] = app
        for setting_name, setting_value in _get_app_settings(app).items():

            # Ignore special internal settings like checksum__
            # (not a huge deal to load them but idk...)
            if setting_name.startswith("checksum__"):
                continue

            env_dict[setting_name] = str(setting_value)

        # Special weird case for backward compatibility...
        # 'path' was loaded into 'path_url' .....
        if "path" in env_dict:
            env_dict["path_url"] = env_dict["path"]

    return env_dict


def _parse_app_instance_name(app_instance_name: str) -> Tuple[str, int]:
    """
    Parse a Yunohost app instance name and extracts the original appid
    and the application instance number

    'yolo'      -> ('yolo', 1)
    'yolo1'     -> ('yolo1', 1)
    'yolo__0'   -> ('yolo__0', 1)
    'yolo__1'   -> ('yolo', 1)
    'yolo__23'  -> ('yolo', 23)
    'yolo__42__72'    -> ('yolo__42', 72)
    'yolo__23qdqsd'   -> ('yolo__23qdqsd', 1)
    'yolo__23qdqsd56' -> ('yolo__23qdqsd56', 1)
    """
    match = re_app_instance_name.match(app_instance_name)
    assert match, f"Could not parse app instance name : {app_instance_name}"
    appid = match.groupdict().get("appid")
    app_instance_nb_ = match.groupdict().get("appinstancenb") or "1"
    if not appid:
        raise Exception(f"Could not parse app instance name : {app_instance_name}")
    if not str(app_instance_nb_).isdigit():
        raise Exception(f"Could not parse app instance name : {app_instance_name}")
    else:
        app_instance_nb = int(str(app_instance_nb_))

    return (appid, app_instance_nb)


def _next_instance_number_for_app(app):

    # Get list of sibling apps, such as {app}, {app}__2, {app}__4
    apps = _installed_apps()
    sibling_app_ids = [a for a in apps if a == app or a.startswith(f"{app}__")]

    # Find the list of ids, such as [1, 2, 4]
    sibling_ids = [_parse_app_instance_name(a)[1] for a in sibling_app_ids]

    # Find the first 'i' that's not in the sibling_ids list already
    i = 1
    while True:
        if i not in sibling_ids:
            return i
        else:
            i += 1


def _make_tmp_workdir_for_app(app=None):

    # Create parent dir if it doesn't exists yet
    if not os.path.exists(APP_TMP_WORKDIRS):
        os.makedirs(APP_TMP_WORKDIRS)

    now = int(time.time())

    # Cleanup old dirs (if any)
    for dir_ in os.listdir(APP_TMP_WORKDIRS):
        path = os.path.join(APP_TMP_WORKDIRS, dir_)
        # We only delete folders older than an arbitary 12 hours
        # This is to cover the stupid case of upgrades
        # Where many app will call 'yunohost backup create'
        # from the upgrade script itself,
        # which will also call this function while the upgrade
        # script itself is running in one of those dir...
        # It could be that there are other edge cases
        # such as app-install-during-app-install
        if os.stat(path).st_mtime < now - 12 * 3600:
            shutil.rmtree(path)
    tmpdir = tempfile.mkdtemp(prefix="app_", dir=APP_TMP_WORKDIRS)

    # Copy existing app scripts, conf, ... if an app arg was provided
    if app:
        os.system(f"cp -a {APPS_SETTING_PATH}/{app}/* {tmpdir}")

    return tmpdir


def unstable_apps():

    output = []
    deprecated_apps = ["mailman", "ffsync"]

    for infos in app_list(full=True)["apps"]:

        if (
            not infos.get("from_catalog")
            or infos.get("from_catalog").get("state")
            in [
                "inprogress",
                "notworking",
            ]
            or infos["id"] in deprecated_apps
        ):
            output.append(infos["id"])

    return output


def _assert_system_is_sane_for_app(manifest, when):

    from yunohost.service import service_status

    logger.debug("Checking that required services are up and running...")

    services = manifest.get("services", [])

    # Some apps use php-fpm, php5-fpm or php7.x-fpm which is now php7.4-fpm
    def replace_alias(service):
        if service in ["php-fpm", "php5-fpm", "php7.0-fpm", "php7.3-fpm"]:
            return "php7.4-fpm"
        else:
            return service

    services = [replace_alias(s) for s in services]

    # We only check those, mostly to ignore "custom" services
    # (added by apps) and because those are the most popular
    # services
    service_filter = ["nginx", "php7.4-fpm", "mysql", "postfix"]
    services = [str(s) for s in services if s in service_filter]

    if "nginx" not in services:
        services = ["nginx"] + services
    if "fail2ban" not in services:
        services.append("fail2ban")

    # Wait if a service is reloading
    test_nb = 0

    while test_nb < 16:
        if not any(s for s in services if service_status(s)["status"] == "reloading"):
            break
        time.sleep(0.5)
        test_nb += 1

    # List services currently down and raise an exception if any are found
    services_status = {s: service_status(s) for s in services}
    faulty_services = [
        f"{s} ({status['status']})"
        for s, status in services_status.items()
        if status["status"] != "running"
    ]

    if faulty_services:
        if when == "pre":
            raise YunohostValidationError(
                "app_action_cannot_be_ran_because_required_services_down",
                services=", ".join(faulty_services),
            )
        elif when == "post":
            raise YunohostError(
                "app_action_broke_system", services=", ".join(faulty_services)
            )

    if dpkg_is_broken():
        if when == "pre":
            raise YunohostValidationError("dpkg_is_broken")
        elif when == "post":
            raise YunohostError("this_action_broke_dpkg")


def _filter_and_hydrate_notifications(notifications, current_version=None, data={}):
    return {
        # Should we render the markdown maybe? idk
        name: _hydrate_app_template(_value_for_locale(content_per_lang), data)
        for name, content_per_lang in notifications.items()
        if current_version is None
        or name == "main"
        or version.parse(name) > current_version
    }


def _display_notifications(notifications, force=False):
    if not notifications:
        return

    for name, content in notifications.items():
        print(f"========== {name}")
        print(content)
    print("==========")

    _ask_confirmation("confirm_notifications_read", kind="simple", force=force)


# FIXME: move this to Moulinette
def _ask_confirmation(
    question: str,
    params: dict = {},
    kind: str = "hard",
    force: bool = False,
):
    """
    Ask confirmation

    Keyword argument:
        question -- m18n key or string
        params -- dict of values passed to the string formating
        kind -- "hard": ask with "Yes, I understand", "soft": "Y/N", "simple": "press enter"
        force -- Will not ask for confirmation

    """
    if force or Moulinette.interface.type == "api":
        return

    # If ran from the CLI in a non-interactive context,
    # skip confirmation (except in hard mode)
    if not os.isatty(1) and kind in ["simple", "soft"]:
        return
    if kind == "simple":
        answer = Moulinette.prompt(
            m18n.n(question, answers="Press enter to continue", **params),
            color="yellow",
        )
        answer = True
    elif kind == "soft":
        answer = Moulinette.prompt(
            m18n.n(question, answers="Y/N", **params), color="yellow"
        )
        answer = answer.upper() == "Y"
    else:
        answer = Moulinette.prompt(
            m18n.n(question, answers="Yes, I understand", **params), color="red"
        )
        answer = answer == "Yes, I understand"

    if not answer:
        raise YunohostError("aborting")
