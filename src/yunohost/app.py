# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_app.py

    Manage apps
"""
import os
import toml
import json
import shutil
import yaml
import time
import re
import subprocess
import glob
import urllib.parse
import tempfile
from collections import OrderedDict

from moulinette import msignals, m18n, msettings
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.network import download_json
from moulinette.utils.process import run_commands, check_output
from moulinette.utils.filesystem import (
    read_file,
    read_json,
    read_toml,
    read_yaml,
    write_to_file,
    write_to_json,
    write_to_yaml,
    mkdir,
)

from yunohost.service import service_status, _run_service_command
from yunohost.utils import packages
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.log import is_unit_operation, OperationLogger

logger = getActionLogger("yunohost.app")

APPS_SETTING_PATH = "/etc/yunohost/apps/"
APP_TMP_WORKDIRS = "/var/cache/yunohost/app_tmp_work_dirs"

APPS_CATALOG_CACHE = "/var/cache/yunohost/repo"
APPS_CATALOG_CONF = "/etc/yunohost/apps_catalog.yml"
APPS_CATALOG_API_VERSION = 2
APPS_CATALOG_DEFAULT_URL = "https://app.yunohost.org/default"

re_app_instance_name = re.compile(
    r"^(?P<appid>[\w-]+?)(__(?P<appinstancenb>[1-9][0-9]*))?$"
)


def app_catalog(full=False, with_categories=False):
    """
    Return a dict of apps available to installation from Yunohost's app catalog
    """

    # Get app list from catalog cache
    catalog = _load_apps_catalog()
    installed_apps = set(_installed_apps())

    # Trim info for apps if not using --full
    for app, infos in catalog["apps"].items():
        infos["installed"] = app in installed_apps

        infos["manifest"]["description"] = _value_for_locale(
            infos["manifest"]["description"]
        )

        if not full:
            catalog["apps"][app] = {
                "description": infos["manifest"]["description"],
                "level": infos["level"],
            }
        else:
            infos["manifest"]["arguments"] = _set_default_ask_questions(
                infos["manifest"].get("arguments", {})
            )

    # Trim info for categories if not using --full
    for category in catalog["categories"]:
        category["title"] = _value_for_locale(category["title"])
        category["description"] = _value_for_locale(category["description"])
        for subtags in category.get("subtags", []):
            subtags["title"] = _value_for_locale(subtags["title"])

    if not full:
        catalog["categories"] = [
            {"id": c["id"], "description": c["description"]}
            for c in catalog["categories"]
        ]

    if not with_categories:
        return {"apps": catalog["apps"]}
    else:
        return {"apps": catalog["apps"], "categories": catalog["categories"]}


def app_search(string):
    """
    Return a dict of apps whose description or name match the search string
    """

    # Retrieve a simple dict listing all apps
    catalog_of_apps = app_catalog()

    # Selecting apps according to a match in app name or description
    matching_apps = {"apps": {}}
    for app in catalog_of_apps["apps"].items():
        if re.search(string, app[0], flags=re.IGNORECASE) or re.search(
            string, app[1]["description"], flags=re.IGNORECASE
        ):
            matching_apps["apps"][app[0]] = app[1]

    return matching_apps


# Old legacy function...
def app_fetchlist():
    logger.warning(
        "'yunohost app fetchlist' is deprecated. Please use 'yunohost tools update --apps' instead"
    )
    from yunohost.tools import tools_update

    tools_update(target="apps")


def app_list(full=False, installed=False, filter=None):
    """
    List installed apps
    """

    # Old legacy argument ... app_list was a combination of app_list and
    # app_catalog before 3.8 ...
    if installed:
        logger.warning(
            "Argument --installed ain't needed anymore when using 'yunohost app list'. It directly returns the list of installed apps.."
        )

    # Filter is a deprecated option...
    if filter:
        logger.warning(
            "Using -f $appname in 'yunohost app list' is deprecated. Just use 'yunohost app list | grep -q 'id: $appname' to check a specific app is installed"
        )

    out = []
    for app_id in sorted(_installed_apps()):

        if filter and not app_id.startswith(filter):
            continue

        try:
            app_info_dict = app_info(app_id, full=full)
        except Exception as e:
            logger.error("Failed to read info for %s : %s" % (app_id, e))
            continue
        app_info_dict["id"] = app_id
        out.append(app_info_dict)

    return {"apps": out}


def app_info(app, full=False):
    """
    Get info for a specific app
    """
    from yunohost.permission import user_permission_list

    if not _is_installed(app):
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )

    local_manifest = _get_manifest_of_app(os.path.join(APPS_SETTING_PATH, app))
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

    if not full:
        return ret

    ret["manifest"] = local_manifest
    ret["manifest"]["arguments"] = _set_default_ask_questions(
        ret["manifest"].get("arguments", {})
    )
    ret["settings"] = settings

    absolute_app_name, _ = _parse_app_instance_name(app)
    ret["from_catalog"] = _load_apps_catalog()["apps"].get(absolute_app_name, {})
    ret["upgradable"] = _app_upgradable(ret)
    ret["supports_change_url"] = os.path.exists(
        os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url")
    )
    ret["supports_backup_restore"] = os.path.exists(
        os.path.join(APPS_SETTING_PATH, app, "scripts", "backup")
    ) and os.path.exists(os.path.join(APPS_SETTING_PATH, app, "scripts", "restore"))
    ret["supports_multi_instance"] = is_true(
        local_manifest.get("multi_instance", False)
    )

    ret["permissions"] = permissions
    ret["label"] = permissions.get(app + ".main", {}).get("label")

    if not ret["label"]:
        logger.warning("Failed to get label for app %s ?" % app)
    return ret


def _app_upgradable(app_infos):
    from packaging import version

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
    for app_id in apps:
        app_settings = _get_app_settings(app_id)
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
            if not app_id + ".main" in permissions:
                logger.warning(
                    "Uhoh, no main permission was found for app %s ... sounds like an app was only partially removed due to another bug :/"
                    % app_id
                )
                continue
            main_perm = permissions[app_id + ".main"]
            if user not in main_perm["corresponding_users"]:
                continue

        this_app_perms = {
            p: i
            for p, i in permissions.items()
            if p.startswith(app_id + ".") and (i["url"] or i["additional_urls"])
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
                    result[perm_domain][perm_path] = {"label": perm_label, "id": app_id}

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
    old_domain, old_path = _normalize_domain_path(old_domain, old_path)
    domain, path = _normalize_domain_path(domain, path)

    if (domain, path) == (old_domain, old_path):
        raise YunohostValidationError(
            "app_change_url_identical_domains", domain=domain, path=path
        )

    # Check the url is available
    _assert_no_conflicting_apps(domain, path, ignore_app=app)

    manifest = _get_manifest_of_app(os.path.join(APPS_SETTING_PATH, app))

    # Retrieve arguments list for change_url script
    # TODO: Allow to specify arguments
    args_odict = _parse_args_from_manifest(manifest, "change_url")

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(app, args=args_odict)
    env_dict["YNH_APP_OLD_DOMAIN"] = old_domain
    env_dict["YNH_APP_OLD_PATH"] = old_path
    env_dict["YNH_APP_NEW_DOMAIN"] = domain
    env_dict["YNH_APP_NEW_PATH"] = path

    if domain != old_domain:
        operation_logger.related_to.append(("domain", old_domain))
    operation_logger.extra.update({"env": env_dict})
    operation_logger.start()

    tmp_workdir_for_app = _make_tmp_workdir_for_app(app=app)
    change_url_script = os.path.join(tmp_workdir_for_app, "scripts/change_url")

    # Execute App change_url script
    ret = hook_exec(change_url_script, env=env_dict)[0]
    if ret != 0:
        msg = "Failed to change '%s' url." % app
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

    # avoid common mistakes
    if _run_service_command("reload", "nginx") is False:
        # grab nginx errors
        # the "exit 0" is here to avoid check_output to fail because 'nginx -t'
        # will return != 0 since we are in a failed state
        nginx_errors = check_output("nginx -t; exit 0")
        raise YunohostError(
            "app_change_url_failed_nginx_reload", nginx_errors=nginx_errors
        )

    logger.success(m18n.n("app_change_url_success", app=app, domain=domain, path=path))

    hook_callback("post_app_change_url", env=env_dict)


def app_upgrade(app=[], url=None, file=None, force=False):
    """
    Upgrade app

    Keyword argument:
        file -- Folder or tarball for upgrade
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade

    """
    from packaging import version
    from yunohost.hook import hook_add, hook_remove, hook_exec, hook_callback
    from yunohost.permission import permission_sync_to_user
    from yunohost.regenconf import manually_modified_files

    apps = app
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
    for app in [app_ for app_ in apps if not _is_installed(app_)]:
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )

    if len(apps) == 0:
        raise YunohostValidationError("apps_already_up_to_date")
    if len(apps) > 1:
        logger.info(m18n.n("app_upgrade_several_apps", apps=", ".join(apps)))

    for number, app_instance_name in enumerate(apps):
        logger.info(m18n.n("app_upgrade_app_name", app=app_instance_name))

        app_dict = app_info(app_instance_name, full=True)

        if file and isinstance(file, dict):
            # We use this dirty hack to test chained upgrades in unit/functional tests
            manifest, extracted_app_folder = _extract_app_from_file(
                file[app_instance_name]
            )
        elif file:
            manifest, extracted_app_folder = _extract_app_from_file(file)
        elif url:
            manifest, extracted_app_folder = _fetch_app_from_git(url)
        elif app_dict["upgradable"] == "url_required":
            logger.warning(m18n.n("custom_app_url_required", app=app_instance_name))
            continue
        elif app_dict["upgradable"] == "yes" or force:
            manifest, extracted_app_folder = _fetch_app_from_git(app_instance_name)
        else:
            logger.success(m18n.n("app_already_up_to_date", app=app_instance_name))
            continue

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
        _check_manifest_requirements(manifest, app_instance_name=app_instance_name)
        _assert_system_is_sane_for_app(manifest, "pre")

        app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)

        # Retrieve arguments list for upgrade script
        # TODO: Allow to specify arguments
        args_odict = _parse_args_from_manifest(manifest, "upgrade")

        # Prepare env. var. to pass to script
        env_dict = _make_environment_for_app_script(app_instance_name, args=args_odict)
        env_dict["YNH_APP_UPGRADE_TYPE"] = upgrade_type
        env_dict["YNH_APP_MANIFEST_VERSION"] = str(app_new_version)
        env_dict["YNH_APP_CURRENT_VERSION"] = str(app_current_version)

        # We'll check that the app didn't brutally edit some system configuration
        manually_modified_files_before_install = manually_modified_files()

        # Attempt to patch legacy helpers ...
        _patch_legacy_helpers(extracted_app_folder)

        # Apply dirty patch to make php5 apps compatible with php7
        _patch_legacy_php_versions(extracted_app_folder)

        # Start register change on system
        related_to = [("app", app_instance_name)]
        operation_logger = OperationLogger("app_upgrade", related_to, env=env_dict)
        operation_logger.start()

        # Execute the app upgrade script
        upgrade_failed = True
        try:
            upgrade_retcode = hook_exec(
                extracted_app_folder + "/scripts/upgrade", env=env_dict
            )[0]

            upgrade_failed = True if upgrade_retcode != 0 else False
            if upgrade_failed:
                error = m18n.n("app_upgrade_script_failed")
                logger.error(
                    m18n.n("app_upgrade_failed", app=app_instance_name, error=error)
                )
                failure_message_with_debug_instructions = operation_logger.error(error)
                if msettings.get("interface") != "api":
                    dump_app_log_extract_for_debugging(operation_logger)
        # Script got manually interrupted ... N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            upgrade_retcode = -1
            error = m18n.n("operation_interrupted")
            logger.error(
                m18n.n("app_upgrade_failed", app=app_instance_name, error=error)
            )
            failure_message_with_debug_instructions = operation_logger.error(error)
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
            logger.error(
                m18n.n("app_install_failed", app=app_instance_name, error=error)
            )
            failure_message_with_debug_instructions = operation_logger.error(error)
        finally:
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
            os.system(
                'rm -rf "%s/scripts" "%s/manifest.toml %s/manifest.json %s/conf"'
                % (
                    app_setting_path,
                    app_setting_path,
                    app_setting_path,
                    app_setting_path,
                )
            )

            if os.path.exists(os.path.join(extracted_app_folder, "manifest.json")):
                os.system(
                    'mv "%s/manifest.json" "%s/scripts" %s'
                    % (extracted_app_folder, extracted_app_folder, app_setting_path)
                )
            if os.path.exists(os.path.join(extracted_app_folder, "manifest.toml")):
                os.system(
                    'mv "%s/manifest.toml" "%s/scripts" %s'
                    % (extracted_app_folder, extracted_app_folder, app_setting_path)
                )

            for file_to_copy in [
                "actions.json",
                "actions.toml",
                "config_panel.json",
                "config_panel.toml",
                "conf",
            ]:
                if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
                    os.system(
                        "cp -R %s/%s %s"
                        % (extracted_app_folder, file_to_copy, app_setting_path)
                    )

            # Clean and set permissions
            shutil.rmtree(extracted_app_folder)
            os.system("chmod 600 %s" % app_setting_path)
            os.system("chmod 400 %s/settings.yml" % app_setting_path)
            os.system("chown -R root: %s" % app_setting_path)

            # So much win
            logger.success(m18n.n("app_upgraded", app=app_instance_name))

            hook_callback("post_app_upgrade", env=env_dict)
            operation_logger.success()

    permission_sync_to_user()

    logger.success(m18n.n("upgrade_complete"))


def app_manifest(app):

    raw_app_list = _load_apps_catalog()["apps"]

    if app in raw_app_list or ("@" in app) or ("http://" in app) or ("https://" in app):
        manifest, extracted_app_folder = _fetch_app_from_git(app)
    elif os.path.exists(app):
        manifest, extracted_app_folder = _extract_app_from_file(app)
    else:
        raise YunohostValidationError("app_unknown")

    shutil.rmtree(extracted_app_folder)

    return manifest


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

    from yunohost.hook import hook_add, hook_remove, hook_exec, hook_callback
    from yunohost.log import OperationLogger
    from yunohost.permission import (
        user_permission_list,
        permission_create,
        permission_delete,
        permission_sync_to_user,
    )
    from yunohost.regenconf import manually_modified_files

    def confirm_install(confirm):
        # Ignore if there's nothing for confirm (good quality app), if --force is used
        # or if request on the API (confirm already implemented on the API side)
        if confirm is None or force or msettings.get("interface") == "api":
            return

        if confirm in ["danger", "thirdparty"]:
            answer = msignals.prompt(
                m18n.n("confirm_app_install_" + confirm, answers="Yes, I understand"),
                color="red",
            )
            if answer != "Yes, I understand":
                raise YunohostError("aborting")

        else:
            answer = msignals.prompt(
                m18n.n("confirm_app_install_" + confirm, answers="Y/N"), color="yellow"
            )
            if answer.upper() != "Y":
                raise YunohostError("aborting")

    raw_app_list = _load_apps_catalog()["apps"]

    if app in raw_app_list or ("@" in app) or ("http://" in app) or ("https://" in app):

        # If we got an app name directly (e.g. just "wordpress"), we gonna test this name
        if app in raw_app_list:
            app_name_to_test = app
        # If we got an url like "https://github.com/foo/bar_ynh, we want to
        # extract "bar" and test if we know this app
        elif ("http://" in app) or ("https://" in app):
            app_name_to_test = app.strip("/").split("/")[-1].replace("_ynh", "")
        else:
            # FIXME : watdo if '@' in app ?
            app_name_to_test = None

        if app_name_to_test in raw_app_list:

            state = raw_app_list[app_name_to_test].get("state", "notworking")
            level = raw_app_list[app_name_to_test].get("level", None)
            confirm = "danger"
            if state in ["working", "validated"]:
                if isinstance(level, int) and level >= 5:
                    confirm = None
                elif isinstance(level, int) and level > 0:
                    confirm = "warning"
        else:
            confirm = "thirdparty"

        confirm_install(confirm)

        manifest, extracted_app_folder = _fetch_app_from_git(app)
    elif os.path.exists(app):
        confirm_install("thirdparty")
        manifest, extracted_app_folder = _extract_app_from_file(app)
    else:
        raise YunohostValidationError("app_unknown")

    # Check ID
    if "id" not in manifest or "__" in manifest["id"]:
        raise YunohostValidationError("app_id_invalid")

    app_id = manifest["id"]
    label = label if label else manifest["name"]

    # Check requirements
    _check_manifest_requirements(manifest, app_id)
    _assert_system_is_sane_for_app(manifest, "pre")

    # Check if app can be forked
    instance_number = _installed_instance_number(app_id, last=True) + 1
    if instance_number > 1:
        if "multi_instance" not in manifest or not is_true(manifest["multi_instance"]):
            raise YunohostValidationError("app_already_installed", app=app_id)

        # Change app_id to the forked app id
        app_instance_name = app_id + "__" + str(instance_number)
    else:
        app_instance_name = app_id

    # Retrieve arguments list for install script
    args_dict = (
        {} if not args else dict(urllib.parse.parse_qsl(args, keep_blank_values=True))
    )
    args_odict = _parse_args_from_manifest(manifest, "install", args=args_dict)

    # Validate domain / path availability for webapps
    _validate_and_normalize_webpath(args_odict, extracted_app_folder)

    # Attempt to patch legacy helpers ...
    _patch_legacy_helpers(extracted_app_folder)

    # Apply dirty patch to make php5 apps compatible with php7
    _patch_legacy_php_versions(extracted_app_folder)

    # We'll check that the app didn't brutally edit some system configuration
    manually_modified_files_before_install = manually_modified_files()

    # Tell the operation_logger to redact all password-type args
    # Also redact the % escaped version of the password that might appear in
    # the 'args' section of metadata (relevant for password with non-alphanumeric char)
    data_to_redact = [
        value[0] for value in args_odict.values() if value[1] == "password"
    ]
    data_to_redact += [
        urllib.parse.quote(data)
        for data in data_to_redact
        if urllib.parse.quote(data) != data
    ]
    operation_logger.data_to_redact.extend(data_to_redact)

    operation_logger.related_to = [
        s for s in operation_logger.related_to if s[0] != "app"
    ]
    operation_logger.related_to.append(("app", app_id))
    operation_logger.start()

    logger.info(m18n.n("app_start_install", app=app_id))

    # Create app directory
    app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)
    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)
    os.makedirs(app_setting_path)

    # Set initial app settings
    app_settings = {
        "id": app_instance_name,
        "install_time": int(time.time()),
        "current_revision": manifest.get("remote", {}).get("revision", "?"),
    }
    _set_app_settings(app_instance_name, app_settings)

    # Move scripts and manifest to the right place
    if os.path.exists(os.path.join(extracted_app_folder, "manifest.json")):
        os.system("cp %s/manifest.json %s" % (extracted_app_folder, app_setting_path))
    if os.path.exists(os.path.join(extracted_app_folder, "manifest.toml")):
        os.system("cp %s/manifest.toml %s" % (extracted_app_folder, app_setting_path))
    os.system("cp -R %s/scripts %s" % (extracted_app_folder, app_setting_path))

    for file_to_copy in [
        "actions.json",
        "actions.toml",
        "config_panel.json",
        "config_panel.toml",
        "conf",
    ]:
        if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
            os.system(
                "cp -R %s/%s %s"
                % (extracted_app_folder, file_to_copy, app_setting_path)
            )

    # Initialize the main permission for the app
    # The permission is initialized with no url associated, and with tile disabled
    # For web app, the root path of the app will be added as url and the tile
    # will be enabled during the app install. C.f. 'app_register_url()' below.
    permission_create(
        app_instance_name + ".main",
        allowed=["all_users"],
        label=label,
        show_tile=False,
        protected=False,
    )

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(app_instance_name, args=args_odict)

    env_dict_for_logging = env_dict.copy()
    for arg_name, arg_value_and_type in args_odict.items():
        if arg_value_and_type[1] == "password":
            del env_dict_for_logging["YNH_APP_ARG_%s" % arg_name.upper()]

    operation_logger.extra.update({"env": env_dict_for_logging})

    # Execute the app install script
    install_failed = True
    try:
        install_retcode = hook_exec(
            os.path.join(extracted_app_folder, "scripts/install"), env=env_dict
        )[0]
        # "Common" app install failure : the script failed and returned exit code != 0
        install_failed = True if install_retcode != 0 else False
        if install_failed:
            error = m18n.n("app_install_script_failed")
            logger.error(m18n.n("app_install_failed", app=app_id, error=error))
            failure_message_with_debug_instructions = operation_logger.error(error)
            if msettings.get("interface") != "api":
                dump_app_log_extract_for_debugging(operation_logger)
    # Script got manually interrupted ... N.B. : KeyboardInterrupt does not inherit from Exception
    except (KeyboardInterrupt, EOFError):
        error = m18n.n("operation_interrupted")
        logger.error(m18n.n("app_install_failed", app=app_id, error=error))
        failure_message_with_debug_instructions = operation_logger.error(error)
    # Something wrong happened in Yunohost's code (most probably hook_exec)
    except Exception:
        import traceback

        error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
        logger.error(m18n.n("app_install_failed", app=app_id, error=error))
        failure_message_with_debug_instructions = operation_logger.error(error)
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

        # If the install failed or broke the system, we remove it
        if install_failed or broke_the_system:

            # This option is meant for packagers to debug their apps more easily
            if no_remove_on_failure:
                raise YunohostError(
                    "The installation of %s failed, but was not cleaned up as requested by --no-remove-on-failure."
                    % app_id,
                    raw_msg=True,
                )
            else:
                logger.warning(m18n.n("app_remove_after_failed_install"))

            # Setup environment for remove script
            env_dict_remove = {}
            env_dict_remove["YNH_APP_ID"] = app_id
            env_dict_remove["YNH_APP_INSTANCE_NAME"] = app_instance_name
            env_dict_remove["YNH_APP_INSTANCE_NUMBER"] = str(instance_number)
            env_dict_remove["YNH_APP_MANIFEST_VERSION"] = manifest.get("version", "?")

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
    os.system("chmod 600 %s" % app_setting_path)
    os.system("chmod 400 %s/settings.yml" % app_setting_path)
    os.system("chown -R root: %s" % app_setting_path)

    logger.success(m18n.n("installation_complete"))

    hook_callback("post_app_install", env=env_dict)


def dump_app_log_extract_for_debugging(operation_logger):

    with open(operation_logger.log_path, "r") as f:
        lines = f.readlines()

    filters = [
        r"set [+-]x$",
        r"set [+-]o xtrace$",
        r"local \w+$",
        r"local legacy_args=.*$",
        r".*Helper used in legacy mode.*",
        r"args_array=.*$",
        r"local -A args_array$",
        r"ynh_handle_getopts_args",
        r"ynh_script_progression",
    ]

    filters = [re.compile(f_) for f_ in filters]

    lines_to_display = []
    for line in lines:

        if ": " not in line.strip():
            continue

        # A line typically looks like
        # 2019-10-19 16:10:27,611: DEBUG - + mysql -u piwigo --password=********** -B piwigo
        # And we just want the part starting by "DEBUG - "
        line = line.strip().split(": ", 1)[1]

        if any(filter_.search(line) for filter_ in filters):
            continue

        lines_to_display.append(line)

        if line.endswith("+ ynh_exit_properly") or " + ynh_die " in line:
            break
        elif len(lines_to_display) > 20:
            lines_to_display.pop(0)

    logger.warning(
        "Here's an extract of the logs before the crash. It might help debugging the error:"
    )
    for line in lines_to_display:
        logger.info(line)


@is_unit_operation()
def app_remove(operation_logger, app):
    """
    Remove app

    Keyword argument:
        app -- App(s) to delete

    """
    from yunohost.hook import hook_exec, hook_remove, hook_callback
    from yunohost.permission import (
        user_permission_list,
        permission_delete,
        permission_sync_to_user,
    )

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
    app_id, app_instance_nb = _parse_app_instance_name(app)
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
    env_dict["YNH_APP_MANIFEST_VERSION"] = manifest.get("version", "?")
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

    if ret == 0:
        logger.success(m18n.n("app_removed", app=app))
        hook_callback("post_app_remove", env=env_dict)
    else:
        logger.warning(m18n.n("app_not_properly_removed", app=app))

    # Remove all permission in LDAP
    for permission_name in user_permission_list(apps=[app])["permissions"].keys():
        permission_delete(permission_name, force=True, sync_perm=False)

    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)

    hook_remove(app)

    permission_sync_to_user()
    _assert_system_is_sane_for_app(manifest, "post")


def app_addaccess(apps, users=[]):
    """
    Grant access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.permission import user_permission_update

    output = {}
    for app in apps:
        permission = user_permission_update(
            app + ".main", add=users, remove="all_users"
        )
        output[app] = permission["corresponding_users"]

    return {"allowed_users": output}


def app_removeaccess(apps, users=[]):
    """
    Revoke access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.permission import user_permission_update

    output = {}
    for app in apps:
        permission = user_permission_update(app + ".main", remove=users)
        output[app] = permission["corresponding_users"]

    return {"allowed_users": output}


def app_clearaccess(apps):
    """
    Reset access rights for the app

    Keyword argument:
        apps

    """
    from yunohost.permission import user_permission_reset

    output = {}
    for app in apps:
        permission = user_permission_reset(app + ".main")
        output[app] = permission["corresponding_users"]

    return {"allowed_users": output}


@is_unit_operation()
def app_makedefault(operation_logger, app, domain=None):
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from yunohost.domain import domain_list

    app_settings = _get_app_settings(app)
    app_domain = app_settings["domain"]
    app_path = app_settings["path"]

    if domain is None:
        domain = app_domain
        operation_logger.related_to.append(("domain", domain))
    elif domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

    if "/" in app_map(raw=True)[domain]:
        raise YunohostValidationError(
            "app_make_default_location_already_used",
            app=app,
            domain=app_domain,
            other_app=app_map(raw=True)[domain]["/"]["id"],
        )

    operation_logger.start()

    # TODO / FIXME : current trick is to add this to conf.json.persisten
    # This is really not robust and should be improved
    # e.g. have a flag in /etc/yunohost/apps/$app/ to say that this is the
    # default app or idk...
    if not os.path.exists("/etc/ssowat/conf.json.persistent"):
        ssowat_conf = {}
    else:
        ssowat_conf = read_json("/etc/ssowat/conf.json.persistent")

    if "redirected_urls" not in ssowat_conf:
        ssowat_conf["redirected_urls"] = {}

    ssowat_conf["redirected_urls"][domain + "/"] = app_domain + app_path

    write_to_json(
        "/etc/ssowat/conf.json.persistent", ssowat_conf, sort_keys=True, indent=4
    )
    os.system("chmod 644 /etc/ssowat/conf.json.persistent")

    logger.success(m18n.n("ssowat_conf_updated"))


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
        permission_name = "%s.legacy_%s_uris" % (app, key.split("_")[0])
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
            value = yaml.load(value)
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

    domain, path = _normalize_domain_path(domain, path)

    # We cannot change the url of an app already installed simply by changing
    # the settings...

    if _is_installed(app):
        settings = _get_app_settings(app)
        if "path" in settings.keys() and "domain" in settings.keys():
            raise YunohostValidationError("app_already_installed_cant_change_url")

    # Check the url is available
    _assert_no_conflicting_apps(domain, path)

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
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.permission import user_permission_list

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

        app_settings = read_yaml(APPS_SETTING_PATH + app + "/settings.yml")

        # Redirected
        redirected_urls.update(app_settings.get("redirected_urls", {}))
        redirected_regex.update(app_settings.get("redirected_regex", {}))

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

    from .utils.legacy import translate_legacy_rules_in_ssowant_conf_json_persistent

    translate_legacy_rules_in_ssowant_conf_json_persistent()

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
    logger.warning(m18n.n("experimental_feature"))

    # this will take care of checking if the app is installed
    app_info_dict = app_info(app)

    return {
        "app": app,
        "app_name": app_info_dict["name"],
        "actions": _get_app_actions(app),
    }


@is_unit_operation()
def app_action_run(operation_logger, app, action, args=None):
    logger.warning(m18n.n("experimental_feature"))

    from yunohost.hook import hook_exec

    # will raise if action doesn't exist
    actions = app_action_list(app)["actions"]
    actions = {x["id"]: x for x in actions}

    if action not in actions:
        raise YunohostValidationError(
            "action '%s' not available for app '%s', available actions are: %s"
            % (action, app, ", ".join(actions.keys())),
            raw_msg=True,
        )

    operation_logger.start()

    action_declaration = actions[action]

    # Retrieve arguments list for install script
    args_dict = (
        dict(urllib.parse.parse_qsl(args, keep_blank_values=True)) if args else {}
    )
    args_odict = _parse_args_for_action(actions[action], args=args_dict)

    env_dict = _make_environment_for_app_script(
        app, args=args_odict, args_prefix="ACTION_"
    )
    env_dict["YNH_ACTION"] = action

    _, path = tempfile.mkstemp()

    with open(path, "w") as script:
        script.write(action_declaration["command"])

    os.chmod(path, 700)

    if action_declaration.get("cwd"):
        cwd = action_declaration["cwd"].replace("$app", app)
    else:
        cwd = os.path.join(APPS_SETTING_PATH, app)

    # FIXME: this should probably be ran in a tmp workdir...
    retcode = hook_exec(
        path,
        env=env_dict,
        chdir=cwd,
        user=action_declaration.get("user", "root"),
    )[0]

    if retcode not in action_declaration.get("accepted_return_codes", [0]):
        msg = "Error while executing action '%s' of app '%s': return code %s" % (
            action,
            app,
            retcode,
        )
        operation_logger.error(msg)
        raise YunohostError(msg, raw_msg=True)

    os.remove(path)

    operation_logger.success()
    return logger.success("Action successed!")


# Config panel todo list:
# * docstrings
# * merge translations on the json once the workflow is in place
@is_unit_operation()
def app_config_show_panel(operation_logger, app):
    logger.warning(m18n.n("experimental_feature"))

    from yunohost.hook import hook_exec

    # this will take care of checking if the app is installed
    app_info_dict = app_info(app)

    operation_logger.start()
    config_panel = _get_app_config_panel(app)
    config_script = os.path.join(APPS_SETTING_PATH, app, "scripts", "config")

    app_id, app_instance_nb = _parse_app_instance_name(app)

    if not config_panel or not os.path.exists(config_script):
        return {
            "app_id": app_id,
            "app": app,
            "app_name": app_info_dict["name"],
            "config_panel": [],
        }

    env = {
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
    }

    # FIXME: this should probably be ran in a tmp workdir...
    return_code, parsed_values = hook_exec(
        config_script, args=["show"], env=env, return_format="plain_dict"
    )

    if return_code != 0:
        raise Exception(
            "script/config show return value code: %s (considered as an error)",
            return_code,
        )

    logger.debug("Generating global variables:")
    for tab in config_panel.get("panel", []):
        tab_id = tab["id"]  # this makes things easier to debug on crash
        for section in tab.get("sections", []):
            section_id = section["id"]
            for option in section.get("options", []):
                option_name = option["name"]
                generated_name = (
                    "YNH_CONFIG_%s_%s_%s" % (tab_id, section_id, option_name)
                ).upper()
                option["name"] = generated_name
                logger.debug(
                    " * '%s'.'%s'.'%s' -> %s",
                    tab.get("name"),
                    section.get("name"),
                    option.get("name"),
                    generated_name,
                )

                if generated_name in parsed_values:
                    # code is not adapted for that so we have to mock expected format :/
                    if option.get("type") == "boolean":
                        if parsed_values[generated_name].lower() in ("true", "1", "y"):
                            option["default"] = parsed_values[generated_name]
                        else:
                            del option["default"]
                    else:
                        option["default"] = parsed_values[generated_name]

                    args_dict = _parse_args_in_yunohost_format(
                        {option["name"]: parsed_values[generated_name]}, [option]
                    )
                    option["default"] = args_dict[option["name"]][0]
                else:
                    logger.debug(
                        "Variable '%s' is not declared by config script, using default",
                        generated_name,
                    )
                    # do nothing, we'll use the default if present

    return {
        "app_id": app_id,
        "app": app,
        "app_name": app_info_dict["name"],
        "config_panel": config_panel,
        "logs": operation_logger.success(),
    }


@is_unit_operation()
def app_config_apply(operation_logger, app, args):
    logger.warning(m18n.n("experimental_feature"))

    from yunohost.hook import hook_exec

    installed = _is_installed(app)
    if not installed:
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )

    config_panel = _get_app_config_panel(app)
    config_script = os.path.join(APPS_SETTING_PATH, app, "scripts", "config")

    if not config_panel or not os.path.exists(config_script):
        # XXX real exception
        raise Exception("Not config-panel.json nor scripts/config")

    operation_logger.start()
    app_id, app_instance_nb = _parse_app_instance_name(app)
    env = {
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
    }
    args = dict(urllib.parse.parse_qsl(args, keep_blank_values=True)) if args else {}

    for tab in config_panel.get("panel", []):
        tab_id = tab["id"]  # this makes things easier to debug on crash
        for section in tab.get("sections", []):
            section_id = section["id"]
            for option in section.get("options", []):
                option_name = option["name"]
                generated_name = (
                    "YNH_CONFIG_%s_%s_%s" % (tab_id, section_id, option_name)
                ).upper()

                if generated_name in args:
                    logger.debug(
                        "include into env %s=%s", generated_name, args[generated_name]
                    )
                    env[generated_name] = args[generated_name]
                else:
                    logger.debug("no value for key id %s", generated_name)

    # for debug purpose
    for key in args:
        if key not in env:
            logger.warning(
                "Ignore key '%s' from arguments because it is not in the config", key
            )

    # FIXME: this should probably be ran in a tmp workdir...
    return_code = hook_exec(
        config_script,
        args=["apply"],
        env=env,
    )[0]

    if return_code != 0:
        msg = (
            "'script/config apply' return value code: %s (considered as an error)"
            % return_code
        )
        operation_logger.error(msg)
        raise Exception(msg)

    logger.success("Config updated as expected")
    return {
        "app": app,
        "logs": operation_logger.success(),
    }


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


def _get_app_actions(app_id):
    "Get app config panel stored in json or in toml"
    actions_toml_path = os.path.join(APPS_SETTING_PATH, app_id, "actions.toml")
    actions_json_path = os.path.join(APPS_SETTING_PATH, app_id, "actions.json")

    # sample data to get an idea of what is going on
    # this toml extract:
    #

    # [restart_service]
    # name = "Restart service"
    # command = "echo pouet $YNH_ACTION_SERVICE"
    # user = "root"  # optional
    # cwd = "/" # optional
    # accepted_return_codes = [0, 1, 2, 3]  # optional
    # description.en = "a dummy stupid exemple or restarting a service"
    #
    #     [restart_service.arguments.service]
    #     type = "string",
    #     ask.en = "service to restart"
    #     example = "nginx"
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'restart_service',
    #               OrderedDict([(u'name', u'Restart service'),
    #                            (u'command', u'echo pouet $YNH_ACTION_SERVICE'),
    #                            (u'user', u'root'),
    #                            (u'cwd', u'/'),
    #                            (u'accepted_return_codes', [0, 1, 2, 3]),
    #                            (u'description',
    #                             OrderedDict([(u'en',
    #                                           u'a dummy stupid exemple or restarting a service')])),
    #                            (u'arguments',
    #                             OrderedDict([(u'service',
    #                                           OrderedDict([(u'type', u'string'),
    #                                                        (u'ask',
    #                                                         OrderedDict([(u'en',
    #                                                                       u'service to restart')])),
    #                                                        (u'example',
    #                                                         u'nginx')]))]))])),
    #
    #
    # and needs to be converted into this:
    #
    # [{u'accepted_return_codes': [0, 1, 2, 3],
    #   u'arguments': [{u'ask': {u'en': u'service to restart'},
    #     u'example': u'nginx',
    #     u'name': u'service',
    #     u'type': u'string'}],
    #   u'command': u'echo pouet $YNH_ACTION_SERVICE',
    #   u'cwd': u'/',
    #   u'description': {u'en': u'a dummy stupid exemple or restarting a service'},
    #   u'id': u'restart_service',
    #   u'name': u'Restart service',
    #   u'user': u'root'}]

    if os.path.exists(actions_toml_path):
        toml_actions = toml.load(open(actions_toml_path, "r"), _dict=OrderedDict)

        # transform toml format into json format
        actions = []

        for key, value in toml_actions.items():
            action = dict(**value)
            action["id"] = key

            arguments = []
            for argument_name, argument in value.get("arguments", {}).items():
                argument = dict(**argument)
                argument["name"] = argument_name

                arguments.append(argument)

            action["arguments"] = arguments
            actions.append(action)

        return actions

    elif os.path.exists(actions_json_path):
        return json.load(open(actions_json_path))

    return None


def _get_app_config_panel(app_id):
    "Get app config panel stored in json or in toml"
    config_panel_toml_path = os.path.join(
        APPS_SETTING_PATH, app_id, "config_panel.toml"
    )
    config_panel_json_path = os.path.join(
        APPS_SETTING_PATH, app_id, "config_panel.json"
    )

    # sample data to get an idea of what is going on
    # this toml extract:
    #
    # version = "0.1"
    # name = "Unattended-upgrades configuration panel"
    #
    # [main]
    # name = "Unattended-upgrades configuration"
    #
    #     [main.unattended_configuration]
    #     name = "50unattended-upgrades configuration file"
    #
    #         [main.unattended_configuration.upgrade_level]
    #         name = "Choose the sources of packages to automatically upgrade."
    #         default = "Security only"
    #         type = "text"
    #         help = "We can't use a choices field for now. In the meantime please choose between one of this values:<br>Security only, Security and updates."
    #         # choices = ["Security only", "Security and updates"]

    #         [main.unattended_configuration.ynh_update]
    #         name = "Would you like to update YunoHost packages automatically ?"
    #         type = "bool"
    #         default = true
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'version', u'0.1'),
    #              (u'name', u'Unattended-upgrades configuration panel'),
    #              (u'main',
    #               OrderedDict([(u'name', u'Unattended-upgrades configuration'),
    #                            (u'unattended_configuration',
    #                             OrderedDict([(u'name',
    #                                           u'50unattended-upgrades configuration file'),
    #                                          (u'upgrade_level',
    #                                           OrderedDict([(u'name',
    #                                                         u'Choose the sources of packages to automatically upgrade.'),
    #                                                        (u'default',
    #                                                         u'Security only'),
    #                                                        (u'type', u'text'),
    #                                                        (u'help',
    #                                                         u"We can't use a choices field for now. In the meantime please choose between one of this values:<br>Security only, Security and updates.")])),
    #                                          (u'ynh_update',
    #                                           OrderedDict([(u'name',
    #                                                         u'Would you like to update YunoHost packages automatically ?'),
    #                                                        (u'type', u'bool'),
    #                                                        (u'default', True)])),
    #
    # and needs to be converted into this:
    #
    # {u'name': u'Unattended-upgrades configuration panel',
    #  u'panel': [{u'id': u'main',
    #    u'name': u'Unattended-upgrades configuration',
    #    u'sections': [{u'id': u'unattended_configuration',
    #      u'name': u'50unattended-upgrades configuration file',
    #      u'options': [{u'//': u'"choices" : ["Security only", "Security and updates"]',
    #        u'default': u'Security only',
    #        u'help': u"We can't use a choices field for now. In the meantime please choose between one of this values:<br>Security only, Security and updates.",
    #        u'id': u'upgrade_level',
    #        u'name': u'Choose the sources of packages to automatically upgrade.',
    #        u'type': u'text'},
    #       {u'default': True,
    #        u'id': u'ynh_update',
    #        u'name': u'Would you like to update YunoHost packages automatically ?',
    #        u'type': u'bool'},

    if os.path.exists(config_panel_toml_path):
        toml_config_panel = toml.load(
            open(config_panel_toml_path, "r"), _dict=OrderedDict
        )

        # transform toml format into json format
        config_panel = {
            "name": toml_config_panel["name"],
            "version": toml_config_panel["version"],
            "panel": [],
        }

        panels = [
            key_value
            for key_value in toml_config_panel.items()
            if key_value[0] not in ("name", "version")
            and isinstance(key_value[1], OrderedDict)
        ]

        for key, value in panels:
            panel = {
                "id": key,
                "name": value["name"],
                "sections": [],
            }

            sections = [
                k_v1
                for k_v1 in value.items()
                if k_v1[0] not in ("name",) and isinstance(k_v1[1], OrderedDict)
            ]

            for section_key, section_value in sections:
                section = {
                    "id": section_key,
                    "name": section_value["name"],
                    "options": [],
                }

                options = [
                    k_v
                    for k_v in section_value.items()
                    if k_v[0] not in ("name",) and isinstance(k_v[1], OrderedDict)
                ]

                for option_key, option_value in options:
                    option = dict(option_value)
                    option["name"] = option_key
                    option["ask"] = {"en": option["ask"]}
                    if "help" in option:
                        option["help"] = {"en": option["help"]}
                    section["options"].append(option)

                panel["sections"].append(section)

            config_panel["panel"].append(panel)

        return config_panel

    elif os.path.exists(config_panel_json_path):
        return json.load(open(config_panel_json_path))

    return None


def _get_app_settings(app_id):
    """
    Get settings of an installed app

    Keyword arguments:
        app_id -- The app id

    """
    if not _is_installed(app_id):
        raise YunohostValidationError(
            "app_not_installed", app=app_id, all_apps=_get_all_installed_apps_id()
        )
    try:
        with open(os.path.join(APPS_SETTING_PATH, app_id, "settings.yml")) as f:
            settings = yaml.load(f)
        # If label contains unicode char, this may later trigger issues when building strings...
        # FIXME: this should be propagated to read_yaml so that this fix applies everywhere I think...
        settings = {k: v for k, v in settings.items()}

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
            _set_app_settings(app_id, settings)

        if app_id == settings["id"]:
            return settings
    except (IOError, TypeError, KeyError):
        logger.error(m18n.n("app_not_correctly_installed", app=app_id))
    return {}


def _set_app_settings(app_id, settings):
    """
    Set settings of an app

    Keyword arguments:
        app_id -- The app id
        settings -- Dict with app settings

    """
    with open(os.path.join(APPS_SETTING_PATH, app_id, "settings.yml"), "w") as f:
        yaml.safe_dump(settings, f, default_flow_style=False)


def _extract_app_from_file(path):
    """
    Unzip / untar / copy application tarball or directory to a tmp work directory

    Keyword arguments:
        path -- Path of the tarball or directory
    """
    logger.debug(m18n.n("extracting"))

    path = os.path.abspath(path)

    extracted_app_folder = _make_tmp_workdir_for_app()

    if ".zip" in path:
        extract_result = os.system(
            f"unzip '{path}' -d {extracted_app_folder} > /dev/null 2>&1"
        )
    elif ".tar" in path:
        extract_result = os.system(
            f"tar -xf '{path}' -C {extracted_app_folder} > /dev/null 2>&1"
        )
    elif os.path.isdir(path):
        shutil.rmtree(extracted_app_folder)
        if path[-1] != "/":
            path = path + "/"
        extract_result = os.system(f"cp -a '{path}' {extracted_app_folder}")
    else:
        extract_result = 1

    if extract_result != 0:
        raise YunohostError("app_extraction_failed")

    try:
        if len(os.listdir(extracted_app_folder)) == 1:
            for folder in os.listdir(extracted_app_folder):
                extracted_app_folder = extracted_app_folder + "/" + folder
        manifest = _get_manifest_of_app(extracted_app_folder)
        manifest["lastUpdate"] = int(time.time())
    except IOError:
        raise YunohostError("app_install_files_invalid")
    except ValueError as e:
        raise YunohostError("app_manifest_invalid", error=e)

    logger.debug(m18n.n("done"))

    manifest["remote"] = {"type": "file", "path": path}
    return manifest, extracted_app_folder


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
        manifest_toml = read_toml(os.path.join(path, "manifest.toml"))

        manifest = manifest_toml.copy()

        install_arguments = []
        for name, values in (
            manifest_toml.get("arguments", {}).get("install", {}).items()
        ):
            args = values.copy()
            args["name"] = name

            install_arguments.append(args)

        manifest["arguments"]["install"] = install_arguments

    elif os.path.exists(os.path.join(path, "manifest.json")):
        manifest = read_json(os.path.join(path, "manifest.json"))
    else:
        raise YunohostError(
            "There doesn't seem to be any manifest file in %s ... It looks like an app was not correctly installed/removed."
            % path,
            raw_msg=True,
        )

    manifest["arguments"] = _set_default_ask_questions(manifest.get("arguments", {}))
    return manifest


def _set_default_ask_questions(arguments):

    # arguments is something like
    # { "install": [
    #       { "name": "domain",
    #         "type": "domain",
    #         ....
    #       },
    #       { "name": "path",
    #         "type": "path"
    #         ...
    #       },
    #       ...
    #   ],
    #  "upgrade": [ ... ]
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
        ("boolean", "is_public"),
    ]  # i18n: app_manifest_install_ask_is_public

    for script_name, arg_list in arguments.items():

        # We only support questions for install so far, and for other
        if script_name != "install":
            continue

        for arg in arg_list:

            # Do not override 'ask' field if provided by app ?... Or shall we ?
            # if "ask" in arg:
            #    continue

            # If this arg corresponds to a question with default ask message...
            if any(
                (arg.get("type"), arg["name"]) == question
                for question in questions_with_default
            ):
                # The key is for example "app_manifest_install_ask_domain"
                key = "app_manifest_%s_ask_%s" % (script_name, arg["name"])
                arg["ask"] = m18n.n(key)

    return arguments


def _get_git_last_commit_hash(repository, reference="HEAD"):
    """
    Attempt to retrieve the last commit hash of a git repository

    Keyword arguments:
        repository -- The URL or path of the repository

    """
    try:
        cmd = "git ls-remote --exit-code {0} {1} | awk '{{print $1}}'".format(
            repository, reference
        )
        commit = check_output(cmd)
    except subprocess.CalledProcessError:
        logger.error("unable to get last commit from %s", repository)
        raise ValueError("Unable to get last commit with git")
    else:
        return commit.strip()


def _fetch_app_from_git(app):
    """
    Unzip or untar application tarball to a tmp directory

    Keyword arguments:
        app -- App_id or git repo URL
    """

    # Extract URL, branch and revision to download
    if ("@" in app) or ("http://" in app) or ("https://" in app):
        url = app
        branch = "master"
        if "/tree/" in url:
            url, branch = url.split("/tree/", 1)
        revision = "HEAD"
    else:
        app_dict = _load_apps_catalog()["apps"]

        app_id, _ = _parse_app_instance_name(app)

        if app_id not in app_dict:
            raise YunohostValidationError("app_unknown")
        elif "git" not in app_dict[app_id]:
            raise YunohostValidationError("app_unsupported_remote_type")

        app_info = app_dict[app_id]
        url = app_info["git"]["url"]
        branch = app_info["git"]["branch"]
        revision = str(app_info["git"]["revision"])

    extracted_app_folder = _make_tmp_workdir_for_app()

    logger.debug(m18n.n("downloading"))

    # Download only this commit
    try:
        # We don't use git clone because, git clone can't download
        # a specific revision only
        run_commands([["git", "init", extracted_app_folder]], shell=False)
        run_commands(
            [
                ["git", "remote", "add", "origin", url],
                [
                    "git",
                    "fetch",
                    "--depth=1",
                    "origin",
                    branch if revision == "HEAD" else revision,
                ],
                ["git", "reset", "--hard", "FETCH_HEAD"],
            ],
            cwd=extracted_app_folder,
            shell=False,
        )
        manifest = _get_manifest_of_app(extracted_app_folder)
    except subprocess.CalledProcessError:
        raise YunohostError("app_sources_fetch_failed")
    except ValueError as e:
        raise YunohostError("app_manifest_invalid", error=e)
    else:
        logger.debug(m18n.n("done"))

    # Store remote repository info into the returned manifest
    manifest["remote"] = {"type": "git", "url": url, "branch": branch}
    if revision == "HEAD":
        try:
            manifest["remote"]["revision"] = _get_git_last_commit_hash(url, branch)
        except Exception as e:
            logger.debug("cannot get last commit hash because: %s ", e)
    else:
        manifest["remote"]["revision"] = revision
        manifest["lastUpdate"] = app_info["lastUpdate"]

    return manifest, extracted_app_folder


def _installed_instance_number(app, last=False):
    """
    Check if application is installed and return instance number

    Keyword arguments:
        app -- id of App to check
        last -- Return only last instance number

    Returns:
        Number of last installed instance | List or instances

    """
    if last:
        number = 0
        try:
            installed_apps = os.listdir(APPS_SETTING_PATH)
        except OSError:
            os.makedirs(APPS_SETTING_PATH)
            return 0

        for installed_app in installed_apps:
            if number == 0 and app == installed_app:
                number = 1
            elif "__" in installed_app:
                if app == installed_app[: installed_app.index("__")]:
                    if int(installed_app[installed_app.index("__") + 2 :]) > number:
                        number = int(installed_app[installed_app.index("__") + 2 :])

        return number

    else:
        instance_number_list = []
        instances_dict = app_map(app=app, raw=True)
        for key, domain in instances_dict.items():
            for key, path in domain.items():
                instance_number_list.append(path["instance"])

        return sorted(instance_number_list)


def _is_installed(app):
    """
    Check if application is installed

    Keyword arguments:
        app -- id of App to check

    Returns:
        Boolean

    """
    return os.path.isdir(APPS_SETTING_PATH + app)


def _installed_apps():
    return os.listdir(APPS_SETTING_PATH)


def _value_for_locale(values):
    """
    Return proper value for current locale

    Keyword arguments:
        values -- A dict of values associated to their locale

    Returns:
        An utf-8 encoded string

    """
    if not isinstance(values, dict):
        return values

    for lang in [m18n.locale, m18n.default_locale]:
        try:
            return values[lang]
        except KeyError:
            continue

    # Fallback to first value
    return list(values.values())[0]


def _check_manifest_requirements(manifest, app_instance_name):
    """Check if required packages are met from the manifest"""

    packaging_format = int(manifest.get("packaging_format", 0))
    if packaging_format not in [0, 1]:
        raise YunohostValidationError("app_packaging_format_not_supported")

    requirements = manifest.get("requirements", dict())

    if not requirements:
        return

    logger.debug(m18n.n("app_requirements_checking", app=app_instance_name))

    # Iterate over requirements
    for pkgname, spec in requirements.items():
        if not packages.meets_version_specifier(pkgname, spec):
            version = packages.ynh_packages_version()[pkgname]["version"]
            raise YunohostValidationError(
                "app_requirements_unmeet",
                pkgname=pkgname,
                version=version,
                spec=spec,
                app=app_instance_name,
            )


def _parse_args_from_manifest(manifest, action, args={}):
    """Parse arguments needed for an action from the manifest

    Retrieve specified arguments for the action from the manifest, and parse
    given args according to that. If some required arguments are not provided,
    its values will be asked if interaction is possible.
    Parsed arguments will be returned as an OrderedDict

    Keyword arguments:
        manifest -- The app manifest to use
        action -- The action to retrieve arguments for
        args -- A dictionnary of arguments to parse

    """
    if action not in manifest["arguments"]:
        logger.debug("no arguments found for '%s' in manifest", action)
        return OrderedDict()

    action_args = manifest["arguments"][action]
    return _parse_args_in_yunohost_format(args, action_args)


def _parse_args_for_action(action, args={}):
    """Parse arguments needed for an action from the actions list

    Retrieve specified arguments for the action from the manifest, and parse
    given args according to that. If some required arguments are not provided,
    its values will be asked if interaction is possible.
    Parsed arguments will be returned as an OrderedDict

    Keyword arguments:
        action -- The action
        args -- A dictionnary of arguments to parse

    """
    args_dict = OrderedDict()

    if "arguments" not in action:
        logger.debug("no arguments found for '%s' in manifest", action)
        return args_dict

    action_args = action["arguments"]

    return _parse_args_in_yunohost_format(args, action_args)


class Question:
    "empty class to store questions information"


class YunoHostArgumentFormatParser(object):
    hide_user_input_in_prompt = False

    def parse_question(self, question, user_answers):
        parsed_question = Question()

        parsed_question.name = question["name"]
        parsed_question.default = question.get("default", None)
        parsed_question.choices = question.get("choices", [])
        parsed_question.optional = question.get("optional", False)
        parsed_question.ask = question.get("ask")
        parsed_question.value = user_answers.get(parsed_question.name)

        if parsed_question.ask is None:
            parsed_question.ask = "Enter value for '%s':" % parsed_question.name

        # Empty value is parsed as empty string
        if parsed_question.default == "":
            parsed_question.default = None

        return parsed_question

    def parse(self, question, user_answers):
        question = self.parse_question(question, user_answers)

        if question.value is None:
            text_for_user_input_in_cli = self._format_text_for_user_input_in_cli(
                question
            )

            try:
                question.value = msignals.prompt(
                    text_for_user_input_in_cli, self.hide_user_input_in_prompt
                )
            except NotImplementedError:
                question.value = None

        # we don't have an answer, check optional and default_value
        if question.value is None or question.value == "":
            if not question.optional and question.default is None:
                raise YunohostValidationError(
                    "app_argument_required", name=question.name
                )
            else:
                question.value = (
                    getattr(self, "default_value", None)
                    if question.default is None
                    else question.default
                )

        # we have an answer, do some post checks
        if question.value is not None:
            if question.choices and question.value not in question.choices:
                self._raise_invalid_answer(question)

        # this is done to enforce a certain formating like for boolean
        # by default it doesn't do anything
        question.value = self._post_parse_value(question)

        return (question.value, self.argument_type)

    def _raise_invalid_answer(self, question):
        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=question.name,
            choices=", ".join(question.choices),
        )

    def _format_text_for_user_input_in_cli(self, question):
        text_for_user_input_in_cli = _value_for_locale(question.ask)

        if question.choices:
            text_for_user_input_in_cli += " [{0}]".format(" | ".join(question.choices))

        if question.default is not None:
            text_for_user_input_in_cli += " (default: {0})".format(question.default)

        return text_for_user_input_in_cli

    def _post_parse_value(self, question):
        return question.value


class StringArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "string"
    default_value = ""


class PasswordArgumentParser(YunoHostArgumentFormatParser):
    hide_user_input_in_prompt = True
    argument_type = "password"
    default_value = ""
    forbidden_chars = "{}"

    def parse_question(self, question, user_answers):
        question = super(PasswordArgumentParser, self).parse_question(
            question, user_answers
        )

        if question.default is not None:
            raise YunohostValidationError(
                "app_argument_password_no_default", name=question.name
            )

        return question

    def _post_parse_value(self, question):
        if any(char in question.value for char in self.forbidden_chars):
            raise YunohostValidationError(
                "pattern_password_app", forbidden_chars=self.forbidden_chars
            )

        # If it's an optional argument the value should be empty or strong enough
        if not question.optional or question.value:
            from yunohost.utils.password import assert_password_is_strong_enough

            assert_password_is_strong_enough("user", question.value)

        return super(PasswordArgumentParser, self)._post_parse_value(question)


class PathArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "path"
    default_value = ""


class BooleanArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "boolean"
    default_value = False

    def parse_question(self, question, user_answers):
        question = super(BooleanArgumentParser, self).parse_question(
            question, user_answers
        )

        if question.default is None:
            question.default = False

        return question

    def _format_text_for_user_input_in_cli(self, question):
        text_for_user_input_in_cli = _value_for_locale(question.ask)

        text_for_user_input_in_cli += " [yes | no]"

        if question.default is not None:
            formatted_default = "yes" if question.default else "no"
            text_for_user_input_in_cli += " (default: {0})".format(formatted_default)

        return text_for_user_input_in_cli

    def _post_parse_value(self, question):
        if isinstance(question.value, bool):
            return 1 if question.value else 0

        if str(question.value).lower() in ["1", "yes", "y", "true"]:
            return 1

        if str(question.value).lower() in ["0", "no", "n", "false"]:
            return 0

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=question.name,
            choices="yes, no, y, n, 1, 0",
        )


class DomainArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "domain"

    def parse_question(self, question, user_answers):
        from yunohost.domain import domain_list, _get_maindomain

        question = super(DomainArgumentParser, self).parse_question(
            question, user_answers
        )

        if question.default is None:
            question.default = _get_maindomain()

        question.choices = domain_list()["domains"]

        return question

    def _raise_invalid_answer(self, question):
        raise YunohostValidationError(
            "app_argument_invalid", name=question.name, error=m18n.n("domain_unknown")
        )


class UserArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "user"

    def parse_question(self, question, user_answers):
        from yunohost.user import user_list, user_info
        from yunohost.domain import _get_maindomain

        question = super(UserArgumentParser, self).parse_question(
            question, user_answers
        )
        question.choices = user_list()["users"]
        if question.default is None:
            root_mail = "root@%s" % _get_maindomain()
            for user in question.choices.keys():
                if root_mail in user_info(user).get("mail-aliases", []):
                    question.default = user
                    break

        return question

    def _raise_invalid_answer(self, question):
        raise YunohostValidationError(
            "app_argument_invalid",
            name=question.name,
            error=m18n.n("user_unknown", user=question.value),
        )


class NumberArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "number"
    default_value = ""

    def parse_question(self, question, user_answers):
        question = super(NumberArgumentParser, self).parse_question(
            question, user_answers
        )

        if question.default is None:
            question.default = 0

        return question

    def _post_parse_value(self, question):
        if isinstance(question.value, int):
            return super(NumberArgumentParser, self)._post_parse_value(question)

        if isinstance(question.value, str) and question.value.isdigit():
            return int(question.value)

        raise YunohostValidationError(
            "app_argument_invalid", name=question.name, error=m18n.n("invalid_number")
        )


class DisplayTextArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "display_text"

    def parse(self, question, user_answers):
        print(question["ask"])


ARGUMENTS_TYPE_PARSERS = {
    "string": StringArgumentParser,
    "password": PasswordArgumentParser,
    "path": PathArgumentParser,
    "boolean": BooleanArgumentParser,
    "domain": DomainArgumentParser,
    "user": UserArgumentParser,
    "number": NumberArgumentParser,
    "display_text": DisplayTextArgumentParser,
}


def _parse_args_in_yunohost_format(user_answers, argument_questions):
    """Parse arguments store in either manifest.json or actions.json or from a
    config panel against the user answers when they are present.

    Keyword arguments:
        user_answers -- a dictionnary of arguments from the user (generally
                        empty in CLI, filed from the admin interface)
        argument_questions -- the arguments description store in yunohost
                              format from actions.json/toml, manifest.json/toml
                              or config_panel.json/toml
    """
    parsed_answers_dict = OrderedDict()

    for question in argument_questions:
        parser = ARGUMENTS_TYPE_PARSERS[question.get("type", "string")]()

        answer = parser.parse(question=question, user_answers=user_answers)
        if answer is not None:
            parsed_answers_dict[question["name"]] = answer

    return parsed_answers_dict


def _validate_and_normalize_webpath(args_dict, app_folder):

    # If there's only one "domain" and "path", validate that domain/path
    # is an available url and normalize the path.

    domain_args = [
        (name, value[0]) for name, value in args_dict.items() if value[1] == "domain"
    ]
    path_args = [
        (name, value[0]) for name, value in args_dict.items() if value[1] == "path"
    ]

    if len(domain_args) == 1 and len(path_args) == 1:

        domain = domain_args[0][1]
        path = path_args[0][1]
        domain, path = _normalize_domain_path(domain, path)

        # Check the url is available
        _assert_no_conflicting_apps(domain, path)

        # (We save this normalized path so that the install script have a
        # standard path format to deal with no matter what the user inputted)
        args_dict[path_args[0][0]] = (path, "path")

    # This is likely to be a full-domain app...
    elif len(domain_args) == 1 and len(path_args) == 0:

        # Confirm that this is a full-domain app This should cover most cases
        # ...  though anyway the proper solution is to implement some mechanism
        # in the manifest for app to declare that they require a full domain
        # (among other thing) so that we can dynamically check/display this
        # requirement on the webadmin form and not miserably fail at submit time

        # Full-domain apps typically declare something like path_url="/" or path=/
        # and use ynh_webpath_register or yunohost_app_checkurl inside the install script
        install_script_content = open(
            os.path.join(app_folder, "scripts/install")
        ).read()

        if re.search(
            r"\npath(_url)?=[\"']?/[\"']?\n", install_script_content
        ) and re.search(
            r"(ynh_webpath_register|yunohost app checkurl)", install_script_content
        ):

            domain = domain_args[0][1]
            _assert_no_conflicting_apps(domain, "/", full_domain=True)


def _normalize_domain_path(domain, path):

    # We want url to be of the format :
    #  some.domain.tld/foo

    # Remove http/https prefix if it's there
    if domain.startswith("https://"):
        domain = domain[len("https://") :]
    elif domain.startswith("http://"):
        domain = domain[len("http://") :]

    # Remove trailing slashes
    domain = domain.rstrip("/").lower()
    path = "/" + path.strip("/")

    return domain, path


def _get_conflicting_apps(domain, path, ignore_app=None):
    """
    Return a list of all conflicting apps with a domain/path (it can be empty)

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
        ignore_app -- An optional app id to ignore (c.f. the change_url usecase)
    """

    from yunohost.domain import domain_list

    domain, path = _normalize_domain_path(domain, path)

    # Abort if domain is unknown
    if domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

    # Fetch apps map
    apps_map = app_map(raw=True)

    # Loop through all apps to check if path is taken by one of them
    conflicts = []
    if domain in apps_map:
        # Loop through apps
        for p, a in apps_map[domain].items():
            if a["id"] == ignore_app:
                continue
            if path == p:
                conflicts.append((p, a["id"], a["label"]))
            # We also don't want conflicts with other apps starting with
            # same name
            elif path.startswith(p) or p.startswith(path):
                conflicts.append((p, a["id"], a["label"]))

    return conflicts


def _assert_no_conflicting_apps(domain, path, ignore_app=None, full_domain=False):

    conflicts = _get_conflicting_apps(domain, path, ignore_app)

    if conflicts:
        apps = []
        for path, app_id, app_label in conflicts:
            apps.append(
                " * {domain:s}{path:s} → {app_label:s} ({app_id:s})".format(
                    domain=domain,
                    path=path,
                    app_id=app_id,
                    app_label=app_label,
                )
            )

        if full_domain:
            raise YunohostValidationError("app_full_domain_unavailable", domain=domain)
        else:
            raise YunohostValidationError(
                "app_location_unavailable", apps="\n".join(apps)
            )


def _make_environment_for_app_script(app, args={}, args_prefix="APP_ARG_"):

    app_setting_path = os.path.join(APPS_SETTING_PATH, app)

    manifest = _get_manifest_of_app(app_setting_path)
    app_id, app_instance_nb = _parse_app_instance_name(app)

    env_dict = {
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
        "YNH_APP_MANIFEST_VERSION": manifest.get("version", "?"),
    }

    for arg_name, arg_value_and_type in args.items():
        env_dict["YNH_%s%s" % (args_prefix, arg_name.upper())] = str(
            arg_value_and_type[0]
        )

    return env_dict


def _parse_app_instance_name(app_instance_name):
    """
    Parse a Yunohost app instance name and extracts the original appid
    and the application instance number

    >>> _parse_app_instance_name('yolo') == ('yolo', 1)
    True
    >>> _parse_app_instance_name('yolo1') == ('yolo1', 1)
    True
    >>> _parse_app_instance_name('yolo__0') == ('yolo__0', 1)
    True
    >>> _parse_app_instance_name('yolo__1') == ('yolo', 1)
    True
    >>> _parse_app_instance_name('yolo__23') == ('yolo', 23)
    True
    >>> _parse_app_instance_name('yolo__42__72') == ('yolo__42', 72)
    True
    >>> _parse_app_instance_name('yolo__23qdqsd') == ('yolo__23qdqsd', 1)
    True
    >>> _parse_app_instance_name('yolo__23qdqsd56') == ('yolo__23qdqsd56', 1)
    True
    """
    match = re_app_instance_name.match(app_instance_name)
    assert match, "Could not parse app instance name : %s" % app_instance_name
    appid = match.groupdict().get("appid")
    app_instance_nb = (
        int(match.groupdict().get("appinstancenb"))
        if match.groupdict().get("appinstancenb") is not None
        else 1
    )
    return (appid, app_instance_nb)


#
# ############################### #
#  Applications list management   #
# ############################### #
#


def _initialize_apps_catalog_system():
    """
    This function is meant to intialize the apps_catalog system with YunoHost's default app catalog.
    """

    default_apps_catalog_list = [{"id": "default", "url": APPS_CATALOG_DEFAULT_URL}]

    try:
        logger.debug(
            "Initializing apps catalog system with YunoHost's default app list"
        )
        write_to_yaml(APPS_CATALOG_CONF, default_apps_catalog_list)
    except Exception as e:
        raise YunohostError(
            "Could not initialize the apps catalog system... : %s" % str(e)
        )

    logger.success(m18n.n("apps_catalog_init_success"))


def _read_apps_catalog_list():
    """
    Read the json corresponding to the list of apps catalogs
    """

    try:
        list_ = read_yaml(APPS_CATALOG_CONF)
        # Support the case where file exists but is empty
        # by returning [] if list_ is None
        return list_ if list_ else []
    except Exception as e:
        raise YunohostError("Could not read the apps_catalog list ... : %s" % str(e))


def _actual_apps_catalog_api_url(base_url):

    return "{base_url}/v{version}/apps.json".format(
        base_url=base_url, version=APPS_CATALOG_API_VERSION
    )


def _update_apps_catalog():
    """
    Fetches the json for each apps_catalog and update the cache

    apps_catalog_list is for example :
     [   {"id": "default", "url": "https://app.yunohost.org/default/"}  ]

    Then for each apps_catalog, the actual json URL to be fetched is like :
       https://app.yunohost.org/default/vX/apps.json

    And store it in :
        /var/cache/yunohost/repo/default.json
    """

    apps_catalog_list = _read_apps_catalog_list()

    logger.info(m18n.n("apps_catalog_updating"))

    # Create cache folder if needed
    if not os.path.exists(APPS_CATALOG_CACHE):
        logger.debug("Initialize folder for apps catalog cache")
        mkdir(APPS_CATALOG_CACHE, mode=0o750, parents=True, uid="root")

    for apps_catalog in apps_catalog_list:
        apps_catalog_id = apps_catalog["id"]
        actual_api_url = _actual_apps_catalog_api_url(apps_catalog["url"])

        # Fetch the json
        try:
            apps_catalog_content = download_json(actual_api_url)
        except Exception as e:
            raise YunohostError(
                "apps_catalog_failed_to_download",
                apps_catalog=apps_catalog_id,
                error=str(e),
            )

        # Remember the apps_catalog api version for later
        apps_catalog_content["from_api_version"] = APPS_CATALOG_API_VERSION

        # Save the apps_catalog data in the cache
        cache_file = "{cache_folder}/{list}.json".format(
            cache_folder=APPS_CATALOG_CACHE, list=apps_catalog_id
        )
        try:
            write_to_json(cache_file, apps_catalog_content)
        except Exception as e:
            raise YunohostError(
                "Unable to write cache data for %s apps_catalog : %s"
                % (apps_catalog_id, str(e))
            )

    logger.success(m18n.n("apps_catalog_update_success"))


def _load_apps_catalog():
    """
    Read all the apps catalog cache files and build a single dict (merged_catalog)
    corresponding to all known apps and categories
    """

    merged_catalog = {"apps": {}, "categories": []}

    for apps_catalog_id in [L["id"] for L in _read_apps_catalog_list()]:

        # Let's load the json from cache for this catalog
        cache_file = "{cache_folder}/{list}.json".format(
            cache_folder=APPS_CATALOG_CACHE, list=apps_catalog_id
        )

        try:
            apps_catalog_content = (
                read_json(cache_file) if os.path.exists(cache_file) else None
            )
        except Exception as e:
            raise YunohostError(
                "Unable to read cache for apps_catalog %s : %s" % (cache_file, e),
                raw_msg=True,
            )

        # Check that the version of the data matches version ....
        # ... otherwise it means we updated yunohost in the meantime
        # and need to update the cache for everything to be consistent
        if (
            not apps_catalog_content
            or apps_catalog_content.get("from_api_version") != APPS_CATALOG_API_VERSION
        ):
            logger.info(m18n.n("apps_catalog_obsolete_cache"))
            _update_apps_catalog()
            apps_catalog_content = read_json(cache_file)

        del apps_catalog_content["from_api_version"]

        # Add apps from this catalog to the output
        for app, info in apps_catalog_content["apps"].items():

            # (N.B. : there's a small edge case where multiple apps catalog could be listing the same apps ...
            #         in which case we keep only the first one found)
            if app in merged_catalog["apps"]:
                logger.warning(
                    "Duplicate app %s found between apps catalog %s and %s"
                    % (app, apps_catalog_id, merged_catalog["apps"][app]["repository"])
                )
                continue

            info["repository"] = apps_catalog_id
            merged_catalog["apps"][app] = info

        # Annnnd categories
        merged_catalog["categories"] += apps_catalog_content["categories"]

    return merged_catalog


#
# ############################### #
#        Small utilities          #
# ############################### #
#


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


def is_true(arg):
    """
    Convert a string into a boolean

    Keyword arguments:
        arg -- The string to convert

    Returns:
        Boolean

    """
    if isinstance(arg, bool):
        return arg
    elif isinstance(arg, str):
        return arg.lower() in ["yes", "true", "on"]
    else:
        logger.debug("arg should be a boolean or a string, got %r", arg)
        return True if arg else False


def unstable_apps():

    output = []

    for infos in app_list(full=True)["apps"]:

        if not infos.get("from_catalog") or infos.get("from_catalog").get("state") in [
            "inprogress",
            "notworking",
        ]:
            output.append(infos["id"])

    return output


def _assert_system_is_sane_for_app(manifest, when):

    logger.debug("Checking that required services are up and running...")

    services = manifest.get("services", [])

    # Some apps use php-fpm or php5-fpm which is now php7.0-fpm
    def replace_alias(service):
        if service in ["php-fpm", "php5-fpm", "php7.0-fpm"]:
            return "php7.3-fpm"
        else:
            return service

    services = [replace_alias(s) for s in services]

    # We only check those, mostly to ignore "custom" services
    # (added by apps) and because those are the most popular
    # services
    service_filter = ["nginx", "php7.3-fpm", "mysql", "postfix"]
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

    if packages.dpkg_is_broken():
        if when == "pre":
            raise YunohostValidationError("dpkg_is_broken")
        elif when == "post":
            raise YunohostError("this_action_broke_dpkg")


LEGACY_PHP_VERSION_REPLACEMENTS = [
    ("/etc/php5", "/etc/php/7.3"),
    ("/etc/php/7.0", "/etc/php/7.3"),
    ("/var/run/php5-fpm", "/var/run/php/php7.3-fpm"),
    ("/var/run/php/php7.0-fpm", "/var/run/php/php7.3-fpm"),
    ("php5", "php7.3"),
    ("php7.0", "php7.3"),
    (
        'phpversion="${phpversion:-7.0}"',
        'phpversion="${phpversion:-7.3}"',
    ),  # Many helpers like the composer ones use 7.0 by default ...
    (
        '"$phpversion" == "7.0"',
        '$(bc <<< "$phpversion >= 7.3") -eq 1',
    ),  # patch ynh_install_php to refuse installing/removing php <= 7.3
]


def _patch_legacy_php_versions(app_folder):

    files_to_patch = []
    files_to_patch.extend(glob.glob("%s/conf/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/*/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/.*" % app_folder))
    files_to_patch.append("%s/manifest.json" % app_folder)
    files_to_patch.append("%s/manifest.toml" % app_folder)

    for filename in files_to_patch:

        # Ignore non-regular files
        if not os.path.isfile(filename):
            continue

        c = (
            "sed -i "
            + "".join(
                "-e 's@{pattern}@{replace}@g' ".format(pattern=p, replace=r)
                for p, r in LEGACY_PHP_VERSION_REPLACEMENTS
            )
            + "%s" % filename
        )
        os.system(c)


def _patch_legacy_php_versions_in_settings(app_folder):

    settings = read_yaml(os.path.join(app_folder, "settings.yml"))

    if settings.get("fpm_config_dir") == "/etc/php/7.0/fpm":
        settings["fpm_config_dir"] = "/etc/php/7.3/fpm"
    if settings.get("fpm_service") == "php7.0-fpm":
        settings["fpm_service"] = "php7.3-fpm"
    if settings.get("phpversion") == "7.0":
        settings["phpversion"] = "7.3"

    # We delete these checksums otherwise the file will appear as manually modified
    list_to_remove = ["checksum__etc_php_7.0_fpm_pool", "checksum__etc_nginx_conf.d"]
    settings = {
        k: v
        for k, v in settings.items()
        if not any(k.startswith(to_remove) for to_remove in list_to_remove)
    }

    write_to_yaml(app_folder + "/settings.yml", settings)


def _patch_legacy_helpers(app_folder):

    files_to_patch = []
    files_to_patch.extend(glob.glob("%s/scripts/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/.*" % app_folder))

    stuff_to_replace = {
        # Replace
        #    sudo yunohost app initdb $db_user -p $db_pwd
        # by
        #    ynh_mysql_setup_db --db_user=$db_user --db_name=$db_user --db_pwd=$db_pwd
        "yunohost app initdb": {
            "pattern": r"(sudo )?yunohost app initdb \"?(\$\{?\w+\}?)\"?\s+-p\s\"?(\$\{?\w+\}?)\"?",
            "replace": r"ynh_mysql_setup_db --db_user=\2 --db_name=\2 --db_pwd=\3",
            "important": True,
        },
        # Replace
        #    sudo yunohost app checkport whaterver
        # by
        #    ynh_port_available whatever
        "yunohost app checkport": {
            "pattern": r"(sudo )?yunohost app checkport",
            "replace": r"ynh_port_available",
            "important": True,
        },
        # We can't migrate easily port-available
        # .. but at the time of writing this code, only two non-working apps are using it.
        "yunohost tools port-available": {"important": True},
        # Replace
        #    yunohost app checkurl "${domain}${path_url}" -a "${app}"
        # by
        #    ynh_webpath_register --app=${app} --domain=${domain} --path_url=${path_url}
        "yunohost app checkurl": {
            "pattern": r"(sudo )?yunohost app checkurl \"?(\$\{?\w+\}?)\/?(\$\{?\w+\}?)\"?\s+-a\s\"?(\$\{?\w+\}?)\"?",
            "replace": r"ynh_webpath_register --app=\4 --domain=\2 --path_url=\3",
            "important": True,
        },
        # Remove
        #    Automatic diagnosis data from YunoHost
        #    __PRE_TAG1__$(yunohost tools diagnosis | ...)__PRE_TAG2__"
        #
        "yunohost tools diagnosis": {
            "pattern": r"(Automatic diagnosis data from YunoHost( *\n)*)? *(__\w+__)? *\$\(yunohost tools diagnosis.*\)(__\w+__)?",
            "replace": r"",
            "important": False,
        },
        # Old $1, $2 in backup/restore scripts...
        "app=$2": {
            "only_for": ["scripts/backup", "scripts/restore"],
            "pattern": r"app=\$2",
            "replace": r"app=$YNH_APP_INSTANCE_NAME",
            "important": True,
        },
        # Old $1, $2 in backup/restore scripts...
        "backup_dir=$1": {
            "only_for": ["scripts/backup", "scripts/restore"],
            "pattern": r"backup_dir=\$1",
            "replace": r"backup_dir=.",
            "important": True,
        },
        # Old $1, $2 in backup/restore scripts...
        "restore_dir=$1": {
            "only_for": ["scripts/restore"],
            "pattern": r"restore_dir=\$1",
            "replace": r"restore_dir=.",
            "important": True,
        },
        # Old $1, $2 in install scripts...
        # We ain't patching that shit because it ain't trivial to patch all args...
        "domain=$1": {"only_for": ["scripts/install"], "important": True},
    }

    for helper, infos in stuff_to_replace.items():
        infos["pattern"] = (
            re.compile(infos["pattern"]) if infos.get("pattern") else None
        )
        infos["replace"] = infos.get("replace")

    for filename in files_to_patch:

        # Ignore non-regular files
        if not os.path.isfile(filename):
            continue

        try:
            content = read_file(filename)
        except MoulinetteError:
            continue

        replaced_stuff = False
        show_warning = False

        for helper, infos in stuff_to_replace.items():

            # Ignore if not relevant for this file
            if infos.get("only_for") and not any(
                filename.endswith(f) for f in infos["only_for"]
            ):
                continue

            # If helper is used, attempt to patch the file
            if helper in content and infos["pattern"]:
                content = infos["pattern"].sub(infos["replace"], content)
                replaced_stuff = True
                if infos["important"]:
                    show_warning = True

            # If the helper is *still* in the content, it means that we
            # couldn't patch the deprecated helper in the previous lines.  In
            # that case, abort the install or whichever step is performed
            if helper in content and infos["important"]:
                raise YunohostValidationError(
                    "This app is likely pretty old and uses deprecated / outdated helpers that can't be migrated easily. It can't be installed anymore.",
                    raw_msg=True,
                )

        if replaced_stuff:

            # Check the app do load the helper
            # If it doesn't, add the instruction ourselve (making sure it's after the #!/bin/bash if it's there...
            if filename.split("/")[-1] in [
                "install",
                "remove",
                "upgrade",
                "backup",
                "restore",
            ]:
                source_helpers = "source /usr/share/yunohost/helpers"
                if source_helpers not in content:
                    content.replace("#!/bin/bash", "#!/bin/bash\n" + source_helpers)
                if source_helpers not in content:
                    content = source_helpers + "\n" + content

            # Actually write the new content in the file
            write_to_file(filename, content)

        if show_warning:
            # And complain about those damn deprecated helpers
            logger.error(
                r"/!\ Packagers ! This app uses a very old deprecated helpers ... Yunohost automatically patched the helpers to use the new recommended practice, but please do consider fixing the upstream code right now ..."
            )
