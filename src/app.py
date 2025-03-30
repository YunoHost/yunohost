#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
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

import os
import time
from shutil import rmtree
from logging import getLogger
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Iterator,
    Literal,
    Required,
    TypedDict,
    NotRequired,
    cast,
    Union,
)

from moulinette import Moulinette, m18n
from .utils.file_utils import (
    chmod,
    chown,
    cp,
    rm,
    read_file,
    write_to_file,
)

from .app_catalog import (  # noqa
    APPS_CATALOG_LOGOS,
    _load_apps_catalog,
    app_catalog,  # Unused but imported because it's exposed via Moulinette
    app_search,  # Unused but imported because it's exposed via Moulinette
)
from .log import OperationLogger, is_flash_unit_operation, is_unit_operation
from .utils.error import YunohostError, YunohostValidationError
from .utils.app_utils import (
    APPS_SETTING_PATH,
    _get_app_settings,
    _set_app_settings,
    _parse_app_version,
    _get_manifest_of_app,
    _extract_app,
    _is_installed,
    _assert_is_installed,
    _installed_apps,
    _check_manifest_requirements,
    _guess_webapp_path_requirement,
    _validate_webpath_requirement,
    _assert_no_conflicting_apps,
    _make_environment_for_app_script,
    _make_tmp_workdir_for_app,
    _assert_system_is_sane_for_app,
    _hydrate_app_template,
    _filter_and_hydrate_notifications,
    _display_notifications,
    _ask_confirmation,
    AppRequirementCheckResult,
    AppManifest,
)

if TYPE_CHECKING:
    from .utils.logging import YunohostLogger
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny

    from .utils.configpanel import ConfigPanelModel, RawConfig, RawSettings
    from .utils.form import FormModel

    logger = cast(YunohostLogger, getLogger("yunohost.app"))
else:
    logger = getLogger("yunohost.app")

PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"
APP_FILES_TO_COPY = [
    "manifest.json",
    "manifest.toml",
    "config_panel.toml",
    "scripts",
    "conf",
    "hooks",
    "doc",
]


class AppInfo(TypedDict, total=False):
    id: Required[str]
    name: Required[str]
    description: Required[str]
    version: Required[str]
    domain_path: str
    logo: str | None
    upgrade: "AppUpgradeInfos"
    settings: dict[str, Any]
    setting_path: str
    manifest: AppManifest
    from_catalog: dict[str, Any]
    is_webapp: bool
    is_default: bool
    supports_change_url: bool
    supports_backup_restore: bool
    supports_multi_instance: bool
    supports_config_panel: bool
    supports_purge: bool
    permissions: dict[str, Any]
    label: str
    notifications: dict[str, dict[str, str]]


def app_list(full: bool = False) -> dict[Literal["apps"], list[AppInfo]]:
    """
    List installed apps
    """

    out = []
    for app_id in sorted(_installed_apps()):
        try:
            app_info_dict = app_info(app_id, full=full)
        except Exception as e:
            logger.error(f"Failed to read info for {app_id} : {e}")
            continue
        out.append(app_info_dict)

    return {"apps": out}


def app_info(
    app: str,
    full: bool = False,
    with_upgrade_infos: bool = False,
    with_pre_upgrade_notifications: bool = False,
    with_settings: bool = False,
) -> AppInfo:
    from tempfile import TemporaryDirectory
    from .domain import _get_raw_domain_settings
    from .permission import user_permission_list
    from .utils.i18n import _value_for_locale
    from .utils.app_utils import (
        _git_clone_light,
        _parse_app_doc_and_notifications,
        _notification_is_dismissed,
        APPS_TMP_WORKDIRS,
        _get_app_label,
    )

    _assert_is_installed(app)

    local_manifest = _get_manifest_of_app(app)
    settings = _get_app_settings(app)
    main_perm = settings.get("_permissions", {}).get("main", {})

    ret: AppInfo = {
        "id": app,
        "name": _get_app_label(app, local_manifest),
        "description": main_perm.get("description")
        or _value_for_locale(local_manifest["description"]),
        "version": local_manifest.get("version", "-"),
    }

    if "domain" in settings and "path" in settings:
        ret["domain_path"] = settings["domain"] + settings["path"]

    if full or with_upgrade_infos:
        ret["upgrade"] = _app_upgrade_infos(app, current_version=ret["version"])

    if (
        "upgrade" in ret
        and with_pre_upgrade_notifications
        and ret["upgrade"]["status"] not in ["up_to_date", "url_required"]
    ):
        url = ret["upgrade"]["url"]
        specific_channel = ret["upgrade"]["specific_channel"]
        new_revision = ret["upgrade"]["new_revision"]
        assert url and new_revision

        try:
            with TemporaryDirectory(prefix="app_", dir=APPS_TMP_WORKDIRS) as d:
                _git_clone_light(d, url, branch=specific_channel, revision=new_revision)
                _, tmp_notifications = _parse_app_doc_and_notifications(Path(d))
        except Exception as e:
            logger.warning(f"Failed to check pre-upgrade notifications for {app} : {e}")
            tmp_notifications = {}

        if tmp_notifications.get("PRE_UPGRADE"):
            ret["upgrade"]["notifications"] = _filter_and_hydrate_notifications(
                tmp_notifications["PRE_UPGRADE"],
                ret["version"],
                ret["settings"],
            )

    if full or with_settings:
        ret["settings"] = settings

    if not full:
        return ret

    ret["manifest"] = local_manifest

    base_app_id = app.split("__")[0]
    ret["from_catalog"] = _load_apps_catalog()["apps"].get(base_app_id, {})

    # Check if $app.png exists in the app logo folder, this is a trick to be able to easily customize the logo
    # of an app just by creating $app.png (instead of the hash.png) in the corresponding folder
    if (Path(APPS_CATALOG_LOGOS) / f"{app}.png").exists():
        ret["logo"] = app
    else:
        ret["logo"] = main_perm.get("logo_hash") or ret["from_catalog"].get("logo_hash")  # type: ignore[typeddict-item]

    # Hydrate app notifications and doc
    rendered_doc: dict[str, dict[str, str]] = {}
    for pagename, content_per_lang in ret["manifest"]["doc"].items():
        for lang, content in content_per_lang.items():
            rendered_content = _hydrate_app_template(content, settings)
            # Rendered content may be empty because of conditional blocks
            if not rendered_content:
                continue
            if pagename not in rendered_doc:
                rendered_doc[pagename] = {}
            rendered_doc[pagename][lang] = rendered_content
    ret["manifest"]["doc"] = rendered_doc

    # Filter dismissed notification
    ret["manifest"]["notifications"] = {
        k: v
        for k, v in ret["manifest"]["notifications"].items()
        if not _notification_is_dismissed(k, settings)
    }

    # Hydrate notifications (also filter uneeded post_upgrade notification based on version)
    for step, notifications in ret["manifest"]["notifications"].items():
        rendered_notifications: dict[str, dict[str, str]] = {}
        for name, content_per_lang in notifications.items():
            for lang, content in content_per_lang.items():
                rendered_content = _hydrate_app_template(content, settings)
                if not rendered_content:
                    continue
                if name not in rendered_notifications:
                    rendered_notifications[name] = {}
                rendered_notifications[name][lang] = rendered_content
        ret["manifest"]["notifications"][step] = rendered_notifications

    ret["is_webapp"] = (
        "domain" in settings and settings["domain"] and "path" in settings
    )

    if ret["is_webapp"]:
        ret["is_default"] = (
            _get_raw_domain_settings(settings["domain"]).get("default_app") == app
        )

    setting_path = Path(APPS_SETTING_PATH) / app
    ret["supports_change_url"] = (setting_path / "scripts" / "change_url").exists()
    ret["supports_backup_restore"] = (
        setting_path / "scripts" / "backup"
    ).exists() and (setting_path / "scripts" / "restore").exists()
    ret["supports_multi_instance"] = local_manifest.get("integration", {}).get(
        "multi_instance", False
    )
    ret["supports_config_panel"] = (setting_path / "config_panel.toml").exists()
    ret["supports_purge"] = (
        local_manifest["packaging_format"] >= 2
        and local_manifest["resources"].get("data_dir") is not None
    )

    ret["permissions"] = user_permission_list(
        full=True, absolute_urls=True, apps=[app]
    )["permissions"]

    # FIXME: this is the same stuff as "name" ... maybe we should get rid of "name" or "label" ?
    ret["label"] = ret["name"]

    return ret


class AppUpgradeInfos(TypedDict):
    status: Literal[
        "upgradable", "up_to_date", "url_required", "bad_quality", "fail_requirements"
    ]
    message: str
    url: str | None
    current_version: str
    new_version: str | None
    new_revision: str | None
    requirements: dict[str, "AppRequirementCheckResult"] | None
    specific_channel: str | None
    specific_channel_message: str | None
    notifications: NotRequired[dict[str, str]]


def _app_upgrade_infos(app: str, current_version: str | None = None) -> AppUpgradeInfos:
    base_app_id = app.split("__")[0]
    app_in_catalog = _load_apps_catalog()["apps"].get(base_app_id, {})

    # current_version can be provided to avoid re-reading the manifest from scratch (eg when in app_info)
    # Otherwise we read it here
    if current_version is None:
        current_version = _get_manifest_of_app(app).get("version", "0~ynh0")

    assert current_version

    if not app_in_catalog or "git" not in app_in_catalog:
        return {
            "status": "url_required",
            "message": m18n.n("app_upgrade_url_required"),
            "url": None,
            "current_version": current_version,
            "new_version": None,
            "new_revision": None,
            "requirements": None,
            "specific_channel": None,
            "specific_channel_message": None,
        }

    url = app_in_catalog["git"]["url"]
    current_revision = _get_app_settings(app).get("current_revision", "?")[:7]
    available_upgrade_channels = app_in_catalog.get("alternative_branches", {})
    specific_channel: str | None = _get_app_settings(app).get("upgrade_channel")
    specific_channel_pr_url: str | None = None
    specific_channel_message: str | None = None
    manifest_in_catalog = app_in_catalog.get("manifest", {})

    if specific_channel and specific_channel in available_upgrade_channels:
        channel = available_upgrade_channels[specific_channel]
        ahead = channel["ahead"]
        if ahead:
            level = channel["level"]
            new_revision = channel["revision"]
            new_version = channel["version"]
            specific_channel_pr_url = channel["pr_url"]
            specific_channel_message = m18n.n(
                "app_upgrade_specific_channel_msg",
                channel=specific_channel,
                pr_url=specific_channel_pr_url,
            )
        else:
            logger.debug(
                f"Ignoring specific upgrade channel '{specific_channel}' for '{app}', because it's not currently ahead of the default branch. The default branch will be used instead."
            )
            specific_channel = None
    elif specific_channel:
        logger.warning(
            f"Unknown specific upgrade channel '{specific_channel}' for '{app}'. Falling back to default."
        )
        specific_channel = None

    if specific_channel is None:
        new_version = manifest_in_catalog.get("version", "0~ynh0")
        new_revision = app_in_catalog.get("git", {}).get("revision", "?")
        level = app_in_catalog.get("level", -1)

    # Do not advertise upgrades for bad-quality apps
    if (
        not (isinstance(level, int) and level >= 5)
        or app_in_catalog.get("state") != "working"
    ):
        return {
            "status": "bad_quality",
            "message": m18n.n("app_upgrade_bad_quality"),
            "url": url,
            "current_version": current_version,
            "new_version": None,
            "new_revision": None,
            "requirements": None,
            "specific_channel": specific_channel,
            "specific_channel_message": specific_channel_message,
        }

    if _parse_app_version(current_version) >= _parse_app_version(new_version) and (
        specific_channel is None or new_revision == current_revision
    ):
        return {
            "status": "up_to_date",
            "message": m18n.n(
                "app_upgrade_up_to_date", current_version=current_version
            ),
            "url": None,
            "current_version": current_version,
            "new_version": new_version,
            "new_revision": new_revision,
            "requirements": None,
            "specific_channel": specific_channel,
            "specific_channel_message": specific_channel_message,
        }

    # Not sure when this happens exactly considering we checked for ">=" before ...
    # maybe that's for "legacy versions" that do not respect the X.Y~ynhZ syntax
    #
    # Update: well it does cover the alternative upgrade channel now (typically testing)
    # where the version may not have been bumped but we want a way to advertise it anyway
    # and distinguish the two versions, using the commit id
    if current_version == new_version:
        current_version += f"({current_revision})"
        new_version = f"{new_version} ({new_revision})"
    else:
        new_version = new_version

    # Check requirements

    requirements = {
        r["id"]: r
        for r in _check_manifest_requirements(
            manifest_in_catalog, action="upgrade", app=app
        )
    }
    pass_requirements = all(r["passed"] for r in requirements.values())
    failed_requirements = " ; ".join(
        [r["error"] for r in requirements.values() if not r["passed"]]
    )

    status: Literal["upgradable", "fail_requirements"] = (
        "upgradable" if pass_requirements else "fail_requirements"
    )
    return {
        "status": status,
        # i18n: app_upgrade_upgradable
        # i18n: app_upgrade_fail_requirements
        "message": m18n.n(
            f"app_upgrade_{status}",
            current_version=current_version,
            new_version=new_version,
            failed_requirements=failed_requirements,
        ),
        "url": url,
        "current_version": current_version,
        "new_version": new_version,
        "new_revision": new_revision,
        "requirements": requirements,
        "specific_channel": specific_channel,
        "specific_channel_message": specific_channel_message,
    }


def app_map(
    app: str | None = None, raw: bool = False, user: str | None = None
) -> dict[str, Any]:
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

    from .permission import AppPermInfos, user_permission_list

    apps = []
    result: dict[str, Any] = {}

    if app is not None:
        _assert_is_installed(app)
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

        this_app_perms: dict[str, AppPermInfos] = {
            p: i  # type: ignore
            for p, i in permissions.items()
            if p.startswith(app + ".") and (i["url"] or i["additional_urls"])  # type: ignore
        }

        for perm_info in this_app_perms.values():
            # If we're building the map for a specific user, check the user
            # actually is allowed for this specific perm
            if user and user not in perm_info["corresponding_users"]:
                continue

            perm_label = perm_info["label"]
            perm_all_urls = list(
                filter(None, [perm_info["url"], *perm_info["additional_urls"]])
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
def app_change_url(
    operation_logger: "OperationLogger", app: str, domain: str, path: str
) -> None:
    """
    Modify the URL at which an application is installed.

    Keyword argument:
        app -- Taget app instance name
        domain -- New app domain on which the application will be moved
        path -- New path at which the application will be move

    """
    from .hook import hook_callback, hook_exec_with_script_debug_if_failure
    from .service import service_reload_or_restart
    from .utils.form import DomainOption, WebPathOption

    _assert_is_installed(app)

    if not os.path.exists(
        os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url")
    ):
        raise YunohostValidationError("app_change_url_no_script", app_name=app)

    old_domain = app_setting(app, "domain")
    old_path = app_setting(app, "path")

    assert isinstance(old_domain, str)
    assert isinstance(old_path, str)

    # Normalize path and domain format

    domain = DomainOption.normalize(domain)
    old_domain = DomainOption.normalize(old_domain)
    path = WebPathOption.normalize(path)
    old_path = WebPathOption.normalize(old_path)

    if (domain, path) == (old_domain, old_path):
        raise YunohostValidationError(
            "app_change_url_identical_domains", domain=domain, path=path
        )

    app_setting_path = os.path.join(APPS_SETTING_PATH, app)
    path_requirement = _guess_webapp_path_requirement(app_setting_path)
    _validate_webpath_requirement(
        {"domain": domain, "path": path}, path_requirement, ignore_app=app
    )
    if path_requirement == "full_domain" and path != "/":
        raise YunohostValidationError("app_change_url_require_full_domain", app=app)

    tmp_workdir_for_app = _make_tmp_workdir_for_app(app=app)

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(
        app, workdir=tmp_workdir_for_app, action="change_url"
    )

    env_dict["YNH_APP_OLD_DOMAIN"] = old_domain
    env_dict["YNH_APP_OLD_PATH"] = old_path
    env_dict["YNH_APP_NEW_DOMAIN"] = domain
    env_dict["YNH_APP_NEW_PATH"] = path

    env_dict["old_domain"] = old_domain
    env_dict["old_path"] = old_path
    env_dict["new_domain"] = domain
    env_dict["new_path"] = path
    env_dict["domain"] = domain
    env_dict["path"] = path
    env_dict["path_url"] = path
    env_dict["change_path"] = "1" if old_path != path else "0"
    env_dict["change_domain"] = "1" if old_domain != domain else "0"

    if domain != old_domain:
        operation_logger.related_to.append(("domain", old_domain))
    operation_logger.extra.update({"env": env_dict})
    operation_logger.start()

    old_nginx_conf_path = f"/etc/nginx/conf.d/{old_domain}.d/{app}.conf"
    new_nginx_conf_path = f"/etc/nginx/conf.d/{domain}.d/{app}.conf"
    old_nginx_conf_backup = None
    if not os.path.exists(old_nginx_conf_path):
        logger.warning(
            f"Current nginx config file {old_nginx_conf_path} doesn't seem to exist ... wtf ?"
        )
    else:
        old_nginx_conf_backup = read_file(old_nginx_conf_path)

    change_url_script = os.path.join(tmp_workdir_for_app, "scripts/change_url")

    # Execute App change_url script
    change_url_failed = True
    try:
        (
            change_url_failed,
            failure_message_with_debug_instructions,
        ) = hook_exec_with_script_debug_if_failure(
            change_url_script,
            env=env_dict,
            operation_logger=operation_logger,
            error_message_if_script_failed=m18n.n("app_change_url_script_failed"),
            error_message_if_failed=lambda e: m18n.n(
                "app_change_url_failed", app=app, error=e
            ),
        )
    finally:
        rmtree(tmp_workdir_for_app)

        if change_url_failed:
            logger.warning("Restoring initial nginx config file")
            if old_nginx_conf_path != new_nginx_conf_path and os.path.exists(
                new_nginx_conf_path
            ):
                rm(new_nginx_conf_path, force=True)
            if old_nginx_conf_backup:
                write_to_file(old_nginx_conf_path, old_nginx_conf_backup)
                service_reload_or_restart("nginx")

            # restore values modified by app_checkurl
            # see begining of the function
            app_setting(app, "domain", value=old_domain)
            app_setting(app, "path", value=old_path)
            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)
        else:
            # make sure the domain/path setting are propagated
            app_setting(app, "domain", value=domain)
            app_setting(app, "path", value=path)

            app_ssowatconf()

            service_reload_or_restart("nginx")

            logger.success(
                m18n.n("app_change_url_success", app=app, domain=domain, path=path)
            )

            hook_callback("post_app_change_url", env=env_dict)


def app_upgrade(
    app: str | list[str] = [],
    url: str | None = None,
    file: str | None = None,
    force: bool = False,
    no_safety_backup: bool = False,
    continue_on_failure: bool = False,
    ignore_yunohost_version: bool = False,
) -> (
    None
    | dict[Literal["success", "failed", "cancelled"], Any]
    | dict[Literal["notifications"], dict[Literal["POST_UPGRADE"], dict[str, str]]]
):
    """
    Upgrade app

    Keyword argument:
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade
        file -- Folder or tarball for upgrade
        no_safety_backup -- Disable the safety backup during upgrade

    """
    from .backup import (
        backup_create,
        backup_delete,
        backup_list,
        backup_restore,
    )
    from .hook import (
        hook_add,
        hook_callback,
        hook_exec_with_script_debug_if_failure,
        hook_remove,
    )
    from .permission import _sync_permissions_with_ldap
    from .regenconf import manually_modified_files
    from .utils.legacy import _patch_legacy_helpers
    from .utils.system import free_space_in_directory

    # "app" is a bad name for this arg but meh that's legacy and possibly can't easily be changed
    # (and actually a bit relevant in terms of what's shown in --help)
    raw_requested_targets = app
    if not raw_requested_targets:
        requested_targets = _installed_apps()
    elif isinstance(raw_requested_targets, str):
        requested_targets = [raw_requested_targets]
    else:
        requested_targets = raw_requested_targets.copy()
        # Remove possible duplicates
        requested_targets = [
            app_
            for i, app_ in enumerate(requested_targets)
            if app_ not in requested_targets[:i]
        ]
        # Abort if any of those app is in fact not installed..
        for app_ in requested_targets:
            _assert_is_installed(app_)

    # Check if disk space available
    if free_space_in_directory("/") <= 512 * 1000 * 1000:
        raise YunohostValidationError("disk_space_not_sufficient_update")

    def _check_upgrade_targets(
        requested_targets: list[str],
    ) -> Iterator[tuple[str, str, str]]:
        if (url or file) and len(requested_targets) > 1 and not isinstance(file, dict):
            raise YunohostValidationError(
                "You provided an url or file to 'yunohost app upgrade' with several targets to upgrade ... it's unclear what to do with this. Please provide a single target when specifying a file or url to 'yunohost app upgrade'!",
                raw_msg=True,
            )

        for app_ in requested_targets:
            logger.debug(f"Checking upgradability for {app_}")
            upgrade_infos = _app_upgrade_infos(app_)
            status = upgrade_infos["status"]
            current_version = upgrade_infos.get("current_version")
            new_version = upgrade_infos.get("new_version")

            new_app_src: str
            if file and isinstance(file, dict):
                # We use this hack to test chained upgrades in unit/functional tests
                new_app_src = file[app_]
            elif file:
                new_app_src = file
            elif url:
                new_app_src = url
            elif status == "url_required":
                logger.warning(m18n.n("app_upgrade_cli_url_required", app=app_))
                continue
            elif upgrade_infos.get("specific_channel"):
                assert upgrade_infos["url"]
                assert upgrade_infos["new_revision"]
                new_app_src = (
                    upgrade_infos["url"] + "/tree/" + upgrade_infos["new_revision"]
                )
            else:
                # Use the infos from the catalog
                app_base_id = app_.split("__")[0]
                new_app_src = app_base_id

            if file or url:
                # It's a bit brutal because we'll do it again later ...
                # ... but using -f or -u is supposed to remain occasional and not the nominal case
                # so doesnt feel worth it to optimize (and there's also cache mechanism for _git_clone under the hood)
                new_manifest, extracted_app_folder = _extract_app(new_app_src)
                new_version = new_manifest.get("version", "?")
                msg = m18n.n(
                    "app_upgrade_cli_will_upgrade",
                    app=app_,
                    current_version=current_version,
                    new_version=new_version,
                )
                yield (app_, msg, new_app_src)
            elif status in ["upgradable", "fail_requirements"]:
                # We allow "fail_requirements" here because the requirements are re-checked later with a possibility to bypass them
                # (so effectivly they're checked twice but meh)
                msg = m18n.n(
                    "app_upgrade_cli_will_upgrade",
                    app=app_,
                    current_version=current_version,
                    new_version=new_version,
                )
                yield (app_, msg, new_app_src)
            elif status == "up_to_date":
                if force:
                    msg = m18n.n(
                        "app_upgrade_cli_will_force_upgrade",
                        app=app_,
                        current_version=current_version,
                    )
                    yield (app_, msg, new_app_src)
                else:
                    logger.info(
                        m18n.n(
                            "app_upgrade_cli_up_to_date",
                            app=app_,
                            current_version=current_version,
                        )
                    )
            elif status == "bad_quality":
                logger.warning(m18n.n("app_upgrade_cli_bad_quality", app=app_))
            else:
                logger.error(f"Unknown upgrade status '{status}' for {app_} !?")

    def _check_manifest_requirements_with_option_to_bypass(app_, new_manifest):
        # Check requirements
        failed_requirements = {
            r["id"]: r
            for r in _check_manifest_requirements(
                new_manifest, action="upgrade", app=app_
            )
            if not r["passed"]
        }
        for id_, check in failed_requirements.items():
            logger.warning(app_ + ": " + check["error"])
            if id_ == "ram":
                # i18n: confirm_app_insufficient_ram
                _ask_confirmation("confirm_app_insufficient_ram", force=force)
            elif id_ == "required_yunohost_version" and ignore_yunohost_version:
                pass
            else:
                return False
        return True

    def _upgrade_single_app(
        app_, current_manifest, new_manifest, workdir, no_safety_backup
    ) -> dict:
        logger.info(m18n.n("app_upgrade_app_name", app=app_))

        # Get current_version and new version
        app_new_version_raw = new_manifest.get("version", "?")
        assert isinstance(app_new_version_raw, str)
        app_new_version = _parse_app_version(app_new_version_raw)

        app_current_version_raw = current_manifest.get("version", "?")
        assert isinstance(app_current_version_raw, str)
        app_current_version = _parse_app_version(app_current_version_raw)

        # Manage upgrade type and avoid any upgrade if there is nothing to do
        # (LEGACY hmpf, we should get rid of this somehow ...)
        upgrade_type = "UNKNOWN"
        if "~ynh" in str(app_current_version_raw) and "~ynh" in str(
            app_new_version_raw
        ):
            if app_current_version > app_new_version:
                upgrade_type = "DOWNGRADE"
            elif app_current_version == app_new_version:
                upgrade_type = "UPGRADE_SAME"
            else:
                app_current_version_upstream, _ = str(app_current_version_raw).split(
                    "~ynh"
                )
                app_new_version_upstream, _ = str(app_new_version_raw).split("~ynh")
                if app_current_version_upstream == app_new_version_upstream:
                    upgrade_type = "UPGRADE_PACKAGE"
                else:
                    upgrade_type = "UPGRADE_APP"

        if new_manifest["packaging_format"] >= 2:
            if no_safety_backup:
                # FIXME: i18n
                logger.warning(
                    "Skipping the creation of a backup prior to the upgrade."
                )
            else:
                # FIXME: i18n
                logger.info("Creating a safety backup prior to the upgrade")

                # Switch between pre-upgrade1 or pre-upgrade2
                safety_backup_name = f"{app_}-pre-upgrade1"
                other_safety_backup_name = f"{app_}-pre-upgrade2"
                if safety_backup_name in backup_list()["archives"]:
                    safety_backup_name = f"{app_}-pre-upgrade2"
                    other_safety_backup_name = f"{app_}-pre-upgrade1"

                tweaked_backup_core_only = False
                if "BACKUP_CORE_ONLY" not in os.environ:
                    tweaked_backup_core_only = True
                    os.environ["BACKUP_CORE_ONLY"] = "1"
                try:
                    backup_create(name=safety_backup_name, apps=[app_], system=None)
                except Exception as e:
                    raise YunohostError(
                        f"Aborting the upgrade, because a safety backup could not be created ({e})",
                        raw_msg=True,
                    )
                finally:
                    if tweaked_backup_core_only:
                        del os.environ["BACKUP_CORE_ONLY"]

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

        _assert_system_is_sane_for_app(new_manifest, "pre")

        # We'll check that the app didn't brutally edit some system configuration
        manually_modified_files_before_install = manually_modified_files()

        # Attempt to patch legacy helpers ...
        _patch_legacy_helpers(workdir)

        # Prepare env. var. to pass to script
        env_dict = _make_environment_for_app_script(
            app_, workdir=workdir, action="upgrade"
        )

        env_dict_more = {
            "YNH_APP_UPGRADE_TYPE": upgrade_type,
            "YNH_APP_MANIFEST_VERSION": str(app_new_version_raw),
            "YNH_APP_CURRENT_VERSION": str(app_current_version_raw),
        }

        if new_manifest["packaging_format"] < 2:
            env_dict_more["NO_BACKUP_UPGRADE"] = "1" if no_safety_backup else "0"

        env_dict.update(env_dict_more)

        # Start register change on system
        related_to = [("app", app_)]
        operation_logger = OperationLogger("app_upgrade", related_to, env=env_dict)
        operation_logger.start()

        hook_callback("pre_app_upgrade", env=env_dict)

        if new_manifest["packaging_format"] >= 2:
            from .utils.resources import AppResourceManager

            AppResourceManager(
                app_,
                wanted=new_manifest,
                current=current_manifest,
                workdir=workdir,
            ).apply(
                rollback_and_raise_exception_if_failure=True,
                operation_logger=operation_logger,
                action="upgrade",
            )

            # Boring stuff : the resource upgrade may have added/remove/updated setting
            # so we need to reflect this in the env_dict used to call the actual upgrade script x_x
            # Or: the old manifest may be in v1 and the new in v2, so force to add the setting in env
            env_dict = _make_environment_for_app_script(
                app_,
                workdir=workdir,
                action="upgrade",
                force_include_app_settings=True,
            )
            env_dict.update(env_dict_more)

        # Execute the app upgrade script
        upgrade_failed = True
        try:
            (
                upgrade_failed,
                failure_message_with_debug_instructions,
            ) = hook_exec_with_script_debug_if_failure(
                workdir + "/scripts/upgrade",
                env=env_dict,
                operation_logger=operation_logger,
                error_message_if_script_failed=m18n.n("app_upgrade_script_failed"),
                error_message_if_failed=lambda e: m18n.n(
                    "app_upgrade_failed", app=app_, error=e
                ),
            )
        finally:
            # If upgrade failed, try to restore the safety backup
            if (
                upgrade_failed
                and new_manifest["packaging_format"] >= 2
                and not no_safety_backup
            ):
                logger.warning(
                    "Upgrade failed ... attempting to restore the safety backup (Yunohost first need to remove the app for this) ..."
                )

                app_remove(app_, force_workdir=workdir)
                backup_restore(name=safety_backup_name, apps=[app_], force=True)
                if not _is_installed(app_):
                    logger.error(
                        "Uhoh ... Yunohost failed to restore the app to the way it was before the failed upgrade :|"
                    )

            # Whatever happened (install success or failure) we check if it broke the system
            # and warn the user about it
            try:
                broke_the_system = False
                _assert_system_is_sane_for_app(new_manifest, "post")
            except Exception as e:
                broke_the_system = True
                logger.error(m18n.n("app_upgrade_failed", app=app_, error=str(e)))
                failure_message_with_debug_instructions = operation_logger.error(str(e))

            # We'll check that the app didn't brutally edit some system configuration
            manually_modified_files_after_install = manually_modified_files()
            manually_modified_files_by_app = set(
                manually_modified_files_after_install
            ) - set(manually_modified_files_before_install)
            if manually_modified_files_by_app:
                logger.error(
                    "Packagers /!\\ This app manually modified some system configuration files! This should not happen! If you need to do so, you should implement a proper conf_regen hook. Those configuration were affected:\n    - "
                    + "\n     - ".join(manually_modified_files_by_app)
                )

            # If the upgrade didnt fail, update the revision and app files
            # (even if it broke the system, otherwise we end up in a funky intermediate state
            # where the app files don't match the installed version or settings,
            # for example for v1->v2 upgrade marked as "broke the system" for some reason)
            if not upgrade_failed:
                now = int(time.time())
                app_setting(app_, "update_time", now)
                app_setting(
                    app_,
                    "current_revision",
                    new_manifest.get("remote", {}).get("revision", "?"),
                )

                # Clean hooks and add new ones
                hook_remove(app_)
                if "hooks" in os.listdir(workdir):
                    for hook in os.listdir(workdir + "/hooks"):
                        hook_add(app_, workdir + "/hooks/" + hook)

                app_setting_path = os.path.join(APPS_SETTING_PATH, app_)

                # Replace scripts and manifest and conf (if exists)
                # Move scripts and manifest to the right place
                for file_to_copy in APP_FILES_TO_COPY:
                    rm(f"{app_setting_path}/{file_to_copy}", recursive=True, force=True)
                    if os.path.exists(os.path.join(workdir, file_to_copy)):
                        cp(
                            f"{workdir}/{file_to_copy}",
                            f"{app_setting_path}/{file_to_copy}",
                            recursive=True,
                        )

                # Clean and set permissions
                rmtree(workdir)
                chmod(app_setting_path, 0o600)
                chmod(f"{app_setting_path}/settings.yml", 0o400)
                chown(app_setting_path, "root", recursive=True)

            if upgrade_failed and broke_the_system:
                raise YunohostError("app_upgrade_failed_and_broke_the_system", app=app_)
            elif broke_the_system:
                raise YunohostError("app_upgrade_broke_the_system", app=app_)
            elif upgrade_failed:
                raise YunohostError(
                    failure_message_with_debug_instructions, raw_msg=True
                )

            # So much win
            logger.success(m18n.n("app_upgraded", app=app_))

            # Format post-upgrade notifications
            if new_manifest["notifications"]["POST_UPGRADE"]:
                # Get updated settings to hydrate notifications
                settings = _get_app_settings(app_)
                post_upgrade_notifications = _filter_and_hydrate_notifications(
                    new_manifest["notifications"]["POST_UPGRADE"],
                    current_version=app_current_version_raw,
                    data=settings,
                )
                if Moulinette.interface.type == "cli":
                    # ask for simple confirm
                    _display_notifications(post_upgrade_notifications, force=force)
            else:
                post_upgrade_notifications = {}

            # Reset the dismiss flag for post upgrade notification
            app_setting(app_, "_dismiss_notification_post_upgrade", delete=True)

            hook_callback("post_app_upgrade", env=env_dict)
            operation_logger.success()

            _sync_permissions_with_ldap()

            return post_upgrade_notifications

    #
    #
    # Start of the actual "multi" app upgrade flow...
    #
    #

    actual_targets = list(_check_upgrade_targets(requested_targets))
    actual_targets_with_manifests_and_workdir = []

    # Fetch app dirs and check requirements before actually launching upgrades
    for app_, msg, new_app_src in actual_targets:
        new_manifest, workdir = _extract_app(new_app_src)
        ok = _check_manifest_requirements_with_option_to_bypass(app_, new_manifest)
        if ok:
            actual_targets_with_manifests_and_workdir.append(
                (app_, msg, _get_manifest_of_app(app_), new_manifest, workdir)
            )

    # If we were asked to upgrade everything
    if not raw_requested_targets:
        # Everything is already ok? Success !
        if not actual_targets:
            logger.success(m18n.n("apps_already_up_to_date"))
            if Moulinette.interface.type == "api":
                return {"notifications": {"POST_UPGRADE": {}}}  # type: ignore
            else:
                return None
        else:
            # We'll proceed - or ask confirmation if some apps did not pass requirements
            pass
    if not actual_targets_with_manifests_and_workdir:
        raise YunohostValidationError("apps_no_target_can_be_upgraded")

    # Before going in, display the list of what's actually gonna be upgraded
    # (though no need to do this if the goal is to upgrade a single app, it's gonna be redundant with the info message in the loop)
    if not raw_requested_targets or len(requested_targets) > 1:
        todolist = [
            msg for _, msg, _, _, _ in actual_targets_with_manifests_and_workdir
        ]
        logger.info(
            m18n.n(
                "app_upgrade_several_apps", apps="\n  - " + ("\n  - ".join(todolist))
            )
        )

    # If some apps did not pass requirements, ask confirmation
    some_target_didnt_pass_requirements = len(
        actual_targets_with_manifests_and_workdir
    ) < len(actual_targets)
    if some_target_didnt_pass_requirements:
        # i18n: apps_confirm_partial_upgrade
        _ask_confirmation("apps_confirm_partial_upgrade", kind="soft")

    # Display pre-upgrade notifications and ask for simple confirm
    # (On the webadmin, it's already handled by the front so we only do this in CLI)
    if Moulinette.interface.type == "cli":
        for (
            app_,
            _,
            current_manifest,
            new_manifest,
            _,
        ) in actual_targets_with_manifests_and_workdir:
            if new_manifest["notifications"]["PRE_UPGRADE"]:
                notifications = _filter_and_hydrate_notifications(
                    new_manifest["notifications"]["PRE_UPGRADE"],
                    current_version=current_manifest.get("version"),
                    data=_get_app_settings(app_),
                )
                _display_notifications(notifications, force=force)

    post_upgrade_notifications: dict[str, str] = {}
    pending_apps = [target[0] for target in actual_targets_with_manifests_and_workdir]
    failed_to_upgrade_apps: dict[str, str] = {}
    successful_apps: list[str] = []
    for (
        app_,
        _,
        current_manifest,
        new_manifest,
        workdir,
    ) in actual_targets_with_manifests_and_workdir:
        pending_apps.remove(app_)

        try:
            post_upgrade_notifications = _upgrade_single_app(
                app_, current_manifest, new_manifest, workdir, no_safety_backup
            )
        except YunohostError as e:
            # If upgrading a single app from the webadmin : re-raise the Exception
            if (
                Moulinette.interface.type == "api"
                and raw_requested_targets
                and len(requested_targets) == 1
            ):
                raise e

            failed_to_upgrade_apps[app_] = str(e)
            logger.error(e)

            broke_the_system = "broke_the_system" in e.key
            # FIXME if "pending_apps" etc
            if broke_the_system and continue_on_failure and pending_apps:
                logger.warning(
                    "Option --continue-on-failure was provided, but all remaining upgrades are cancelled anyway because it looks like the app broke the system"
                )
                continue_on_failure = False
            if continue_on_failure and pending_apps:
                logger.warning(
                    m18n.n("app_upgrade_continuing_with_other_apps", app=app_)
                )
                continue
            else:
                if pending_apps:
                    logger.warning(
                        m18n.n("apps_upgrade_cancelled", apps=", ".join(pending_apps))
                    )
                break
        else:
            successful_apps.append(app_)

    if Moulinette.interface.type == "api":
        # FIXME : in fact post_upgrade_notifications is only the notification from the last app x_x
        # I guess we didnt notice so far because the app only upgrades a single app at a time...
        return {"notifications": {"POST_UPGRADE": post_upgrade_notifications}}  # type: ignore[return-value]
    else:
        if len(actual_targets_with_manifests_and_workdir) > 1:
            result_dict: dict[Literal["success", "failed", "cancelled"], Any] = {}
            if successful_apps:
                result_dict["success"] = successful_apps
            if failed_to_upgrade_apps:
                result_dict["failed"] = failed_to_upgrade_apps
            if pending_apps:
                result_dict["cancelled"] = pending_apps
            return result_dict
        else:
            return None


def app_manifest(app: str, with_screenshot: bool = False) -> AppManifest:
    from .utils.form import parse_raw_options

    manifest, extracted_app_folder = _extract_app(app)

    manifest["install"] = parse_raw_options(manifest.get("install", {}), serialize=True)

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
                            manifest["screenshot"] = (
                                f"data:image/{ext};charset=utf-8;base64,{data}"
                            )
                        break

    rmtree(extracted_app_folder)

    manifest["requirements"] = {
        r["id"]: r
        for r in _check_manifest_requirements(
            manifest, action="install", app=manifest["id"]
        )
    }
    return manifest


@is_unit_operation()
def app_install(
    operation_logger: "OperationLogger",
    app: str,
    label: str | None = None,
    args: str | None = None,
    no_remove_on_failure: bool = False,
    force: bool = False,
    ignore_yunohost_version: bool = False,
) -> None | dict[Literal["notifications"], dict[str, str]]:
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation
        no_remove_on_failure -- Debug option to avoid removing the app on a failed installation
        force -- Do not ask for confirmation when installing experimental / low-quality apps
    """

    from .hook import (
        hook_add,
        hook_callback,
        hook_exec,
        hook_exec_with_script_debug_if_failure,
        hook_remove,
    )
    from .log import OperationLogger
    from .permission import (
        _sync_permissions_with_ldap,
        permission_create,
        permission_delete,
        user_permission_list,
    )
    from .regenconf import manually_modified_files
    from .user import user_list
    from .utils.form import ask_questions_and_parse_answers
    from .utils.legacy import _patch_legacy_helpers
    from .utils.system import free_space_in_directory
    from .utils.app_utils import _next_instance_number_for_app, _confirm_app_install

    # Check if disk space available
    if free_space_in_directory("/") <= 512 * 1000 * 1000:
        raise YunohostValidationError("disk_space_not_sufficient_install")

    _confirm_app_install(app, force)
    manifest, extracted_app_folder = _extract_app(app)

    # Display pre_install notices in cli mode
    if manifest["notifications"]["PRE_INSTALL"] and Moulinette.interface.type == "cli":
        notifications = _filter_and_hydrate_notifications(
            manifest["notifications"]["PRE_INSTALL"]
        )
        _display_notifications(notifications, force=force)

    packaging_format = manifest["packaging_format"]

    # Check ID
    if "id" not in manifest or "__" in manifest["id"] or "." in manifest["id"]:
        raise YunohostValidationError("app_id_invalid")

    app_id = manifest["id"]

    instance_number = _next_instance_number_for_app(app_id)
    if instance_number > 1:
        # Change app_id to the forked app id
        app_instance_name = app_id + "__" + str(instance_number)
    else:
        app_instance_name = app_id

    if app_instance_name in user_list()["users"].keys():
        raise YunohostValidationError(
            f"There is already a YunoHost user called {app_instance_name} ...",
            raw_msg=True,
        )

    # Check requirements
    failed_requirements = {
        r["id"]: r
        for r in _check_manifest_requirements(
            manifest, action="upgrade", app=app_instance_name
        )
        if not r["passed"]
    }
    for id_, check in failed_requirements.items():
        if id_ == "ram":
            logger.warning(check["error"])
            _ask_confirmation("confirm_app_insufficient_ram", force=force)
        elif id_ == "required_yunohost_version" and ignore_yunohost_version:
            logger.warning(check["error"])
        else:
            raise YunohostValidationError(check["error"], raw_msg=True)

    _assert_system_is_sane_for_app(manifest, "pre")

    app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)

    # Retrieve arguments list for install script
    raw_options = manifest["install"]
    options, form = ask_questions_and_parse_answers(raw_options, prefilled_answers=args)
    parsedargs = form.dict(exclude_none=True)

    # Validate domain / path availability for webapps
    # (ideally this should be handled by the resource system for manifest v >= 2
    path_requirement = _guess_webapp_path_requirement(extracted_app_folder)
    _validate_webpath_requirement(parsedargs, path_requirement)

    if packaging_format < 2:
        # Attempt to patch legacy helpers ...
        _patch_legacy_helpers(extracted_app_folder)

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
        rmtree(app_setting_path)
    os.makedirs(app_setting_path)

    # Hotfix for bug in the webadmin while we fix the actual issue :D
    if label == "undefined":
        label = None

    # Set initial app settings
    app_settings = {
        "id": app_instance_name,
        "install_time": int(time.time()),
        "current_revision": manifest.get("remote", {}).get("revision", "?"),
    }

    if label:
        app_settings["label"] = label

    # If packaging_format v2+, save all install options as settings
    if packaging_format >= 2:
        for option in options:
            # Except readonly "questions" that don't even have a value
            if option.readonly:
                continue
            # Except user-provider passwords
            # ... which we need to reinject later in the env_dict
            if option.type == "password":
                continue

            app_settings[option.id] = form[option.id]

    _set_app_settings(app_instance_name, app_settings)

    # Move scripts and manifest to the right place
    for file_to_copy in APP_FILES_TO_COPY:
        if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
            cp(
                f"{extracted_app_folder}/{file_to_copy}",
                f"{app_setting_path}/{file_to_copy}",
                recursive=True,
            )

    if int(packaging_format) == 2:
        from .utils.resources import AppResourceManager
        try:
            AppResourceManager(app_instance_name, wanted=manifest, current={}).apply(
                rollback_and_raise_exception_if_failure=True,
                operation_logger=operation_logger,
                action="install",
            )
        except (KeyboardInterrupt, EOFError, Exception) as e:
            rmtree(app_setting_path)
            raise e
    elif packaging_format <= 1:
        # Initialize the main permission for the app
        # The permission is initialized with no url associated, and with tile disabled
        # For web app, the root path of the app will be added as url and the tile
        # will be enabled during the app install. C.f. 'app_register_url()' below
        # or the webpath resource
        permission_create(
            app_instance_name + ".main",
            allowed=["all_users"],
            show_tile=False,
            protected=False,
        )

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(
        app_instance_name,
        args=parsedargs,
        workdir=extracted_app_folder,
        action="install",
    )

    # Reinject user-provider passwords which are not in the app settings
    ephemeral_vars_for_install = {}
    if packaging_format >= 2:
        for option in options:
            # (cf a few line before)
            if option.type == "password":
                env_dict[option.id] = form[option.id]
                ephemeral_vars_for_install[option.id] = form[option.id]

    # We want to hav the env_dict in the log ... but not password values
    env_dict_for_logging = env_dict.copy()
    for option in options:
        # Or should it be more generally option.redact ?
        if option.type == "password":
            if f"YNH_APP_ARG_{option.id.upper()}" in env_dict_for_logging:
                del env_dict_for_logging[f"YNH_APP_ARG_{option.id.upper()}"]
            if option.id in env_dict_for_logging:
                del env_dict_for_logging[option.id]

    operation_logger.extra.update({"env": env_dict_for_logging})

    if packaging_format >= 3:

        app = app_instance_name
        workdir = extracted_app_folder
        app_scripts = check_output(f"bash -c \"source '{workdir}/scripts.sh'; declare -F | cut -d' ' -f3\"").strip().split("\n")
        call_remove_if_failure = False

        def _run_step(step):
            if step not in app_scripts:
                return
            snippet = ["source $YNH_APP_BASEDIR/scripts.sh"]
            # FIXME : revisit this ? idk
            if "common" in app_scripts:
                snippet.append("common")
            logger.debug(f"Running step: {step}")
            snippet.append(step)
            _run_app_script_or_snippet(
                app,
                step,
                '\n'.join(snippet),
                env=ephemeral_vars_for_install.copy(),
                workdir=workdir,
                as_app=(not step.endswith("_as_root") and step != "validate_install"),
                raise_exception_if_failure=True
            )

        def packaging_v3_install_sequence():

            from .utils.resources import AppResourceManager
            from .utils.configurations import AppConfigurationsManager

            # validate_install is actually ran as root because the user doesnt exists yet
            _run_step("validate_install")

            # Provision resources
            resource_manager = AppResourceManager(app, wanted=manifest, current={}, env=env_dict)
            resource_manager.apply(
                rollback_and_raise_exception_if_failure=True,
                operation_logger=operation_logger,
            )

            # We don't have "smart" rollback beyond that point
            nonlocal call_remove_if_failure
            call_remove_if_failure = True

            # FIXME: i18n / ux
            logger.info(f"Building {app} ...")
            _run_step("before_build_as_root")
            _run_step("build")
            _run_step("after_build_as_root")

            # FIXME : fix install_dir permissions somehow?

            # FIXME: error handling ?
            # FIXME : possibly replace all this block with a call to app_regenconf()?
            logger.info(f"Adding configurations for {app} ...")
            _run_step("before_regenconf_as_root")
            _run_step("before_regenconf")
            AppConfigurationsManager(app, wanted=manifest, workdir=workdir).apply()
            _run_step("after_regenconf")
            _run_step("after_regenconf_as_root")

            # FIXME: i18n / ux
            logger.info(f"Initializing {app} ...")
            _run_step("before_init_as_root")
            _run_step("init")
            _run_step("after_init_as_root")

            # FIXME: i18n / ux
            logger.info("Finalizing ...")
            _run_step("before_finalize_as_root")
            _run_step("finalize")
            _run_step("after_finalize_as_root")

    if packaging_format >= 3:
        try:
            packaging_v3_install_sequence()
        except (KeyboardInterrupt, EOFError, Exception) as e:
            if call_remove_if_failure:
                app_remove(app)
            else:
                shutil.rmtree(app_setting_path)
            shutil.rmtree(extracted_app_folder)
            failure_message_with_debug_instructions = operation_logger.error(str(e))
            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)

    # Execute the app install script
    install_failed = True
    try:
        if packaging_format < 3:
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
        else:
            install_failed = False
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
                + "\n     - ".join(manually_modified_files_by_app)
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
                from .utils.resources import AppResourceManager

                AppResourceManager(
                    app_instance_name, wanted={}, current=manifest
                ).apply(rollback_and_raise_exception_if_failure=False, action="remove")
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
            rmtree(app_setting_path)
            rmtree(extracted_app_folder)

            _sync_permissions_with_ldap()
            app_ssowatconf()

            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)

    # Clean hooks and add new ones
    hook_remove(app_instance_name)
    if "hooks" in os.listdir(extracted_app_folder):
        for file in os.listdir(extracted_app_folder + "/hooks"):
            hook_add(app_instance_name, extracted_app_folder + "/hooks/" + file)

    # Clean and set permissions
    rmtree(extracted_app_folder)
    chmod(app_setting_path, 0o600)
    chmod(f"{app_setting_path}/settings.yml", 0o400)
    chown(app_setting_path, "root", recursive=True)

    logger.success(m18n.n("installation_complete"))

    # Get the generated settings to hydrate notifications
    settings = _get_app_settings(app_instance_name)
    notifications = _filter_and_hydrate_notifications(
        manifest["notifications"]["POST_INSTALL"], data=settings
    )

    # Display post_install notices in cli mode
    if notifications and Moulinette.interface.type == "cli":
        _display_notifications(notifications, force=force)

    # Call postinstall hook
    hook_callback("post_app_install", env=env_dict)

    # Return hydrated post install notif for API
    if Moulinette.interface.type == "api":
        return {"notifications": notifications}
    else:
        return None


@is_unit_operation()
def app_remove(
    operation_logger: "OperationLogger",
    app: str,
    purge: bool = False,
    force_workdir: str | None = None,
    remove_on_failed_install: bool = False,
) -> None:
    """
    Remove app

    Keyword arguments:
        app -- App(s) to delete
        purge -- Remove with all app data
        force_workdir -- Special var to force the working directoy to use, in context such as remove-after-failed-upgrade or remove-after-failed-restore
    """
    from .domain import _get_raw_domain_settings, domain_config_set, domain_list
    from .hook import hook_callback, hook_exec, hook_remove
    from .permission import (
        _sync_permissions_with_ldap,
        permission_delete,
        user_permission_list,
    )
    from .utils.legacy import _patch_legacy_helpers

    _assert_is_installed(app)

    if remove_on_failed_install:
        operation_logger.operation = "remove_on_failed_install"

    operation_logger.start()

    logger.info(m18n.n("app_start_remove", app=app))
    app_setting_path = os.path.join(APPS_SETTING_PATH, app)

    # Attempt to patch legacy helpers ...
    _patch_legacy_helpers(app_setting_path)

    if force_workdir:
        # This is when e.g. calling app_remove() from the upgrade-failed case
        # where we want to remove using the *new* remove script and not the old one
        # and also get the new manifest
        # It's especially important during v1->v2 app format transition where the
        # setting names change (e.g. install_dir instead of final_path) and
        # running the old remove script doesnt make sense anymore ...
        workdir = _make_tmp_workdir_for_app()
        os.system(f"cp -a {force_workdir}/* {workdir}/")
    else:
        workdir = _make_tmp_workdir_for_app(app=app)

    manifest = _get_manifest_of_app(workdir)

    env_dict = _make_environment_for_app_script(
        app, workdir=workdir, action="remove"
    )
    env_dict["YNH_APP_PURGE"] = str(1 if purge else 0)

    operation_logger.extra.update({"env": env_dict})
    operation_logger.flush()

    packaging_format = manifest["packaging_format"]
    ret = 0

    app_scripts = []
    if packaging_format >= 3:
        try:
            # FIXME : turn this into a helper function somehow
            app_scripts = check_output(f"bash -c \"source '{workdir}/scripts.sh'; declare -F | cut -d' ' -f3\"").strip().split("\n")
        except Exception as e:
            logger.warning(f"Uhoh !? Failed to parse available functions for {app} ? {e}")

    def _run_step(step):
        if step not in app_scripts:
            return
        snippet = ["source $YNH_APP_BASEDIR/scripts.sh"]
        # FIXME : revisit this ? idk
        if "common" in app_scripts:
            snippet.append("common")
        logger.debug(f"Running step: {step}")
        snippet.append(step)
        _run_app_script_or_snippet(
            app,
            step,
            '\n'.join(snippet),
            workdir=workdir,
            as_app=(not step.endswith("_as_root")),
            raise_exception_if_failure=False
        )

    if packaging_format >= 3:
        try:
            _run_step("before_remove_as_root")
            _run_step("before_remove")
        except Exception as e:
            ret = -1
            logger.error(e)

    if packaging_format < 3:
        remove_script = f"{workdir}/scripts/remove"
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
    else:
        from .utils.configurations import AppConfigurationsManager
        manifest_for_remove = copy.deepcopy(manifest)
        manifest_for_remove["configurations"] = {}
        try:
            AppConfigurationsManager(app, wanted=manifest_for_remove, workdir=workdir).apply()
        except Exception as e:
            logger.warning(f"Failed to properly cleanup configurations related to {app} ? {e}")
            ret = -1

    if packaging_format >= 2:
        from .utils.resources import AppResourceManager

        AppResourceManager(app, wanted={}, current=manifest).apply(
            rollback_and_raise_exception_if_failure=False,
            purge_data_dir=purge,
            action="remove",
        )
    else:
        # Remove all permission in LDAP
        for permission_name in user_permission_list(apps=[app])["permissions"].keys():
            permission_delete(permission_name, force=True, sync_perm=False)

    if packaging_format >= 3:
        try:
            _run_step("after_remove_as_root")
            _run_step("after_remove")
        except Exception as e:
            ret = -1
            logger.error(e)

    rmtree(workdir)

    if purge and os.path.exists(f"/var/log/{app}"):
        rmtree(f"/var/log/{app}")

    if os.path.exists(app_setting_path):
        rmtree(app_setting_path)

    hook_remove(app)

    for domain in domain_list()["domains"]:
        if _get_raw_domain_settings(domain).get("default_app") == app:
            domain_config_set(domain, "feature.app.default_app", "_none")

    if ret == 0:
        if remove_on_failed_install:
            logger.info(m18n.n("app_removed", app=app))
        else:
            logger.success(m18n.n("app_removed", app=app))
        hook_callback("post_app_remove", env=env_dict)
    else:
        logger.warning(m18n.n("app_not_properly_removed", app=app))

    _sync_permissions_with_ldap()
    _assert_system_is_sane_for_app(manifest, "post")


@is_unit_operation()
def app_makedefault(
    operation_logger: "OperationLogger",
    app: str,
    domain: str | None = None,
    undo: bool = False,
) -> None:
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from .domain import _assert_domain_exists, domain_config_set

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


def app_setting(
    app: str,
    key: str,
    value: str | int | dict[str, Any] | None = None,
    delete: bool = False,
) -> str | int | dict[str, Any] | None:
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """
    app_settings = _get_app_settings(app) or {}

    # GET
    if value is None and not delete:
        return app_settings.get(key, None)

    # DELETE
    if delete:
        if key in app_settings:
            del app_settings[key]
        else:
            # Don't call _set_app_settings to avoid unecessary writes...
            return None

    # SET
    else:
        app_settings[key] = value

    _set_app_settings(app, app_settings)

    return None


def app_shell(app: str) -> None:
    """
    Open an interactive shell with the app environment already loaded

    Keyword argument:
        app -- App ID

    """
    import subprocess

    env = _make_environment_for_app_script(app)
    env["PATH"] = os.environ["PATH"]
    subprocess.run(
        [
            "/bin/bash",
            "-c",
            "source /usr/share/yunohost/helpers && ynh_spawn_app_shell " + app,
        ],
        env=env,
    )


def app_register_url(app: str, domain: str, path: str) -> None:
    """
    Book/register a web path for a given app

    Keyword argument:
        app -- App which will use the web path
        domain -- The domain on which the app should be registered (e.g. your.domain.tld)
        path -- The path to be registered (e.g. /coffee)
    """
    from .permission import (
        _sync_permissions_with_ldap,
        permission_url,
        user_permission_update,
    )
    from .utils.form import DomainOption, WebPathOption

    domain = DomainOption.normalize(domain)
    path = WebPathOption.normalize(path)

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
    _sync_permissions_with_ldap()


def app_ssowatconf() -> None:
    """
    Regenerate SSOwat configuration file

    """
    from .domain import (
        _get_domain_portal_dict,
        _get_raw_domain_settings,
        domain_list,
    )
    from .permission import AppPermInfos, user_permission_list
    from .settings import settings_get
    from .utils.file_utils import read_json, write_to_json

    domain_portal_dict = _get_domain_portal_dict()

    domains = domain_list()["domains"]
    portal_domains = domain_list(exclude_subdomains=True)["domains"]
    all_permissions: dict[str, AppPermInfos] = user_permission_list(  # type: ignore
        full=True, ignore_system_perms=True, absolute_urls=True
    )["permissions"]

    permissions = {
        "core_skipped": {
            "users": [],
            "auth_header": False,
            "public": True,
            "uris": [domain + "/yunohost/admin" for domain in domains]
            + [domain + "/yunohost/api" for domain in domains]
            + [domain + "/yunohost/portalapi" for domain in domains]
            + [
                r"re:^[^/]*/502\.html$",
                r"re:^[^/]*/\.well-known/ynh-diagnosis/.*$",
                r"re:^[^/]*/\.well-known/acme-challenge/.*$",
                r"re:^[^/]*/\.well-known/autoconfig/mail/config-v1\.1\.xml.*$",
            ],
        }
    }

    # FIXME : this could be handled by nginx's regen conf to further simplify ssowat's code ...
    redirected_urls = {}
    for domain in domains:
        default_app: str | None = _get_raw_domain_settings(domain).get("default_app")

        if (
            default_app is not None
            and default_app != "_none"
            and _is_installed(default_app)
        ):
            app_settings = _get_app_settings(default_app)
            app_domain = app_settings["domain"]
            app_path = app_settings["path"]

            # Prevent infinite redirect loop...
            if domain + "/" != app_domain + app_path:
                redirected_urls[domain + "/"] = app_domain + app_path
        elif bool(
            _get_raw_domain_settings(domain).get("enable_public_apps_page", False)
        ):
            redirected_urls[domain + "/"] = domain_portal_dict[domain]

    # Will organize apps by portal domain
    portal_domains_apps: dict[str, dict[str, dict]] = {
        domain: {} for domain in portal_domains
    }

    # This check is to prevent an issue during postinstall if the catalog cant
    # be initialized (because of offline postinstall) and it's not a big deal
    # because there's no app yet (this is only used to get the default logo for
    # the app
    if os.path.exists("/etc/yunohost/installed"):
        apps_catalog = _load_apps_catalog()["apps"]
    else:
        apps_catalog = {}

    # New permission system
    for perm_name, perm_info in all_permissions.items():
        uris = list(
            filter(None, [perm_info.get("url"), *perm_info.get("additional_urls", [])])
        )
        # Ignore permissions for which there's no url defined
        if not uris:
            continue

        app_id = perm_name.split(".")[0]
        app_settings = _get_app_settings(app_id)

        if perm_info["auth_header"]:
            if app_settings.get("auth_header"):
                auth_header = app_settings.get("auth_header")
                assert auth_header in ["basic-with-password", "basic-without-password"]
            else:
                auth_header = "basic-with-password"
        else:
            auth_header = False

        permissions[perm_name] = {
            "users": perm_info["corresponding_users"],
            "auth_header": auth_header,
            "public": "visitors" in perm_info["allowed"],
            "uris": uris,
        }

        # Apps can opt out of the auth spoofing protection using this if they really need to,
        # but that's a huge security hole and ultimately should never happen...
        # ... But some apps live caldav/webdav need this to not break external clients x_x
        apps_that_need_external_auth_maybe = [
            "agendav",
            "baikal",
            "ihatemoney",
            "keeweb",
            "monica",
            "my_webdav",
            "nextcloud",
            "owncloud",
            "paheko",
            "radicale",
            "tracim",
            "vikunja",
            "z-push",
        ]
        protect_against_basic_auth_spoofing = app_settings.get(
            "protect_against_basic_auth_spoofing"
        )
        if protect_against_basic_auth_spoofing is not None:
            permissions[perm_name]["protect_against_basic_auth_spoofing"] = (
                protect_against_basic_auth_spoofing
                not in [False, "False", "false", "0", 0]
            )
        elif app_id.split("__")[0] in apps_that_need_external_auth_maybe:
            permissions[perm_name]["protect_against_basic_auth_spoofing"] = False

        # Next: portal related
        # No need to keep apps that aren't supposed to be displayed in portal
        if not perm_info.get("show_tile", False):
            continue

        local_manifest = _get_manifest_of_app(app_id)

        app_domain = uris[0].split("/")[0]
        # get "topest" domain
        app_portal_domain = next(
            domain for domain in portal_domains if domain in app_domain
        )
        app_portal_info = {
            "label": perm_info["label"],
            "users": perm_info["corresponding_users"],
            "public": "visitors" in perm_info["allowed"],
            "url": uris[0],
            "description": perm_info.get("description")
            or local_manifest["description"],
            "order": perm_info.get("order", 100),
        }

        if perm_info.get("hide_from_public"):
            app_portal_info["hide_from_public"] = True

        # Logo may be customized via the perm setting, otherwise we use the default logo that we fetch from the catalog infos
        app_base_id = app_id.split("__")[0]
        # Use the perm logo, or the main-perm logo, or the default logo from catalog
        logo_hash = (
            perm_info.get("logo_hash")
            or all_permissions[f"{app_id}.main"].get("logo_hash")
            or apps_catalog.get(app_base_id, {}).get("logo_hash")
        )
        if logo_hash:
            app_portal_info["logo"] = f"/yunohost/sso/applogos/{logo_hash}.png"

        portal_domains_apps[app_portal_domain][perm_name] = app_portal_info

    conf_dict: dict[str, str | dict] = {
        "cookie_secret_file": "/etc/yunohost/.ssowat_cookie_secret",
        "session_folder": "/var/cache/yunohost-portal/sessions",
        "cookie_name": "yunohost.portal",
        "redirected_urls": redirected_urls,
        "domain_portal_urls": domain_portal_dict,
        "permissions": permissions,
    }

    write_to_json("/etc/ssowat/conf.json", conf_dict, sort_keys=True, indent=4)  # type: ignore[arg-type]

    # Generate a file per possible portal with available apps
    portal_email_settings = {
        k: v
        for k, v in settings_get("security.portal", export=True).items()
        if "allow_edit_email" in k
    }
    for domain, apps in portal_domains_apps.items():
        portal_settings = {}
        portal_settings.update(portal_email_settings)

        portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"
        if portal_settings_path.exists():
            this_domain_portal_settings: dict[str, Any] = read_json(
                str(portal_settings_path)
            )  # type: ignore[assignment]
            portal_settings.update(this_domain_portal_settings)

        # Do no override anything else than "apps" since the file is shared
        # with domain's config panel "portal" options
        portal_settings["apps"] = apps

        write_to_json(
            str(portal_settings_path), portal_settings, sort_keys=True, indent=4
        )

    # Cleanup old files from possibly old domains
    for setting_file in Path(PORTAL_SETTINGS_DIR).iterdir():
        if setting_file.name.endswith(".json"):
            domain = setting_file.name[: -len(".json")]
            if domain not in portal_domains_apps:
                setting_file.unlink()

    logger.debug(m18n.n("ssowat_conf_generated"))


@is_flash_unit_operation()
def app_change_label(app: str, new_label: str) -> None:
    _assert_is_installed(app)

    app_setting(app, "label", new_label)

    # FIXME: we kinda have redundant stuff between the label key on the main perm, and the label key at top level ...
    # or at least this operation should also change the label in the main perm to be consistent ...


def app_action_list(app: str) -> None:
    AppConfigPanel, _ = _get_AppConfigPanel()
    return AppConfigPanel(app).list_actions()


def app_action_run(
    app: str, action: str, args: str | None = None, args_file=None, core: bool = False
) -> None:
    if action.startswith("_core"):
        core = True
    if core:
        _assert_is_installed(app)

        from .utils.form import parse_prefilled_values

        parsedargs = parse_prefilled_values(args)

        _, _, action = action.split(".")
        if action == "force_upgrade":
            app_upgrade(app, force=True)
        elif action == "upgrade":
            app_upgrade(app)
        elif action == "change_url":
            app_change_url(
                app, parsedargs["change_url_domain"], parsedargs["change_url_path"]
            )
        elif action == "uninstall":
            app_remove(app, purge=parsedargs.get("purge", False))
        else:
            raise YunohostValidationError("Unknown app action {action}", raw_msg=True)
        return
    else:
        operation_logger = OperationLogger("app_action_run", [("app", app)])
        AppConfigPanel, _ = _get_AppConfigPanel()
        config_panel = AppConfigPanel(app)
        return config_panel.run_action(
            action, args=args, args_file=args_file, operation_logger=operation_logger
        )


def app_config_get(
    app: str,
    key: str = "",
    full: bool = False,
    export: bool = False,
    core: bool = False,
):
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

    AppConfigPanel, AppCoreConfigPanel = _get_AppConfigPanel()
    try:
        config_ = AppConfigPanel(app) if core is False else AppCoreConfigPanel(app)
        return config_.get(key, mode)
    except YunohostValidationError as e:
        if Moulinette.interface.type == "api" and e.key == "config_no_panel":
            # Be more permissive when no config panel found
            return {}
        else:
            raise


@is_unit_operation()
def app_config_set(
    operation_logger: "OperationLogger",
    app: str,
    key: str | None = None,
    value: Any = None,
    args: str | None = None,
    args_file=None,
    core: bool = False,
) -> None:
    """
    Apply a new app configuration
    """

    AppConfigPanel, AppCoreConfigPanel = _get_AppConfigPanel()
    config_ = AppConfigPanel(app) if core is False else AppCoreConfigPanel(app)

    return config_.set(key, value, args, args_file, operation_logger=operation_logger)


def _get_AppConfigPanel():
    from .utils.configpanel import ConfigPanel

    class AppConfigPanel(ConfigPanel):
        entity_type = "app"
        save_path_tpl = os.path.join(APPS_SETTING_PATH, "{entity}/settings.yml")
        config_path_tpl = os.path.join(APPS_SETTING_PATH, "{entity}/config_panel.toml")
        settings_must_be_defined = True

        def _get_raw_settings(self) -> "RawSettings":
            return self._call_config_script("show")

        def _apply(
            self,
            form: "FormModel",
            config: "ConfigPanelModel",
            previous_settings: dict[str, Any],
            exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
        ) -> None:
            env = {key: str(value) for key, value in form.dict().items()}
            return_content = self._call_config_script("apply", env=env)

            # If the script returned validation error
            # raise a ValidationError exception using
            # the first key
            errors = return_content.get("validation_errors")
            if errors:
                for key, message in errors.items():
                    raise YunohostValidationError(
                        "app_argument_invalid",
                        name=key,
                        error=message,
                    )

        def _run_action(self, form: "FormModel", action_id: str) -> None:
            env = {key: str(value) for key, value in form.dict().items()}
            self._call_config_script(action_id, env=env)

        def _call_config_script(
            self, action: str, env: dict[str, Any] | None = None
        ) -> dict[str, Any]:
            from .hook import hook_exec

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
            app_setting_path = os.path.join(APPS_SETTING_PATH, self.entity)
            app_script_env = _make_environment_for_app_script(
                app, workdir=app_setting_path
            )
            app_script_env.update(env)
            app_script_env["YNH_APP_CONFIG_PANEL_OPTIONS_TYPES_AND_BINDS"] = (
                self._dump_options_types_and_binds()
            )

            ret, values = hook_exec(config_script, args=[action], env=app_script_env)
            if ret != 0:
                if action == "show":
                    raise YunohostError("app_config_unable_to_read")
                elif action == "apply":
                    raise YunohostError("app_config_unable_to_apply")
                else:
                    raise YunohostError("app_action_failed", action=action, app=app)
            return values

        def _get_partial_raw_config(self):
            raw_config = super()._get_partial_raw_config()

            self._compute_binds(raw_config)

            return raw_config

        def _compute_binds(self, raw_config):
            """
            This compute the 'bind' statement for every option
            In particular to handle __FOOBAR__ syntax
            and to handle the fact that bind statements may be defined panel-wide or section-wide
            """

            settings = _get_app_settings(self.entity)

            for panel_id, panel in raw_config.items():
                if not isinstance(panel, dict):
                    continue
                bind_panel = panel.get("bind")
                for section_id, section in panel.items():
                    if not isinstance(section, dict):
                        continue
                    bind_section = section.get("bind")
                    if not bind_section:
                        bind_section = bind_panel
                    elif bind_section[-1] == ":" and bind_panel and ":" in bind_panel:
                        selector, bind_panel_file = bind_panel.split(":")
                        if ">" in bind_section:
                            bind_section = bind_section + bind_panel_file
                        else:
                            bind_section = selector + bind_section + bind_panel_file
                    for option_id, option in section.items():
                        if not isinstance(option, dict):
                            continue
                        bind = option.get("bind")
                        if not bind:
                            if bind_section:
                                bind = bind_section
                            else:
                                bind = "settings"
                        elif bind[-1] == ":" and bind_section and ":" in bind_section:
                            selector, bind_file = bind_section.split(":")
                            if ">" in bind:
                                bind = bind + bind_file
                            else:
                                bind = selector + bind + bind_file
                        if (
                            bind == "settings"
                            and option.get("type", "string") == "file"
                        ):
                            bind = "null"
                        if option.get("type", "string") == "button":
                            bind = "null"

                        option["bind"] = _hydrate_app_template(bind, settings)

        def _dump_options_types_and_binds(self):
            raw_config = self._get_partial_raw_config()
            lines = []
            for panel_id, panel in raw_config.items():
                if not isinstance(panel, dict):
                    continue
                for section_id, section in panel.items():
                    if not isinstance(section, dict):
                        continue
                    for option_id, option in section.items():
                        if not isinstance(option, dict):
                            continue
                        lines.append(
                            "|".join(
                                [
                                    option_id,
                                    option.get("type", "string"),
                                    option["bind"],
                                ]
                            )
                        )
            return "\n".join(lines)

    class AppCoreConfigPanel(ConfigPanel):
        entity_type = "app"

        def __init__(self, entity) -> None:
            self.entity = entity
            self.config_path = self.config_path_tpl.format(
                entity=entity, entity_type=self.entity_type
            )

        def _get_raw_config(self) -> "RawConfig":
            from .user import user_group_list, user_list

            raw_config = super()._get_raw_config()
            i18n_prefix = raw_config["i18n"]

            perm_config_template = raw_config["_core"].pop("permissions")
            special_groups = {g: m18n.n(g) for g in ["visitors", "all_users", "admins"]}
            regular_groups = {
                g: g.title()
                for g in list(
                    user_group_list(include_primary_groups=False)["groups"].keys()
                )
                if g not in special_groups
            }
            users = {
                username: infos["fullname"]
                for username, infos in user_list(fields=["fullname"])["users"].items()
            }

            groups = {**special_groups, **regular_groups, **users}

            perm_config_template["allowed"]["choices"] = list(groups.keys())

            # i18n tweaks
            for k, v in perm_config_template.items():
                v["ask"] = m18n.n(f"{i18n_prefix}_permission_{k}")
                if m18n.key_exists(f"{i18n_prefix}_permission_{k}_help"):
                    v["help"] = m18n.n(f"{i18n_prefix}_permission_{k}_help")

            settings = _get_app_settings(self.entity)
            perms_that_are_not_main = list(settings.get("_permissions", {}).keys())
            if "main" in perms_that_are_not_main:
                perms_that_are_not_main.remove("main")
            for perm in ["main"] + perms_that_are_not_main:
                # Prefix every key with "permission_{perm}_" to make the key unique
                this_perm_config = {
                    f"permission_{perm}_{k}": v for k, v in perm_config_template.items()
                }
                raw_config["_core"][f"permission_{perm}"] = this_perm_config
                if perm != "main":
                    # i18n: app_config_permission_extraperm_section_name
                    section_name = m18n.n(
                        f"{i18n_prefix}_permission_extraperm_section_name", perm=perm
                    )
                    raw_config["_core"][f"permission_{perm}"]["collapsed"] = True
                    raw_config["_core"][f"permission_{perm}"]["name"] = section_name

            return raw_config

        def _get_raw_settings(self) -> "RawSettings":
            from .permission import AppPermInfos, user_permission_list

            perms: dict[str, AppPermInfos] = user_permission_list(
                full=True, apps=[self.entity]
            )["permissions"]  # type: ignore
            app_settings = _get_app_settings(self.entity)
            perms_as_app_settings = app_settings.get("_permissions", {})

            domain, path = app_settings.get("domain"), app_settings.get("path")

            raw_settings = {}

            for perm, infos in perms.items():
                perm = perm.split(".")[1]
                if perm == "main":
                    label = (
                        perms_as_app_settings.get(perm, {}).get("label")
                        or app_settings.get("label")
                        or self.entity.title()
                    )
                else:
                    label = perms_as_app_settings.get(perm, {}).get("label") or perm
                raw_settings[f"permission_{perm}_label"] = label
                raw_settings[f"permission_{perm}_description"] = infos.get(
                    "description", ""
                )
                raw_settings[f"permission_{perm}_show_tile"] = infos["show_tile"]
                if infos.get("url") and domain and path:
                    absolute_url = f"https://{domain}{path}{infos.get('url')}"
                    raw_settings[f"permission_{perm}_location"] = {
                        "ask": m18n.n(
                            "app_config_permission_location", absolute_url=absolute_url
                        )
                    }
                else:
                    raw_settings[f"permission_{perm}_location"] = {"visible": False}
                    raw_settings[f"permission_{perm}_show_tile"] = {
                        "value": False,
                        "visible": False,
                    }
                raw_settings[f"permission_{perm}_url"] = infos.get("url") or ""
                if infos.get("logo_hash"):
                    raw_settings[f"permission_{perm}_logo"] = (
                        f"{APPS_CATALOG_LOGOS}/{infos.get('logo_hash')}.png"
                    )
                else:
                    raw_settings[f"permission_{perm}_logo"] = ""
                raw_settings[f"permission_{perm}_allowed"] = ",".join(infos["allowed"])
                if infos.get("protected"):
                    raw_settings[f"permission_{perm}_allowed"] = {
                        "value": raw_settings[f"permission_{perm}_allowed"],
                        "help": m18n.n("app_config_permission_allowed_warn_protected"),
                    }

            return raw_settings

        def _apply(
            self,
            form: "FormModel",
            config: "ConfigPanelModel",
            previous_settings: dict[str, Any],
            exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
        ) -> None:
            from .user import (
                user_permission_add,
                user_permission_remove,
                user_permission_update,
            )

            next_settings = {
                k: v for k, v in form.dict().items() if previous_settings.get(k) != v
            }

            perm_changes: dict[str, dict[str, Any]] = {}
            for next_setting, value in next_settings.items():
                # next_setting is something like 'permission_main_logo'
                _, perm, key = next_setting.split("_", 2)
                if perm not in perm_changes:
                    perm_changes[perm] = {}
                if key == "logo" and value.strip():
                    value = open(value, "rb")
                perm_changes[perm][key] = value

            for perm, new_infos in perm_changes.items():
                new_allowed = (
                    new_infos.pop("allowed") if "allowed" in new_infos else None
                )

                if new_infos:
                    user_permission_update(f"{self.entity}.{perm}", **new_infos)
                if new_allowed is not None:
                    old_allowed = previous_settings.get(
                        f"permission_{perm}_allowed", ""
                    )
                    old_allowed_set = (
                        set(old_allowed.split(",")) if old_allowed else set()
                    )
                    new_allowed_set = (
                        set(new_allowed.split(",")) if new_allowed else set()
                    )
                    to_add = list(set(new_allowed_set) - set(old_allowed_set))
                    to_remove = list(set(old_allowed_set) - set(new_allowed_set))
                    if to_add:
                        user_permission_add(f"{self.entity}.{perm}", to_add)
                    if to_remove:
                        user_permission_remove(f"{self.entity}.{perm}", to_remove)

    return AppConfigPanel, AppCoreConfigPanel


@is_flash_unit_operation()
def app_dismiss_notification(app: str, name: Literal["post_install", "post_upgrade"]):
    assert isinstance(name, str)
    name_ = name.lower()
    assert name_ in ["post_install", "post_upgrade"]
    _assert_is_installed(app)

    app_setting(app, f"_dismiss_notification_{name_}", value="1")


def regen_mail_app_user_config_for_dovecot_and_postfix(
    only: Literal["dovecot", "postfix"] | None = None,
) -> None:
    dovecot = True if only in [None, "dovecot"] else False
    postfix = True if only in [None, "postfix"] else False

    from .utils.password import _hash_user_password

    postfix_map = []
    dovecot_passwd = []
    for app in _installed_apps():
        settings = _get_app_settings(app)

        if "domain" not in settings or "mail_pwd" not in settings:
            continue

        mail_user = settings.get("mail_user", app)
        mail_domain = settings.get("mail_domain", settings["domain"])

        if dovecot:
            hashed_password = _hash_user_password(settings["mail_pwd"])
            dovecot_passwd.append(
                f"{app}:{hashed_password}::::::allow_nets=::1,127.0.0.1/24,local,mail={mail_user}@{mail_domain}"
            )
        if postfix:
            postfix_map.append(f"{mail_user}@{mail_domain} {app}")

    if dovecot:
        app_senders_passwd = "/etc/dovecot/app-senders-passwd"
        content = "# This file is regenerated automatically.\n# Please DO NOT edit manually ... changes will be overwritten!"
        content += "\n" + "\n".join(dovecot_passwd)
        write_to_file(app_senders_passwd, content)
        chmod(app_senders_passwd, 0o440)
        chown(app_senders_passwd, "root", "dovecot")

    if postfix:
        app_senders_map = "/etc/postfix/app_senders_login_maps"
        content = "# This file is regenerated automatically.\n# Please DO NOT edit manually ... changes will be overwritten!"
        content += "\n" + "\n".join(postfix_map)
        write_to_file(app_senders_map, content)
        chmod(app_senders_map, 0o440)
        chown(app_senders_map, "postfix", "root")
        os.system(f"postmap {app_senders_map} 2>/dev/null")
        chmod(app_senders_map + ".db", 0o640)
        chown(app_senders_map + ".db", "postfix", "root")
