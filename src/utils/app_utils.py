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

import copy
import os
import re
import shutil
import subprocess
import time
from logging import getLogger
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Iterator,
    Literal,
    TypedDict,
    cast,
)

import yaml
from moulinette import Moulinette, m18n
from .file_utils import (
    chmod,
    chown,
    cp,
    read_file,
    read_json,
    read_toml,
)
from .process import check_output
from packaging import version

from .error import YunohostError, YunohostValidationError
from .i18n import _value_for_locale
from .system import (
    binary_to_human,
    debian_version,
    dpkg_is_broken,
    free_space_in_directory,
    get_ynh_package_version,
    human_to_binary,
    ram_available,
    system_arch,
)

if TYPE_CHECKING:
    from .logging import YunohostLogger

    logger = cast(YunohostLogger, getLogger("yunohost.app"))
else:
    logger = getLogger("yunohost.app")

APPS_SETTING_PATH = "/etc/yunohost/apps/"
APPS_TMP_WORKDIRS = "/var/cache/yunohost/app_tmp_work_dirs"
GIT_CLONE_CACHE = "/var/cache/yunohost/gitclones"

re_app_instance_name = re.compile(
    r"^(?P<appid>[\w-]+?)(__(?P<appinstancenb>[1-9][0-9]*))?$"
)

APP_REPO_URL = re.compile(
    r"^https://[a-zA-Z0-9-_.]+/[a-zA-Z0-9-_./~]+/[a-zA-Z0-9-_.]+_ynh(/?(-/)?(tree|src/(branch|tag|commit))/[a-zA-Z0-9-_.]+)?(\.git)?/?$"
)

# TODO: lol
# Ideally this should be a readonly / frozen dict ?
AppManifest = dict[str, Any]


def _confirm_app_install(app: str, force: bool = False) -> None:
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


app_settings_cache: dict[str, dict[str, Any]] = {}
app_settings_cache_timestamp: dict[str, float] = {}


def _get_app_settings(app: str) -> dict[str, Any]:
    """
    Get settings of an installed app

    Keyword arguments:
        app -- The app id (like nextcloud__2)

    """
    _assert_is_installed(app)

    app_setting_path = os.path.join(APPS_SETTING_PATH, app, "settings.yml")
    app_setting_timestamp = os.path.getmtime(app_setting_path)

    # perf: app settings are cached using the settings.yml's modification date,
    # such that we don't have to worry too much about calling this function
    # too many times (because ultimately parsing yml is not free)
    if app_settings_cache_timestamp.get(app) == app_setting_timestamp:
        return app_settings_cache[app].copy()

    try:
        with open(app_setting_path) as f:
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

        # Make the app id available as $app too
        settings["app"] = app

        # FIXME: it's not clear why this code exists... Shouldn't we hard-define 'id' as $app ...?
        if app != settings["id"]:
            return {}

        # Cache the settings
        app_settings_cache[app] = settings.copy()
        app_settings_cache_timestamp[app] = app_setting_timestamp

        return settings
    except (IOError, TypeError, KeyError):
        logger.error(m18n.n("app_not_correctly_installed", app=app))
    return {}


def _set_app_settings(app: str, settings: dict[str, Any]) -> None:
    """
    Set settings of an app

    Keyword arguments:
        app_id -- The app id (like nextcloud__2)
        settings -- Dict with app settings

    """
    with open(os.path.join(APPS_SETTING_PATH, app, "settings.yml"), "w") as f:
        yaml.safe_dump(settings, f, default_flow_style=False)

    if app in app_settings_cache_timestamp:
        del app_settings_cache_timestamp[app]
    if app in app_settings_cache:
        del app_settings_cache[app]


def _get_app_label(app: str, manifest: AppManifest | None = None) -> str:
    _assert_is_installed(app)
    settings = _get_app_settings(app)
    main_perm = settings.get("_permissions", {}).get("main", {})

    if main_perm.get("label"):
        return main_perm["label"]
    elif settings.get("label"):
        return settings["label"]
    elif manifest:
        # This case is just to provide a manifest to avoid re-fetching
        # the manifest when the upper scope already has it
        return manifest["name"]
    else:
        return _get_manifest_of_app(app)["name"]


def _parse_app_version(v: str) -> tuple[version.Version, int]:
    if v in ["?", "-"]:
        return (version.parse("0"), 0)

    try:
        if "~" in v:
            return (
                version.parse(v.split("~")[0]),
                int(v.split("~")[1].replace("ynh", "")),
            )
        else:
            return (version.parse(v), 0)
    except Exception as e:
        raise YunohostError(f"Failed to parse app version '{v}' : {e}", raw_msg=True)


app_manifests_cache: dict[str, AppManifest] = {}
app_manifests_cache_timestamp: dict[str, float] = {}


def _get_manifest_of_app(path_or_app_id: str) -> AppManifest:
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

    if "/" in path_or_app_id:
        path = Path(path_or_app_id)
    else:
        path = Path(APPS_SETTING_PATH) / path_or_app_id

    if (path / "manifest.toml").exists():
        manifest_path = path / "manifest.toml"
        read_manifest = read_toml
    elif (path / "manifest.json").exists():
        manifest_path = path / "manifest.json"
        read_manifest = read_json
    else:
        raise YunohostError(
            f"There doesn't seem to be any manifest file in {path} ... It looks like an app was not correctly installed/removed.",
            raw_msg=True,
        )

    # Check cache
    if path_or_app_id in app_manifests_cache:
        cache_timestamp = app_manifests_cache_timestamp[path_or_app_id]
        manifest_and_doc_timestamps = [manifest_path.stat().st_mtime]
        manifest_and_doc_timestamps += [
            p.stat().st_mtime for p in (path / "doc").rglob("*")
        ]
        if cache_timestamp > max(manifest_and_doc_timestamps):
            return copy.deepcopy(app_manifests_cache[path_or_app_id])

    manifest: AppManifest = read_manifest(str(manifest_path))  # type: ignore[assignment]

    manifest["packaging_format"] = float(
        str(manifest.get("packaging_format", "")).strip() or "0"
    )

    if manifest["packaging_format"] < 2:
        manifest = _convert_v1_manifest_to_v2(manifest)

    manifest["install"] = _set_default_ask_questions(manifest.get("install", {}))
    manifest["doc"], manifest["notifications"] = _parse_app_doc_and_notifications(path)

    # Cache the result ... but only for "raw" app names, not paths,
    # which are likely just temporary and would fill the cache with stuff that's not likely to be useful?
    if "/" not in path_or_app_id:
        app_manifests_cache[path_or_app_id] = manifest
        app_manifests_cache_timestamp[path_or_app_id] = time.time()

    return copy.deepcopy(manifest)


AppDocDict = dict[str, dict[str, str]]
AppNotificationsDict = dict[str, dict[str, dict[str, str]]]


def _parse_app_doc_and_notifications(
    path: Path,
) -> tuple[AppDocDict, AppNotificationsDict]:
    doc: AppDocDict = {}
    notification_names = ["PRE_INSTALL", "POST_INSTALL", "PRE_UPGRADE", "POST_UPGRADE"]

    for filepath in (path / "doc").glob("*.md"):
        # to be improved : [a-z]{2,3} is a clumsy way of parsing the
        # lang code ... some lang code are more complex that this é_è
        m = re.match("([A-Z]*)(_[a-z]{2,3})?.md", str(filepath).split("/")[-1])

        if not m:
            # FIXME: shall we display a warning ? idk
            continue

        pagename, lang = m.groups()

        if pagename in notification_names:
            continue

        lang = lang.strip("_") if lang else "en"

        if pagename not in doc:
            doc[pagename] = {}

        try:
            doc[pagename][lang] = read_file(str(filepath)).strip()
        except Exception as e:
            logger.error(e)
            continue

    notifications: AppNotificationsDict = {}

    for step in notification_names:
        notifications[step] = {}
        for filepath in (path / "doc").glob(f"{step}*.md"):
            m = re.match(step + "(_[a-z]{2,3})?.md", str(filepath).split("/")[-1])
            if not m:
                continue
            pagename = "main"
            lang = m.groups()[0].strip("_") if m.groups()[0] else "en"
            if pagename not in notifications[step]:
                notifications[step][pagename] = {}
            try:
                notifications[step][pagename][lang] = read_file(str(filepath)).strip()
            except Exception as e:
                logger.error(e)
                continue

        for filepath in (path / "doc" / f"{step}.d").glob("*.md"):
            m = re.match(
                r"([A-Za-z0-9\.\~]*)(_[a-z]{2,3})?.md", str(filepath).split("/")[-1]
            )
            if not m:
                continue
            pagename, lang = m.groups()
            lang = lang.strip("_") if lang else "en"
            if pagename not in notifications[step]:
                notifications[step][pagename] = {}

            try:
                notifications[step][pagename][lang] = read_file(str(filepath)).strip()
            except Exception as e:
                logger.error(e)
                continue

    return doc, notifications


def _hydrate_app_template(template: str, data: dict[str, Any]):
    # Apply jinja for stuff like {% if .. %} blocks,
    # but only if there's indeed an if block (to try to reduce overhead or idk)
    if "{%" in template:
        from jinja2 import Template

        template = Template(template).render(**data)

    stuff_to_replace = set(re.findall(r"__[A-Z0-9]+?[A-Z0-9_]*?[A-Z0-9]*?__", template))

    for stuff in stuff_to_replace:
        varname = stuff.strip("_").lower()

        if varname in data:
            template = template.replace(stuff, str(data[varname]))

    return template.strip()


def _convert_v1_manifest_to_v2(manifest: dict[str, Any]) -> AppManifest:
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


def _set_default_ask_questions(questions: dict[str, Any], script_name: str = "install"):
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

    for question_id, question in questions.items():
        question["id"] = question_id

        # If this question corresponds to a question with default ask message...
        if any(
            (question.get("type"), question["id"]) == question_with_default
            for question_with_default in questions_with_default
        ):
            # The key is for example "app_manifest_install_ask_domain"
            question["ask"] = m18n.n(f"app_manifest_{script_name}_ask_{question['id']}")

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


def _app_quality(src: str) -> Literal["success", "warning", "danger", "thirdparty"]:
    """
    app may in fact be an app name, an url, or a path
    """

    from ..app_catalog import _load_apps_catalog

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


def _extract_app(src: str) -> tuple[AppManifest, str]:
    """
    src may be an app name, an url, or a path
    """

    from ..app_catalog import _load_apps_catalog

    raw_app_catalog = _load_apps_catalog()["apps"]

    # App is an appname in the catalog
    if src in raw_app_catalog:
        if "git" not in raw_app_catalog[src]:
            raise YunohostValidationError("app_unsupported_remote_type")

        app_info = raw_app_catalog[src]
        url = app_info["git"]["url"]
        branch = app_info["git"]["branch"]
        revision = str(app_info["git"]["revision"])
        return _extract_app_from_gitrepo(
            url, branch=branch, revision=revision, app_info=app_info
        )
    # App is a git repo url
    elif _is_app_repo_url(src):
        url = src.strip().strip("/")
        # gitlab urls may look like 'https://domain/org/group/repo/-/tree/testing'
        # compated to github urls looking like 'https://domain/org/repo/tree/testing'
        if "/-/" in url:
            url = url.replace("/-/", "/")
        if "/tree/" in url:
            url, branch = url.split("/tree/", 1)
        else:
            branch = None
        return _extract_app_from_gitrepo(url, branch=branch)
    # App is a local folder
    elif os.path.exists(src):
        return _extract_app_from_folder(src)
    else:
        if "http://" in src or "https://" in src:
            logger.error(
                f"{src} is not a valid app url: app url are expected to look like https://domain.tld/path/to/repo_ynh"
            )
        raise YunohostValidationError("app_unknown")


def _extract_app_from_folder(path: str) -> tuple[AppManifest, str]:
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
        # Change the last edit time which is used in _make_tmp_workdir_for_app
        # to cleanup old dir ... otherwise it may end up being incorrectly removed
        # at the end of the safety-backup-before-upgrade :/
        os.system(f"touch {extracted_app_folder}")
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


def _git_clone_light(
    dest_dir: str, url: str, branch: str | None = None, revision: str = "HEAD"
) -> str:
    # Cleanup stale caches (older than 24 hours)
    if not Path(GIT_CLONE_CACHE).exists():
        os.makedirs(GIT_CLONE_CACHE)
        chmod(GIT_CLONE_CACHE, 0o700)
        chown(GIT_CLONE_CACHE, "root", "root")

    for cache in Path(GIT_CLONE_CACHE).iterdir():
        if cache.is_dir() and (time.time() - cache.stat().st_ctime) > 24 * 3600:
            try:
                shutil.rmtree(cache)
            except Exception as e:
                logger.debug(f"Uhoh, failed to cleanup cache {cache} ? {e}")

    # There's a cache mechanism to avoid re-git-cloning the same stuff over and over again
    # which can be ~costly, for example when checking up the PRE-UPGRADE notifs for app upgrades
    if revision != "HEAD":
        git_clone_cache = Path(GIT_CLONE_CACHE) / revision
        if git_clone_cache.exists():
            logger.debug(
                f"Reusing cache for {url} (branch={branch}, revision={revision}"
            )
            shutil.copytree(git_clone_cache, dest_dir, dirs_exist_ok=True)
            return revision

    logger.debug(f"Fetching {url} (branch={branch}, revision={revision}")

    git_ls_remote = check_output(
        ["git", "ls-remote", "--symref", url, "HEAD"],
        env={"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"},
        shell=False,
    )

    if not branch:
        default_branch = None
        try:
            for line in git_ls_remote.split("\n"):
                # Look for the line formated like :
                # ref: refs/heads/master	HEAD
                if "ref: refs/heads/" in line:
                    line = line.replace("/", " ").replace("\t", " ")
                    default_branch = line.split()[3]
        except Exception:
            pass

        if not default_branch:
            logger.warning("Failed to parse default branch, trying 'main'")
            branch = "main"
        else:
            if default_branch in ["testing", "dev"]:
                logger.warning(
                    f"Trying 'master' branch instead of default '{default_branch}'"
                )
                branch = "master"
            else:
                branch = default_branch

    logger.debug(m18n.n("downloading"))

    # Download only specified commit
    # We don't use git clone because, git clone can't download
    # a specific revision only
    ref = branch if revision == "HEAD" else revision
    assert ref
    subprocess.check_call(
        ["git", "init", dest_dir], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    cmds = [
        ["git", "remote", "add", "origin", url],
        ["git", "fetch", "--depth=1", "origin", ref],
        ["git", "reset", "--hard", "FETCH_HEAD"],
    ]
    for cmd in cmds:
        subprocess.check_call(
            cmd, cwd=dest_dir, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )

    logger.debug(m18n.n("done"))

    if revision == "HEAD":
        try:
            # Get git last commit hash
            cmd2 = f"git ls-remote --exit-code {url} {branch} | awk '{{print $1}}'"
            actual_revision = check_output(cmd2)
        except Exception as e:
            logger.warning(f"cannot get last commit hash because: {e}")
            actual_revision = "HEAD"
    else:
        actual_revision = revision
        # Save as cache
        git_clone_cache = Path(GIT_CLONE_CACHE) / revision
        if git_clone_cache.exists():
            shutil.rmtree(git_clone_cache)
        shutil.copytree(dest_dir, git_clone_cache)

    return actual_revision


def _extract_app_from_gitrepo(
    url: str, branch: str | None = None, revision: str = "HEAD", app_info: dict = {}
) -> tuple[AppManifest, str]:
    extracted_app_folder = _make_tmp_workdir_for_app()

    try:
        actual_revision = _git_clone_light(extracted_app_folder, url, branch, revision)
    except Exception as e:
        logger.error(e)
        raise YunohostError("app_sources_fetch_failed")
    else:
        logger.debug(m18n.n("done"))

    manifest = _get_manifest_of_app(extracted_app_folder)

    # Store remote repository info into the returned manifest
    manifest["remote"] = {
        "type": "git",
        "url": url,
        "branch": branch,
        "revision": actual_revision,
    }
    if revision != "HEAD":
        manifest["lastUpdate"] = app_info.get("lastUpdate")

    manifest["quality"] = {
        "level": app_info.get("level", -1),
        "state": app_info.get("state", "thirdparty"),
    }
    manifest["antifeatures"] = app_info.get("antifeatures", [])
    manifest["potential_alternative_to"] = app_info.get("potential_alternative_to", [])

    return manifest, extracted_app_folder


def _is_installed(app: str) -> bool:
    return os.path.isdir(APPS_SETTING_PATH + app)


def _assert_is_installed(app: str) -> None:
    if not _is_installed(app):
        installed_apps = "\n - " + "\n - ".join(sorted(_installed_apps()))
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=installed_apps
        )


def _installed_apps() -> list[str]:
    return os.listdir(APPS_SETTING_PATH)


class AppRequirementCheckResult(TypedDict):
    id: str
    passed: bool
    error: str


def _check_manifest_requirements(
    manifest: AppManifest, action: Literal["install", "upgrade"], app: str
) -> Iterator[AppRequirementCheckResult]:
    """Check if required packages are met from the manifest"""

    app_base_id = manifest["id"]
    logger.debug(m18n.n("app_requirements_checking", app=app))

    # Packaging format
    if manifest["packaging_format"] not in [1, 2]:
        raise YunohostValidationError("app_packaging_format_not_supported")

    # Yunohost version
    required_yunohost_version = (
        manifest["integration"].get("yunohost", "4.3").strip(">= ")
    )
    current_yunohost_version = get_ynh_package_version("yunohost")["version"]

    yield {
        "id": "required_yunohost_version",
        "passed": version.parse(required_yunohost_version)
        <= version.parse(current_yunohost_version),
        "error": m18n.n(
            "app_yunohost_version_not_supported",
            current=current_yunohost_version,
            required=required_yunohost_version,
        ),
    }

    # Architectures
    arch_requirement = manifest["integration"]["architectures"]
    arch = system_arch()

    yield {
        "id": "arch",
        "passed": arch_requirement in ["all", "?"] or arch in arch_requirement,
        "error": m18n.n(
            "app_arch_not_supported",
            current=arch,
            required=", ".join(arch_requirement)
            if arch_requirement != "all"
            else "all",
        ),
    }

    # Multi-instance
    if action == "install":
        multi_instance = manifest["integration"]["multi_instance"] is True
        if not multi_instance:
            apps = _installed_apps()
            sibling_apps = [
                a for a in apps if a == app_base_id or a.startswith(f"{app_base_id}__")
            ]
            multi_instance = len(sibling_apps) == 0

        yield {
            "id": "install",
            "passed": multi_instance,
            "error": m18n.n("app_already_installed", app=app_base_id),
        }

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

        yield {
            "id": "disk",
            "passed": has_enough_disk,
            "error": m18n.n(
                "app_not_enough_disk",
                current=free_space,
                required=manifest["integration"]["disk"],
            ),
        }

    # Ram
    ram_requirement = manifest["integration"]["ram"]
    ram, swap = ram_available()
    # Is "include_swap" really useful ? We should probably decide wether to always include it or not instead
    if ram_requirement.get("include_swap", False):
        ram += swap

    if ram_requirement["build"] == "?" or ram > human_to_binary(
        ram_requirement["build"]
    ):
        can_build = True
    # When upgrading, compare the available ram to (build - runtime), because the app is already running
    elif (
        action == "upgrade"
        and ram_requirement["runtime"] != "?"
        and ram
        > human_to_binary(ram_requirement["build"])
        - human_to_binary(ram_requirement["runtime"])
    ):
        can_build = True
    else:
        can_build = False

    # Before upgrading, the application is probably already running,
    # and RAM rarely increases significantly from one version to the next.
    can_run = (
        ram_requirement["runtime"] == "?"
        or ram > human_to_binary(ram_requirement["runtime"])
        or action == "upgrade"
    )

    # Some apps have a higher runtime value than build ...
    if ram_requirement["build"] != "?" and ram_requirement["runtime"] != "?":
        max_build_runtime = (
            ram_requirement["build"]
            if human_to_binary(ram_requirement["build"])
            > human_to_binary(ram_requirement["runtime"])
            else ram_requirement["runtime"]
        )
    elif ram_requirement["build"] != "?":
        max_build_runtime = ram_requirement["build"]
    else:
        max_build_runtime = ram_requirement["runtime"]

    yield {
        "id": "ram",
        "passed": can_build and can_run,
        "error": m18n.n(
            "app_not_enough_ram",
            current=binary_to_human(ram),
            required=max_build_runtime,
        ),
    }


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
        if manifest.get("packaging_format", 0) < 2:
            # This is likely to be a full-domain app...

            # Confirm that this is a full-domain app This should cover most cases
            # ...  though anyway the proper solution is to implement some mechanism
            # in the manifest for app to declare that they require a full domain
            # (among other thing) so that we can dynamically check/display this
            # requirement on the webadmin form and not miserably fail at submit time

            # Full-domain apps typically declare something like path_url="/" or path=/
            # and use ynh_webpath_register or yunohost_app_checkurl inside the install script
            install_script_content = read_file(
                os.path.join(app_folder, "scripts/install")
            )

            if re.search(
                r"\npath(_url)?=[\"']?/[\"']?", install_script_content
            ) and re.search(r"ynh_webpath_register", install_script_content):
                return "full_domain"

        else:
            # For packaging v2 apps, check if there's a permission with url being a string
            perm_resource = manifest.get("resources", {}).get("permissions")
            if perm_resource is not None and isinstance(
                perm_resource.get("main", {}).get("url"), str
            ):
                return "full_domain"

    return "?"


def _validate_webpath_requirement(
    args: dict[str, Any], path_requirement: str, ignore_app: str | None = None
) -> None:
    domain = args.get("domain")
    path = args.get("path")

    if not domain and not path:
        return None

    if path_requirement == "domain_and_path":
        assert domain and path
        _assert_no_conflicting_apps(domain, path, ignore_app=ignore_app)

    elif path_requirement == "full_domain":
        assert domain
        _assert_no_conflicting_apps(
            domain, "/", full_domain=True, ignore_app=ignore_app
        )


def _get_conflicting_apps(
    domain: str, path: str, ignore_app: str | None = None
) -> list[tuple[str, str, str]]:
    """
    Return a list of all conflicting apps with a domain/path (it can be empty)

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
        ignore_app -- An optional app id to ignore (c.f. the change_url usecase)
    """

    from ..app import app_map
    from ..domain import _assert_domain_exists
    from .form import DomainOption, WebPathOption

    domain = DomainOption.normalize(domain)
    path = WebPathOption.normalize(path)

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
            if path == p or (
                not (path.startswith("/.well-known/") or p.startswith("/.well-known/"))
                and (path == "/" or p == "/")
            ):
                conflicts.append((p, a["id"], a["label"]))

    return conflicts


def _assert_no_conflicting_apps(
    domain: str, path: str, ignore_app: str | None = None, full_domain: bool = False
) -> None:
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
    app,
    args={},
    args_prefix="APP_ARG_",
    workdir=None,
    action=None,
    force_include_app_settings=False,
) -> dict[str, str]:
    from ..log import OperationLogger

    manifest = _get_manifest_of_app(workdir if workdir else app)

    app_id, app_instance_nb = _parse_app_instance_name(app)

    env_dict = {
        "YNH_DEFAULT_PHP_VERSION": "8.2",
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
        "YNH_APP_MANIFEST_VERSION": manifest.get("version", "?"),
        "YNH_APP_PACKAGING_FORMAT": str(manifest["packaging_format"]),
        "YNH_HELPERS_VERSION": str(
            manifest.get("integration", {}).get("helpers_version")
            or manifest["packaging_format"]
        ).replace(".0", ""),
        "YNH_ARCH": system_arch(),
        "YNH_DEBIAN_VERSION": debian_version(),
    }

    if workdir:
        env_dict["YNH_APP_BASEDIR"] = workdir

    if action:
        env_dict["YNH_APP_ACTION"] = action

    for arg_name, arg_value in args.items():
        arg_name_upper = arg_name.upper()
        env_dict[f"YNH_{args_prefix}{arg_name_upper}"] = str(arg_value)

    # If packaging format v2, load all settings
    if manifest["packaging_format"] >= 2 or force_include_app_settings:
        env_dict["app"] = app
        data_to_redact = []
        prefixes_or_suffixes_to_redact = [
            "pwd",
            "pass",
            "passwd",
            "password",
            "passphrase",
            "secret",
            "key",
            "token",
        ]

        for setting_name, setting_value in _get_app_settings(app).items():
            # Ignore special internal settings like checksum__
            # (not a huge deal to load them but idk...)
            if setting_name.startswith("checksum__"):
                continue

            setting_value = str(setting_value)
            env_dict[setting_name] = setting_value

            # Check if we should redact this setting value
            # (the check on the setting length exists to prevent stupid stuff like redacting empty string or something which is actually just 0/1, true/false, ...
            if len(setting_value) > 6 and any(
                setting_name.startswith(p) or setting_name.endswith(p)
                for p in prefixes_or_suffixes_to_redact
            ):
                data_to_redact.append(setting_value)

        # Special weird case for backward compatibility...
        # 'path' was loaded into 'path_url' .....
        if "path" in env_dict:
            env_dict["path_url"] = env_dict["path"]

        for operation_logger in OperationLogger._instances:
            operation_logger.data_to_redact.extend(data_to_redact)

    return env_dict


def _parse_app_instance_name(app_instance_name: str) -> tuple[str, int]:
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


def _next_instance_number_for_app(app: str) -> int:
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


def _make_tmp_workdir_for_app(app: str | None = None) -> str:
    from tempfile import mkdtemp

    # Create parent dir if it doesn't exists yet
    if not os.path.exists(APPS_TMP_WORKDIRS):
        os.makedirs(APPS_TMP_WORKDIRS)

    now = int(time.time())

    # Cleanup old dirs (if any)
    for dir_ in os.listdir(APPS_TMP_WORKDIRS):
        path = os.path.join(APPS_TMP_WORKDIRS, dir_)
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

    tmpdir = mkdtemp(prefix="app_", dir=APPS_TMP_WORKDIRS)

    # Copy existing app scripts, conf, ... if an app arg was provided
    if app:
        os.system(f"cp -a {APPS_SETTING_PATH}/{app}/* {tmpdir}")

    return tmpdir


def _assert_system_is_sane_for_app(manifest: AppManifest, when: Literal["pre", "post"]):
    from ..service import service_status

    logger.debug("Checking that required services are up and running...")

    # FIXME: in the past we had more elaborate checks about mariadb/php/postfix
    # though they werent very formalized. Ideally we should rework this in the
    # context of packaging v2, which implies deriving what services are
    # relevant to check from the manifst

    services = ["nginx", "fail2ban"]

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


def _notification_is_dismissed(name, settings):
    # Check for _dismiss_notiication_$name setting and also auto-dismiss
    # notifications after one week (otherwise people using mostly CLI would
    # never really dismiss the notification and it would be displayed forever)

    if name == "POST_INSTALL":
        return (
            settings.get("_dismiss_notification_post_install")
            or (int(time.time()) - settings.get("install_time", 0)) / (24 * 3600) > 7
        )
    elif name == "POST_UPGRADE":
        # Check on update_time also implicitly prevent the post_upgrade notification
        # from being displayed after install, because update_time is only set during upgrade
        return (
            settings.get("_dismiss_notification_post_upgrade")
            or (int(time.time()) - settings.get("update_time", 0)) / (24 * 3600) > 7
        )
    else:
        return False


def _filter_and_hydrate_notifications(
    notifications, current_version=None, data={}
) -> dict[str, str]:
    def is_version_more_recent_than_current_version(name, current_version):
        current_version = str(current_version)
        return _parse_app_version(name) > _parse_app_version(current_version)

    out = {
        # Should we render the markdown maybe? idk
        name: _hydrate_app_template(_value_for_locale(content_per_lang), data)
        for name, content_per_lang in notifications.items()
        if current_version is None
        or name == "main"
        or is_version_more_recent_than_current_version(name, current_version)
    }

    # Filter out empty notifications (notifications may be empty because of if blocks)
    return {
        name: content for name, content in out.items() if content and content.strip()
    }


def _display_notifications(notifications: dict[str, str], force=False) -> None:
    if not notifications:
        return

    for name, content in notifications.items():
        print("==========")
        print(content)
    print("==========")

    # i18n: confirm_notifications_read
    _ask_confirmation("confirm_notifications_read", kind="simple", force=force)


def _ask_confirmation(
    question: str,
    params: dict = {},
    kind: Literal["simple", "soft", "hard"] = "hard",
    force: bool = False,
) -> None:
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
