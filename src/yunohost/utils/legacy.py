import os
from moulinette import m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import write_to_json, read_yaml

from yunohost.user import user_list
from yunohost.app import (
    _installed_apps,
    _get_app_settings,
    _set_app_settings,
)
from yunohost.permission import (
    permission_create,
    user_permission_update,
    permission_sync_to_user,
)

logger = getActionLogger("yunohost.legacy")

LEGACY_PERMISSION_LABEL = {
    ("nextcloud", "skipped"): "api",  # .well-known
    ("libreto", "skipped"): "pad access",  # /[^/]+
    ("leed", "skipped"): "api",  # /action.php, for cron task ...
    ("mailman", "protected"): "admin",  # /admin
    ("prettynoemiecms", "protected"): "admin",  # /admin
    ("etherpad_mypads", "skipped"): "admin",  # /admin
    ("baikal", "protected"): "admin",  # /admin/
    ("couchpotato", "unprotected"): "api",  # /api
    ("freshrss", "skipped"): "api",  # /api/,
    ("portainer", "skipped"): "api",  # /api/webhooks/
    ("jeedom", "unprotected"): "api",  # /core/api/jeeApi.php
    ("bozon", "protected"): "user interface",  # /index.php
    (
        "limesurvey",
        "protected",
    ): "admin",  # /index.php?r=admin,/index.php?r=plugins,/scripts
    ("kanboard", "unprotected"): "api",  # /jsonrpc.php
    ("seafile", "unprotected"): "medias",  # /media
    ("ttrss", "skipped"): "api",  # /public.php,/api,/opml.php?op=publish
    ("libreerp", "protected"): "admin",  # /web/database/manager
    ("z-push", "skipped"): "api",  # $domain/[Aa]uto[Dd]iscover/.*
    ("radicale", "skipped"): "?",  # $domain$path_url
    (
        "jirafeau",
        "protected",
    ): "user interface",  # $domain$path_url/$","$domain$path_url/admin.php.*$
    ("opensondage", "protected"): "admin",  # $domain$path_url/admin/
    (
        "lstu",
        "protected",
    ): "user interface",  # $domain$path_url/login$","$domain$path_url/logout$","$domain$path_url/api$","$domain$path_url/extensions$","$domain$path_url/stats$","$domain$path_url/d/.*$","$domain$path_url/a$","$domain$path_url/$
    (
        "lutim",
        "protected",
    ): "user interface",  # $domain$path_url/stats/?$","$domain$path_url/manifest.webapp/?$","$domain$path_url/?$","$domain$path_url/[d-m]/.*$
    (
        "lufi",
        "protected",
    ): "user interface",  # $domain$path_url/stats$","$domain$path_url/manifest.webapp$","$domain$path_url/$","$domain$path_url/d/.*$","$domain$path_url/m/.*$
    (
        "gogs",
        "skipped",
    ): "api",  # $excaped_domain$excaped_path/[%w-.]*/[%w-.]*/git%-receive%-pack,$excaped_domain$excaped_path/[%w-.]*/[%w-.]*/git%-upload%-pack,$excaped_domain$excaped_path/[%w-.]*/[%w-.]*/info/refs
}


def legacy_permission_label(app, permission_type):
    return LEGACY_PERMISSION_LABEL.get(
        (app, permission_type), "Legacy %s urls" % permission_type
    )


def migrate_legacy_permission_settings(app=None):

    logger.info(m18n.n("migrating_legacy_permission_settings"))
    apps = _installed_apps()

    if app:
        if app not in apps:
            logger.error(
                "Can't migrate permission for app %s because it ain't installed..."
                % app
            )
            apps = []
        else:
            apps = [app]

    for app in apps:

        settings = _get_app_settings(app) or {}
        if settings.get("label"):
            user_permission_update(
                app + ".main", label=settings["label"], sync_perm=False
            )
            del settings["label"]

        def _setting(name):
            s = settings.get(name)
            return s.split(",") if s else []

        skipped_urls = [uri for uri in _setting("skipped_uris") if uri != "/"]
        skipped_urls += ["re:" + regex for regex in _setting("skipped_regex")]
        unprotected_urls = [uri for uri in _setting("unprotected_uris") if uri != "/"]
        unprotected_urls += ["re:" + regex for regex in _setting("unprotected_regex")]
        protected_urls = [uri for uri in _setting("protected_uris") if uri != "/"]
        protected_urls += ["re:" + regex for regex in _setting("protected_regex")]

        if skipped_urls != []:
            permission_create(
                app + ".legacy_skipped_uris",
                additional_urls=skipped_urls,
                auth_header=False,
                label=legacy_permission_label(app, "skipped"),
                show_tile=False,
                allowed="visitors",
                protected=True,
                sync_perm=False,
            )
        if unprotected_urls != []:
            permission_create(
                app + ".legacy_unprotected_uris",
                additional_urls=unprotected_urls,
                auth_header=True,
                label=legacy_permission_label(app, "unprotected"),
                show_tile=False,
                allowed="visitors",
                protected=True,
                sync_perm=False,
            )
        if protected_urls != []:
            permission_create(
                app + ".legacy_protected_uris",
                additional_urls=protected_urls,
                auth_header=True,
                label=legacy_permission_label(app, "protected"),
                show_tile=False,
                allowed=[],
                protected=True,
                sync_perm=False,
            )

        legacy_permission_settings = [
            "skipped_uris",
            "unprotected_uris",
            "protected_uris",
            "skipped_regex",
            "unprotected_regex",
            "protected_regex",
        ]
        for key in legacy_permission_settings:
            if key in settings:
                del settings[key]

        _set_app_settings(app, settings)

        permission_sync_to_user()


def translate_legacy_rules_in_ssowant_conf_json_persistent():

    persistent_file_name = "/etc/ssowat/conf.json.persistent"
    if not os.path.exists(persistent_file_name):
        return

    # Ugly hack because for some reason so many people have tabs in their conf.json.persistent ...
    os.system(r"sed -i 's/\t/    /g' /etc/ssowat/conf.json.persistent")

    # Ugly hack to try not to misarably fail migration
    persistent = read_yaml(persistent_file_name)

    legacy_rules = [
        "skipped_urls",
        "unprotected_urls",
        "protected_urls",
        "skipped_regex",
        "unprotected_regex",
        "protected_regex",
    ]

    if not any(legacy_rule in persistent for legacy_rule in legacy_rules):
        return

    if not isinstance(persistent.get("permissions"), dict):
        persistent["permissions"] = {}

    skipped_urls = persistent.get("skipped_urls", []) + [
        "re:" + r for r in persistent.get("skipped_regex", [])
    ]
    protected_urls = persistent.get("protected_urls", []) + [
        "re:" + r for r in persistent.get("protected_regex", [])
    ]
    unprotected_urls = persistent.get("unprotected_urls", []) + [
        "re:" + r for r in persistent.get("unprotected_regex", [])
    ]

    known_users = list(user_list()["users"].keys())

    for legacy_rule in legacy_rules:
        if legacy_rule in persistent:
            del persistent[legacy_rule]

    if skipped_urls:
        persistent["permissions"]["custom_skipped"] = {
            "users": [],
            "label": "Custom permissions - skipped",
            "show_tile": False,
            "auth_header": False,
            "public": True,
            "uris": skipped_urls
            + persistent["permissions"].get("custom_skipped", {}).get("uris", []),
        }

    if unprotected_urls:
        persistent["permissions"]["custom_unprotected"] = {
            "users": [],
            "label": "Custom permissions - unprotected",
            "show_tile": False,
            "auth_header": True,
            "public": True,
            "uris": unprotected_urls
            + persistent["permissions"].get("custom_unprotected", {}).get("uris", []),
        }

    if protected_urls:
        persistent["permissions"]["custom_protected"] = {
            "users": known_users,
            "label": "Custom permissions - protected",
            "show_tile": False,
            "auth_header": True,
            "public": False,
            "uris": protected_urls
            + persistent["permissions"].get("custom_protected", {}).get("uris", []),
        }

    write_to_json(persistent_file_name, persistent, sort_keys=True, indent=4)

    logger.warning(
        "Yunohost automatically translated some legacy rules in /etc/ssowat/conf.json.persistent to match the new permission system"
    )
