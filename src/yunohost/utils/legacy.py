import os
import re
import glob
from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import (
    read_file,
    write_to_file,
    write_to_json,
    write_to_yaml,
    read_yaml,
)

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
from yunohost.utils.error import YunohostValidationError


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
        "YunoHost automatically translated some legacy rules in /etc/ssowat/conf.json.persistent to match the new permission system"
    )


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
