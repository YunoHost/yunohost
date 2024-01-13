#
# Copyright (c) 2024 YunoHost Contributors
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
import re
import glob
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import (
    read_file,
    write_to_file,
    write_to_yaml,
    write_to_json,
    read_yaml,
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

LEGACY_SETTINGS = {
    "security.password.admin.strength": "security.password.admin_strength",
    "security.password.user.strength": "security.password.user_strength",
    "security.ssh.compatibility": "security.ssh.ssh_compatibility",
    "security.ssh.port": "security.ssh.ssh_port",
    "security.ssh.password_authentication": "security.ssh.ssh_password_authentication",
    "security.nginx.redirect_to_https": "security.nginx.nginx_redirect_to_https",
    "security.nginx.compatibility": "security.nginx.nginx_compatibility",
    "security.postfix.compatibility": "security.postfix.postfix_compatibility",
    "pop3.enabled": "email.pop3.pop3_enabled",
    "smtp.allow_ipv6": "email.smtp.smtp_allow_ipv6",
    "smtp.relay.host": "email.smtp.smtp_relay_host",
    "smtp.relay.port": "email.smtp.smtp_relay_port",
    "smtp.relay.user": "email.smtp.smtp_relay_user",
    "smtp.relay.password": "email.smtp.smtp_relay_password",
    "backup.compress_tar_archives": "misc.backup.backup_compress_tar_archives",
    "ssowat.panel_overlay.enabled": "misc.portal.ssowat_panel_overlay_enabled",
    "security.webadmin.allowlist.enabled": "security.webadmin.webadmin_allowlist_enabled",
    "security.webadmin.allowlist": "security.webadmin.webadmin_allowlist",
    "security.experimental.enabled": "security.experimental.security_experimental_enabled",
}


def translate_legacy_settings_to_configpanel_settings(settings):
    return LEGACY_SETTINGS.get(settings, settings)


def legacy_permission_label(app, permission_type):
    return LEGACY_PERMISSION_LABEL.get(
        (app, permission_type), "Legacy %s urls" % permission_type
    )


def translate_legacy_default_app_in_ssowant_conf_json_persistent():
    from yunohost.app import app_list
    from yunohost.domain import domain_config_set

    persistent_file_name = "/etc/ssowat/conf.json.persistent"
    if not os.path.exists(persistent_file_name):
        return

    # Ugly hack because for some reason so many people have tabs in their conf.json.persistent ...
    os.system(r"sed -i 's/\t/    /g' /etc/ssowat/conf.json.persistent")

    # Ugly hack to try not to misarably fail migration
    persistent = read_yaml(persistent_file_name)

    if "redirected_urls" not in persistent:
        return

    redirected_urls = persistent["redirected_urls"]

    if not any(
        from_url.count("/") == 1 and from_url.endswith("/")
        for from_url in redirected_urls
    ):
        return

    apps = app_list()["apps"]

    if not any(app.get("domain_path") in redirected_urls.values() for app in apps):
        return

    for from_url, dest_url in redirected_urls.copy().items():
        # Not a root domain, skip
        if from_url.count("/") != 1 or not from_url.endswith("/"):
            continue
        for app in apps:
            if app.get("domain_path") != dest_url:
                continue
            domain_config_set(from_url.strip("/"), "feature.app.default_app", app["id"])
            del redirected_urls[from_url]

    persistent["redirected_urls"] = redirected_urls

    write_to_json(persistent_file_name, persistent, sort_keys=True, indent=4)

    logger.warning(
        "YunoHost automatically translated some legacy redirections in /etc/ssowat/conf.json.persistent to match the new default application using domain configuration"
    )


LEGACY_PHP_VERSION_REPLACEMENTS = [
    ("/etc/php5", "/etc/php/7.4"),
    ("/etc/php/7.0", "/etc/php/7.4"),
    ("/etc/php/7.3", "/etc/php/7.4"),
    ("/var/run/php5-fpm", "/var/run/php/php7.4-fpm"),
    ("/var/run/php/php7.0-fpm", "/var/run/php/php7.4-fpm"),
    ("/var/run/php/php7.3-fpm", "/var/run/php/php7.4-fpm"),
    ("php5", "php7.4"),
    ("php7.0", "php7.4"),
    ("php7.3", "php7.4"),
    ('YNH_PHP_VERSION="7.3"', 'YNH_PHP_VERSION="7.4"'),
    (
        'phpversion="${phpversion:-7.0}"',
        'phpversion="${phpversion:-7.4}"',
    ),  # Many helpers like the composer ones use 7.0 by default ...
    (
        'phpversion="${phpversion:-7.3}"',
        'phpversion="${phpversion:-7.4}"',
    ),  # Many helpers like the composer ones use 7.0 by default ...
    (
        '"$phpversion" == "7.0"',
        '$(bc <<< "$phpversion >= 7.4") -eq 1',
    ),  # patch ynh_install_php to refuse installing/removing php <= 7.3
    (
        '"$phpversion" == "7.3"',
        '$(bc <<< "$phpversion >= 7.4") -eq 1',
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
            + "".join(f"-e 's@{p}@{r}@g' " for p, r in LEGACY_PHP_VERSION_REPLACEMENTS)
            + "%s" % filename
        )
        os.system(c)


def _patch_legacy_php_versions_in_settings(app_folder):
    settings = read_yaml(os.path.join(app_folder, "settings.yml"))

    if settings.get("fpm_config_dir") in ["/etc/php/7.0/fpm", "/etc/php/7.3/fpm"]:
        settings["fpm_config_dir"] = "/etc/php/7.4/fpm"
    if settings.get("fpm_service") in ["php7.0-fpm", "php7.3-fpm"]:
        settings["fpm_service"] = "php7.4-fpm"
    if settings.get("phpversion") in ["7.0", "7.3"]:
        settings["phpversion"] = "7.4"

    # We delete these checksums otherwise the file will appear as manually modified
    list_to_remove = [
        "checksum__etc_php_7.3_fpm_pool",
        "checksum__etc_php_7.0_fpm_pool",
        "checksum__etc_nginx_conf.d",
    ]
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
        "yunohost app initdb": {"important": True},
        "yunohost app checkport": {"important": True},
        "yunohost tools port-available": {"important": True},
        "yunohost app checkurl": {"important": True},
        "yunohost user create": {
            "pattern": r"yunohost user create (\S+) (-f|--firstname) (\S+) (-l|--lastname) \S+ (.*)",
            "replace": r"yunohost user create \1 --fullname \3 \5",
            "important": False,
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
            "important": True,
        },
        # Old $1, $2 in backup/restore scripts...
        "backup_dir=$1": {
            "only_for": ["scripts/backup", "scripts/restore"],
            "important": True,
        },
        # Old $1, $2 in backup/restore scripts...
        "restore_dir=$1": {"only_for": ["scripts/restore"], "important": True},
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
                r"/!\ Packagers! This app uses very old deprecated helpers... YunoHost automatically patched the helpers to use the new recommended practice, but please do consider fixing the upstream code right now..."
            )
