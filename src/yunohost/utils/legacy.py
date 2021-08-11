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
