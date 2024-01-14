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
import hashlib
from logging import getLogger

from moulinette import m18n
from moulinette.utils.network import download_json
from moulinette.utils.filesystem import (
    read_json,
    read_yaml,
    write_to_json,
    write_to_yaml,
    mkdir,
)

from yunohost.utils.i18n import _value_for_locale
from yunohost.utils.error import YunohostError

logger = getLogger("yunohost.app_catalog")

APPS_CATALOG_CACHE = "/var/cache/yunohost/repo"
APPS_CATALOG_LOGOS = "/usr/share/yunohost/applogos"
APPS_CATALOG_CONF = "/etc/yunohost/apps_catalog.yml"
APPS_CATALOG_API_VERSION = 3
APPS_CATALOG_DEFAULT_URL = "https://app.yunohost.org/default"


def app_catalog(full=False, with_categories=False, with_antifeatures=False):
    """
    Return a dict of apps available to installation from Yunohost's app catalog
    """

    from yunohost.app import _installed_apps

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

    _catalog = {"apps": catalog["apps"]}

    if with_categories:
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

        _catalog["categories"] = catalog["categories"]

    if with_antifeatures:
        for antifeature in catalog["antifeatures"]:
            antifeature["title"] = _value_for_locale(antifeature["title"])
            antifeature["description"] = _value_for_locale(antifeature["description"])

        if not full:
            catalog["antifeatures"] = [
                {"id": a["id"], "description": a["description"]}
                for a in catalog["antifeatures"]
            ]

        _catalog["antifeatures"] = catalog["antifeatures"]

    return _catalog


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
            f"Could not initialize the apps catalog system... : {e}", raw_msg=True
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
        raise YunohostError(
            f"Could not read the apps_catalog list ... : {e}", raw_msg=True
        )


def _actual_apps_catalog_api_url(base_url):
    return f"{base_url}/v{APPS_CATALOG_API_VERSION}/apps.json"


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

    if not os.path.exists(APPS_CATALOG_LOGOS):
        mkdir(APPS_CATALOG_LOGOS, mode=0o755, parents=True, uid="root")

    for apps_catalog in apps_catalog_list:
        if apps_catalog["url"] is None:
            continue

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
        cache_file = f"{APPS_CATALOG_CACHE}/{apps_catalog_id}.json"
        try:
            write_to_json(cache_file, apps_catalog_content)
        except Exception as e:
            raise YunohostError(
                f"Unable to write cache data for {apps_catalog_id} apps_catalog : {e}",
                raw_msg=True,
            )

        # Download missing app logos
        logos_to_download = []
        for app, infos in apps_catalog_content["apps"].items():
            logo_hash = infos.get("logo_hash")
            if not logo_hash or os.path.exists(f"{APPS_CATALOG_LOGOS}/{logo_hash}.png"):
                continue
            logos_to_download.append(logo_hash)

        if len(logos_to_download) > 20:
            logger.info(
                f"(Will fetch {len(logos_to_download)} logos, this may take a couple minutes)"
            )

        import requests
        from multiprocessing.pool import ThreadPool

        def fetch_logo(logo_hash):
            try:
                r = requests.get(
                    f"{apps_catalog['url']}/v{APPS_CATALOG_API_VERSION}/logos/{logo_hash}.png",
                    timeout=10,
                )
                assert (
                    r.status_code == 200
                ), f"Got status code {r.status_code}, expected 200"
                if hashlib.sha256(r.content).hexdigest() != logo_hash:
                    raise Exception(
                        f"Found inconsistent hash while downloading logo {logo_hash}"
                    )
                open(f"{APPS_CATALOG_LOGOS}/{logo_hash}.png", "wb").write(r.content)
                return True
            except Exception as e:
                logger.debug(f"Failed to download logo {logo_hash} : {e}")
                return False

        results = ThreadPool(8).imap_unordered(fetch_logo, logos_to_download)
        for result in results:
            # Is this even needed to iterate on the results ?
            pass

    logger.success(m18n.n("apps_catalog_update_success"))


def _load_apps_catalog():
    """
    Read all the apps catalog cache files and build a single dict (merged_catalog)
    corresponding to all known apps and categories
    """

    merged_catalog = {"apps": {}, "categories": [], "antifeatures": []}

    for apps_catalog_id in [L["id"] for L in _read_apps_catalog_list()]:
        # Let's load the json from cache for this catalog
        cache_file = f"{APPS_CATALOG_CACHE}/{apps_catalog_id}.json"

        try:
            apps_catalog_content = (
                read_json(cache_file) if os.path.exists(cache_file) else None
            )
        except Exception as e:
            raise YunohostError(
                f"Unable to read cache for apps_catalog {cache_file} : {e}",
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
                other_catalog = merged_catalog["apps"][app]["repository"]
                logger.warning(
                    f"Duplicate app {app} found between apps catalog {apps_catalog_id} and {other_catalog}"
                )
                continue

            if info.get("level") == "?":
                info["level"] = -1

            # FIXME: we may want to autoconvert all v0/v1 manifest to v2 here
            # so that everything is consistent in terms of APIs, datastructure format etc
            info["repository"] = apps_catalog_id
            merged_catalog["apps"][app] = info

        # Annnnd categories + antifeatures
        # (we use .get here, only because the dev catalog doesnt include the categories/antifeatures keys)
        merged_catalog["categories"] += apps_catalog_content.get("categories", [])
        merged_catalog["antifeatures"] += apps_catalog_content.get("antifeatures", [])

    return merged_catalog
