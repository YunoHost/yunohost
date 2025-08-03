#!/usr/bin/env python3
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

import glob
import os
import shutil

import pytest
import requests
import requests_mock
from moulinette import m18n

from yunohost.app_catalog import (
    APPS_CATALOG_API_VERSION,
    APPS_CATALOG_CACHE,
    APPS_CATALOG_CONF,
    APPS_CATALOG_DEFAULT_URL,
    _actual_apps_catalog_api_url,
    _load_apps_catalog,
    _read_apps_catalog_list,
    _update_apps_catalog,
    app_catalog,
    logger,
)
from yunohost.utils.error import YunohostError
from yunohost.utils.file_utils import read_json, write_to_json, write_to_yaml

from .conftest import message

APPS_CATALOG_DEFAULT_URL_FULL = _actual_apps_catalog_api_url(APPS_CATALOG_DEFAULT_URL)

DUMMY_APP_CATALOG = """{
   "apps": {
       "foo": {"id": "foo", "level": 4, "category": "yolo", "manifest":{"description": "Foo"}},
       "bar": {"id": "bar", "level": 7, "category": "swag", "manifest":{"description": "Bar"}}
   },
   "categories": [
       {"id": "yolo", "description": "YoLo", "title": {"en": "Yolo"}},
       {"id": "swag", "description": "sWaG", "title": {"en": "Swag"}}
   ]
}
"""


class AnyStringWith(str):
    def __eq__(self, other):
        return self in other


def setup_function(function):
    # Clear apps catalog cache
    shutil.rmtree(APPS_CATALOG_CACHE, ignore_errors=True)

    # Clear apps_catalog conf
    if os.path.exists(APPS_CATALOG_CONF):
        os.remove(APPS_CATALOG_CONF)


def teardown_function(function):
    # Clear apps catalog cache
    # Otherwise when using apps stuff after running the test,
    # we'll still have the dummy unusable list
    shutil.rmtree(APPS_CATALOG_CACHE, ignore_errors=True)


#
# ################################################
#


def test_apps_catalog_emptylist():
    # Let's imagine somebody removed the default apps catalog because uh idk they dont want to use our default apps catalog
    os.system("rm %s" % APPS_CATALOG_CONF)
    os.system("touch %s" % APPS_CATALOG_CONF)

    apps_catalog_list = _read_apps_catalog_list()
    assert len(apps_catalog_list) == 0


def test_apps_catalog_update_nominal(mocker):
    # Cache is empty
    assert not glob.glob(APPS_CATALOG_CACHE + "/*")

    # Update
    with requests_mock.Mocker() as m:
        (_actual_apps_catalog_api_url,)
        # Mock the server response with a dummy apps catalog
        m.register_uri("GET", APPS_CATALOG_DEFAULT_URL_FULL, text=DUMMY_APP_CATALOG)

        mocker.spy(m18n, "n")
        _update_apps_catalog()
        m18n.n.assert_any_call("apps_catalog_updating")
        m18n.n.assert_any_call("apps_catalog_update_success")

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPS_CATALOG_CACHE + "/*")

    # And if we load the catalog, we sould find
    # - foo and bar as apps (unordered),
    # - yolo and swag as categories (ordered)
    catalog = app_catalog(with_categories=True)

    assert "apps" in catalog
    assert set(catalog["apps"].keys()) == {"foo", "bar"}

    assert "categories" in catalog
    assert [c["id"] for c in catalog["categories"]] == ["yolo", "swag"]


def test_apps_catalog_update_404(mocker):
    with requests_mock.Mocker() as m:
        # 404 error
        m.register_uri("GET", APPS_CATALOG_DEFAULT_URL_FULL, status_code=404)

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_apps_catalog()
            m18n.n.assert_any_call("apps_catalog_failed_to_download")


def test_apps_catalog_update_timeout(mocker):
    with requests_mock.Mocker() as m:
        # Timeout
        m.register_uri(
            "GET", APPS_CATALOG_DEFAULT_URL_FULL, exc=requests.exceptions.ConnectTimeout
        )

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_apps_catalog()
            m18n.n.assert_any_call("apps_catalog_failed_to_download")


def test_apps_catalog_update_sslerror(mocker):
    with requests_mock.Mocker() as m:
        # SSL error
        m.register_uri(
            "GET", APPS_CATALOG_DEFAULT_URL_FULL, exc=requests.exceptions.SSLError
        )

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_apps_catalog()
            m18n.n.assert_any_call("apps_catalog_failed_to_download")


def test_apps_catalog_update_corrupted(mocker):
    with requests_mock.Mocker() as m:
        # Corrupted json
        m.register_uri(
            "GET", APPS_CATALOG_DEFAULT_URL_FULL, text=DUMMY_APP_CATALOG[:-2]
        )

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_apps_catalog()
            m18n.n.assert_any_call("apps_catalog_failed_to_download")


def test_apps_catalog_load_with_empty_cache(mocker):
    # Cache is empty
    assert not glob.glob(APPS_CATALOG_CACHE + "/*")

    # Update
    with requests_mock.Mocker() as m:
        # Mock the server response with a dummy apps catalog
        m.register_uri("GET", APPS_CATALOG_DEFAULT_URL_FULL, text=DUMMY_APP_CATALOG)

        # Try to load the apps catalog
        # This should implicitly trigger an update in the background
        mocker.spy(m18n, "n")
        app_dict = _load_apps_catalog()["apps"]
        m18n.n.assert_any_call("apps_catalog_obsolete_cache")
        m18n.n.assert_any_call("apps_catalog_update_success")

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPS_CATALOG_CACHE + "/*")

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()


def test_apps_catalog_load_with_conflicts_between_lists(mocker):
    conf = [
        {"id": "default", "url": APPS_CATALOG_DEFAULT_URL},
        {
            "id": "default2",
            "url": APPS_CATALOG_DEFAULT_URL.replace("yunohost.org", "yolohost.org"),
        },
    ]

    write_to_yaml(APPS_CATALOG_CONF, conf)

    # Update
    with requests_mock.Mocker() as m:
        # Mock the server response with a dummy apps catalog
        # + the same apps catalog for the second list
        m.register_uri("GET", APPS_CATALOG_DEFAULT_URL_FULL, text=DUMMY_APP_CATALOG)
        m.register_uri(
            "GET",
            APPS_CATALOG_DEFAULT_URL_FULL.replace("yunohost.org", "yolohost.org"),
            text=DUMMY_APP_CATALOG,
        )

        # Try to load the apps catalog
        # This should implicitly trigger an update in the background
        mocker.spy(logger, "warning")
        app_dict = _load_apps_catalog()["apps"]
        logger.warning.assert_any_call(AnyStringWith("Duplicate"))

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPS_CATALOG_CACHE + "/*")

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()


def test_apps_catalog_load_with_outdated_api_version():
    # Update
    with requests_mock.Mocker() as m:
        m.register_uri("GET", APPS_CATALOG_DEFAULT_URL_FULL, text=DUMMY_APP_CATALOG)
        _update_apps_catalog()

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPS_CATALOG_CACHE + "/*")

    # Tweak the cache to replace the from_api_version with a different one
    for cache_file in glob.glob(APPS_CATALOG_CACHE + "/*"):
        cache_json = read_json(cache_file)
        assert cache_json["from_api_version"] == APPS_CATALOG_API_VERSION
        cache_json["from_api_version"] = 0
        write_to_json(cache_file, cache_json)

    # Update
    with requests_mock.Mocker() as m:
        # Mock the server response with a dummy apps catalog
        m.register_uri("GET", APPS_CATALOG_DEFAULT_URL_FULL, text=DUMMY_APP_CATALOG)
        with message("apps_catalog_update_success"):
            app_dict = _load_apps_catalog()["apps"]

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()

    # Check that we indeed have the new api number in cache
    for cache_file in glob.glob(APPS_CATALOG_CACHE + "/*"):
        cache_json = read_json(cache_file)
        assert cache_json["from_api_version"] == APPS_CATALOG_API_VERSION
