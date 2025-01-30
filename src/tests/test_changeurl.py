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

import os
import time

import pytest
import requests

from yunohost.app import app_change_url, app_install, app_map, app_remove
from yunohost.domain import _get_maindomain
from yunohost.utils.error import YunohostError

from .conftest import get_test_apps_dir

# Get main domain
maindomain = ""


def setup_function(function):
    global maindomain
    maindomain = _get_maindomain()


def teardown_function(function):
    app_remove("change_url_app")


def install_changeurl_app(path):
    app_install(
        os.path.join(get_test_apps_dir(), "change_url_app_ynh"),
        args="domain={}&path={}".format(maindomain, path),
        force=True,
    )


def check_changeurl_app(path):
    appmap = app_map(raw=True)

    assert path in appmap[maindomain].keys()

    assert appmap[maindomain][path]["id"] == "change_url_app"

    r = requests.get(
        "https://127.0.0.1%s/" % path, headers={"Host": maindomain}, verify=False
    )
    assert r.status_code == 200


def test_appchangeurl():
    install_changeurl_app("/changeurl")
    check_changeurl_app("/changeurl")

    app_change_url("change_url_app", maindomain, "/newchangeurl")

    # For some reason the nginx reload can take some time to propagate ...?
    time.sleep(2)

    check_changeurl_app("/newchangeurl")


def test_appchangeurl_sameurl():
    install_changeurl_app("/changeurl")
    check_changeurl_app("/changeurl")

    with pytest.raises(YunohostError):
        app_change_url("change_url_app", maindomain, "changeurl")
