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

import pytest

from yunohost.app import (
    _is_app_repo_url,
    _parse_app_instance_name,
    app_install,
    app_remove,
)
from yunohost.domain import _get_maindomain, domain_url_available
from yunohost.permission import _validate_and_sanitize_permission_url
from yunohost.utils.error import YunohostError

from .conftest import get_test_apps_dir

# Get main domain
maindomain = _get_maindomain()


def setup_function(function):
    try:
        app_remove("register_url_app")
    except Exception:
        pass


def teardown_function(function):
    try:
        app_remove("register_url_app")
    except Exception:
        pass


def test_parse_app_instance_name():
    assert _parse_app_instance_name("yolo") == ("yolo", 1)
    assert _parse_app_instance_name("yolo1") == ("yolo1", 1)
    assert _parse_app_instance_name("yolo__0") == ("yolo__0", 1)
    assert _parse_app_instance_name("yolo__1") == ("yolo", 1)
    assert _parse_app_instance_name("yolo__23") == ("yolo", 23)
    assert _parse_app_instance_name("yolo__42__72") == ("yolo__42", 72)
    assert _parse_app_instance_name("yolo__23qdqsd") == ("yolo__23qdqsd", 1)
    assert _parse_app_instance_name("yolo__23qdqsd56") == ("yolo__23qdqsd56", 1)


def test_repo_url_definition():
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/foobar123_ynh")
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/foobar123_ynh/")
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/foobar123_ynh.git")
    assert _is_app_repo_url(
        "https://github.com/YunoHost-Apps/foobar123_ynh/tree/testing"
    )
    assert _is_app_repo_url(
        "https://github.com/YunoHost-Apps/foobar123_ynh/tree/testing/"
    )
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/foo-bar-123_ynh")
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/foo_bar_123_ynh")
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/FooBar123_ynh")
    assert _is_app_repo_url("https://github.com/labriqueinternet/vpnclient_ynh")
    assert _is_app_repo_url("https://framagit.org/YunoHost/apps/nodebb_ynh")
    assert _is_app_repo_url(
        "https://framagit.org/YunoHost/apps/nodebb_ynh/-/tree/testing"
    )
    assert _is_app_repo_url("https://gitlab.com/yunohost-apps/foobar_ynh")
    assert _is_app_repo_url("https://code.antopie.org/miraty/qr_ynh")
    assert _is_app_repo_url(
        "https://gitlab.domainepublic.net/Neutrinet/neutrinet_ynh/-/tree/unstable"
    )
    assert _is_app_repo_url("https://github.com/YunoHost-Apps/foobar_ynh/tree/1.23.4")
    assert _is_app_repo_url("git@github.com:YunoHost-Apps/foobar_ynh.git")
    assert _is_app_repo_url("https://git.super.host/~max/foobar_ynh")

    ### Gitea
    assert _is_app_repo_url("https://gitea.instance.tld/user/repo_ynh")
    assert _is_app_repo_url(
        "https://gitea.instance.tld/user/repo_ynh/src/branch/branch_name"
    )
    assert _is_app_repo_url("https://gitea.instance.tld/user/repo_ynh/src/tag/tag_name")
    assert _is_app_repo_url(
        "https://gitea.instance.tld/user/repo_ynh/src/commit/abcd1234"
    )

    ### Invalid patterns

    # no schema
    assert not _is_app_repo_url("github.com/YunoHost-Apps/foobar_ynh")
    # http
    assert not _is_app_repo_url("http://github.com/YunoHost-Apps/foobar_ynh")
    # does not end in `_ynh`
    assert not _is_app_repo_url("https://github.com/YunoHost-Apps/foobar_wat")
    assert not _is_app_repo_url("https://github.com/YunoHost-Apps/foobar_ynh_wat")
    assert not _is_app_repo_url("https://github.com/YunoHost-Apps/foobar/tree/testing")
    assert not _is_app_repo_url(
        "https://github.com/YunoHost-Apps/foobar_ynh_wat/tree/testing"
    )
    assert not _is_app_repo_url("https://framagit.org/YunoHost/apps/")
    assert not _is_app_repo_url("https://framagit.org/YunoHost/apps/pwet")
    assert not _is_app_repo_url("https://framagit.org/YunoHost/apps/pwet_foo")


def test_urlavailable():
    # Except the maindomain/macnuggets to be available
    assert domain_url_available(maindomain, "/macnuggets")

    # We don't know the domain yolo.swag
    with pytest.raises(YunohostError):
        assert domain_url_available("yolo.swag", "/macnuggets")


def test_registerurl():
    app_install(
        os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
        args="domain={}&path={}".format(maindomain, "/urlregisterapp"),
        force=True,
    )

    assert not domain_url_available(maindomain, "/urlregisterapp")

    # Try installing at same location
    with pytest.raises(YunohostError):
        app_install(
            os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
            args="domain={}&path={}".format(maindomain, "/urlregisterapp"),
            force=True,
        )


def test_registerurl_baddomain():
    with pytest.raises(YunohostError):
        app_install(
            os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
            args="domain={}&path={}".format("yolo.swag", "/urlregisterapp"),
            force=True,
        )


def test_normalize_permission_path():
    # Relative path
    assert (
        _validate_and_sanitize_permission_url(
            "/wiki/", maindomain + "/path", "test_permission"
        )
        == "/wiki"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "/", maindomain + "/path", "test_permission"
        )
        == "/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "//salut/", maindomain + "/path", "test_permission"
        )
        == "/salut"
    )

    # Full path
    assert (
        _validate_and_sanitize_permission_url(
            maindomain + "/hey/", maindomain + "/path", "test_permission"
        )
        == maindomain + "/hey"
    )
    assert (
        _validate_and_sanitize_permission_url(
            maindomain + "//", maindomain + "/path", "test_permission"
        )
        == maindomain + "/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            maindomain + "/", maindomain + "/path", "test_permission"
        )
        == maindomain + "/"
    )

    # Relative Regex
    assert (
        _validate_and_sanitize_permission_url(
            "re:/yolo.*/", maindomain + "/path", "test_permission"
        )
        == "re:/yolo.*/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "re:/y.*o(o+)[a-z]*/bo\1y", maindomain + "/path", "test_permission"
        )
        == "re:/y.*o(o+)[a-z]*/bo\1y"
    )

    # Full Regex
    assert (
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/yolo.*/", maindomain + "/path", "test_permission"
        )
        == "re:" + maindomain + "/yolo.*/"
    )
    assert (
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/y.*o(o+)[a-z]*/bo\1y",
            maindomain + "/path",
            "test_permission",
        )
        == "re:" + maindomain + "/y.*o(o+)[a-z]*/bo\1y"
    )


def test_normalize_permission_path_with_bad_regex():
    # Relative Regex
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:/yolo.*[1-7]^?/", maindomain + "/path", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:/yolo.*[1-7](]/", maindomain + "/path", "test_permission"
        )

    # Full Regex
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:" + maindomain + "/yolo[1-9]**/",
            maindomain + "/path",
            "test_permission",
        )


def test_normalize_permission_path_with_unknown_domain():
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "shouldntexist.tld/hey", maindomain + "/path", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "re:shouldntexist.tld/hey.*", maindomain + "/path", "test_permission"
        )


def test_normalize_permission_path_conflicting_path():
    app_install(
        os.path.join(get_test_apps_dir(), "register_url_app_ynh"),
        args="domain={}&path={}".format(maindomain, "/url/registerapp"),
        force=True,
    )

    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            "/registerapp", maindomain + "/url", "test_permission"
        )
    with pytest.raises(YunohostError):
        _validate_and_sanitize_permission_url(
            maindomain + "/url/registerapp", maindomain + "/path", "test_permission"
        )
