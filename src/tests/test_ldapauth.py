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
from moulinette import m18n
from moulinette.core import MoulinetteError

from yunohost.authenticators.ldap_admin import Authenticator as LDAPAuth
from yunohost.domain import _get_maindomain
from yunohost.user import user_create, user_delete, user_list, user_update


def setup_function(function):
    for u in user_list()["users"]:
        user_delete(u, purge=True, force=True)

    maindomain = _get_maindomain()

    if os.system("systemctl is-active slapd >/dev/null") != 0:
        os.system("systemctl start slapd && sleep 3")

    user_create("alice", maindomain, "Yunohost", admin=True, fullname="Alice White")
    user_create("bob", maindomain, "test123Ynh", fullname="Bob Snow")


def teardown_function():
    os.system("systemctl is-active slapd >/dev/null || systemctl start slapd; sleep 5")

    for u in user_list()["users"]:
        user_delete(u, purge=True, force=True)


def test_authenticate():
    LDAPAuth().authenticate_credentials(credentials="alice:Yunohost")


def test_authenticate_with_no_user():
    with pytest.raises(MoulinetteError):
        LDAPAuth().authenticate_credentials(credentials="Yunohost")

    with pytest.raises(MoulinetteError):
        LDAPAuth().authenticate_credentials(credentials=":Yunohost")


def test_authenticate_with_user_who_is_not_admin():
    with pytest.raises(MoulinetteError) as exception:
        LDAPAuth().authenticate_credentials(credentials="bob:test123Ynh")

    translation = m18n.n("invalid_credentials")
    expected_msg = translation.format()
    assert expected_msg in str(exception)


def test_authenticate_with_wrong_password():
    with pytest.raises(MoulinetteError) as exception:
        LDAPAuth().authenticate_credentials(credentials="alice:bad_password_lul")

    translation = m18n.n("invalid_credentials")
    expected_msg = translation.format()
    assert expected_msg in str(exception)


def test_authenticate_server_down():
    os.system("systemctl stop slapd && sleep 5")

    LDAPAuth().authenticate_credentials(credentials="alice:Yunohost")


def test_authenticate_change_password():
    LDAPAuth().authenticate_credentials(credentials="alice:Yunohost")

    user_update("alice", change_password="plopette")

    with pytest.raises(MoulinetteError) as exception:
        LDAPAuth().authenticate_credentials(credentials="alice:Yunohost")

    translation = m18n.n("invalid_credentials")
    expected_msg = translation.format()
    assert expected_msg in str(exception)

    LDAPAuth().authenticate_credentials(credentials="alice:plopette")
