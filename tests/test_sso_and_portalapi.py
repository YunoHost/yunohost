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

import base64
import os
import time
from pathlib import Path

import requests

from yunohost.app import (
    app_change_url,
    app_install,
    app_remove,
    app_setting,
    app_ssowatconf,
)
from yunohost.authenticators.ldap_ynhuser import (
    SESSION_FOLDER,
    Authenticator,
    short_hash,
)
from yunohost.domain import _get_maindomain, domain_add, domain_list, domain_remove
from yunohost.permission import user_permission_list, user_permission_update
from yunohost.user import user_create, user_delete, user_list, user_update

from .conftest import get_test_apps_dir, message, raiseYunohostError

# Get main domain
maindomain = open("/etc/yunohost/current_host").read().strip()
subdomain = f"sub.{maindomain}"
secondarydomain = "secondary.test"
dummy_password = "test123Ynh"


def setup_function(function):
    Authenticator.invalidate_all_sessions_for_user("alice")
    assert number_of_active_session_for_user("alice") == 0
    Authenticator.invalidate_all_sessions_for_user("bob")
    assert number_of_active_session_for_user("bob") == 0

    user_permission_update(
        "hellopy.main", add=["visitors", "all_users"], remove=["alice", "bob"]
    )

    app_setting("hellopy", "auth_header", delete=True)
    app_setting("hellopy", "protect_against_basic_auth_spoofing", delete=True)
    app_ssowatconf()


def teardown_function(function):
    pass


def setup_module(module):
    assert os.system("systemctl is-active yunohost-portal-api >/dev/null") == 0

    if "alice" not in user_list()["users"]:
        user_create(
            "alice", maindomain, dummy_password, fullname="Alice White", admin=True
        )
    if "bob" not in user_list()["users"]:
        user_create("bob", maindomain, dummy_password, fullname="Bob Marley")

    app_install(
        os.path.join(get_test_apps_dir(), "hellopy_ynh"),
        args=f"domain={maindomain}&init_main_permission=visitors",
        force=True,
    )


def teardown_module(module):
    if "alice" in user_list()["users"]:
        user_delete("alice", force=True)
    if "bob" in user_list()["users"]:
        user_delete("bob", force=True)

    app_remove("hellopy")

    if subdomain in domain_list()["domains"]:
        domain_remove(subdomain)
    if secondarydomain in domain_list()["domains"]:
        domain_remove(secondarydomain)


def login(session, logged_as, logged_on=None):
    if not logged_on:
        logged_on = maindomain

    login_endpoint = f"https://{logged_on}/yunohost/portalapi/login"
    r = session.post(
        login_endpoint,
        data={"credentials": f"{logged_as}:{dummy_password}"},
        headers={
            "X-Requested-With": "",
        },
        verify=False,
    )

    return r


def logout(session):
    logout_endpoint = f"https://{maindomain}/yunohost/portalapi/logout"
    r = session.get(
        logout_endpoint,
        headers={
            "X-Requested-With": "",
        },
        verify=False,
    )
    return r


def number_of_active_session_for_user(user):
    return len(list(Path(SESSION_FOLDER).glob(f"{short_hash(user)}*")))


def request(webpath, logged_as=None, session=None, inject_auth=None, logged_on=None):
    webpath = webpath.rstrip("/")

    headers = {}
    if inject_auth:
        b64loginpassword = base64.b64encode(
            (inject_auth[0] + ":" + inject_auth[1]).encode()
        ).decode()
        headers["Authorization"] = f"Basic {b64loginpassword}"

    # Anonymous access
    if session:
        r = session.get(webpath, verify=False, allow_redirects=False, headers=headers)
    elif not logged_as:
        r = requests.get(webpath, verify=False, allow_redirects=False, headers=headers)
    # Login as a user using dummy password
    else:
        with requests.Session() as session:
            r = login(session, logged_as, logged_on)
            # We should have some cookies related to authentication now
            assert session.cookies
            r = session.get(
                webpath, verify=False, allow_redirects=False, headers=headers
            )

    return r


def test_api_public_as_anonymous():
    # FIXME : should list apps only if the domain option is enabled

    r = request(f"https://{maindomain}/yunohost/portalapi/public")
    assert r.status_code == 200 and "apps" in r.json()


def test_api_me_as_anonymous():
    r = request(f"https://{maindomain}/yunohost/portalapi/me")
    assert r.status_code == 401


def test_api_login_and_logout():
    with requests.Session() as session:
        r = login(session, "alice")

        assert "yunohost.portal" in session.cookies
        assert r.status_code == 200

        assert number_of_active_session_for_user("alice") == 1

        r = logout(session)

        assert number_of_active_session_for_user("alice") == 0


def test_api_login_nonexistinguser():
    with requests.Session() as session:
        r = login(session, "nonexistent")

        assert r.status_code == 401


def test_api_public_and_me_logged_in():
    r = request(f"https://{maindomain}/yunohost/portalapi/public", logged_as="alice")
    assert r.status_code == 200 and "apps" in r.json()
    r = request(f"https://{maindomain}/yunohost/portalapi/me", logged_as="alice")
    assert r.status_code == 200 and r.json()["username"] == "alice"

    assert number_of_active_session_for_user("alice") == 2


def test_api_session_expired():
    with requests.Session() as session:
        r = login(session, "alice")

        assert "yunohost.portal" in session.cookies
        assert r.status_code == 200

        r = request(f"https://{maindomain}/yunohost/portalapi/me", session=session)
        assert r.status_code == 200 and r.json()["username"] == "alice"

        for file in Path(SESSION_FOLDER).glob(f"{short_hash('alice')}*"):
            os.utime(str(file), (0, 0))

        r = request(f"https://{maindomain}/yunohost/portalapi/me", session=session)
        assert number_of_active_session_for_user("alice") == 0
        assert r.status_code == 401


def test_public_routes_not_blocked_by_ssowat():
    r = request(f"https://{maindomain}/yunohost/api/whatever")
    # Getting code 405, Method not allowed, which means the API does answer,
    # meaning it's not blocked by ssowat
    # Or : on the CI, the yunohost-api is likely to be down (to save resources)
    assert r.status_code in [405, 502]

    os.system("mkdir -p /var/www/.well-known/acme-challenge-public")
    Path("/var/www/.well-known/acme-challenge-public/toto").touch()
    r = request(f"http://{maindomain}/.well-known/acme-challenge/toto")
    assert r.status_code == 200

    r = request(f"http://{maindomain}/.well-known/acme-challenge/nonexistent")
    assert r.status_code == 404


def test_permission_propagation_on_ssowat():
    res = user_permission_list(full=True)["permissions"]
    assert "visitors" in res["hellopy.main"]["allowed"]
    assert "all_users" in res["hellopy.main"]["allowed"]

    r = request(f"https://{maindomain}/")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{maindomain}/", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{maindomain}/", logged_as="bob")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    user_permission_update(
        "hellopy.main", remove=["visitors", "all_users"], add="alice"
    )

    # Visitors now get redirected to portal
    r = request(f"https://{maindomain}/")
    assert r.status_code == 302
    assert r.headers["Location"].startswith(f"https://{maindomain}/yunohost/sso?r=")

    # Alice can still access the app fine
    r = request(f"https://{maindomain}/", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"


def test_login_right_depending_on_app_access_and_mail():
    r = request(f"https://{maindomain}/", logged_as="bob")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    user_permission_update(
        "hellopy.main", remove=["visitors", "all_users"], add="alice"
    )

    # Bob can still login even though he has no access to any apps, because its mail address is on the maindomain
    with requests.Session() as session:
        r = login(session, "bob")
        assert session.cookies

    if secondarydomain not in domain_list()["domains"]:
        domain_add(secondarydomain)

    user_update("bob", mail=f"bob@{secondarydomain}")

    # Now bob shouldn't be able to login anymore (on the main domain)
    with requests.Session() as session:
        r = login(session, "bob")
        assert not session.cookies

    user_permission_update("hellopy.main", add="bob")

    # Bob should be allowed to login again (even though its mail is on secondarydomain)
    r = request(f"https://{maindomain}/", logged_as="bob")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"


def test_sso_basic_auth_header():
    r = request(f"https://{maindomain}/show-auth")
    assert (
        r.status_code == 200 and r.content.decode().strip() == "User: None\nPwd: None"
    )

    r = request(f"https://{maindomain}/show-auth", logged_as="alice")
    assert (
        r.status_code == 200
        and r.content.decode().strip() == f"User: alice\nPwd: {dummy_password}"
    )

    app_setting("hellopy", "auth_header", value="basic-without-password")
    app_ssowatconf()

    r = request(f"https://{maindomain}/show-auth", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == f"User: alice\nPwd: -"


def test_sso_basic_auth_header_spoofing():
    r = request(f"https://{maindomain}/show-auth")
    assert (
        r.status_code == 200 and r.content.decode().strip() == "User: None\nPwd: None"
    )

    r = request(f"https://{maindomain}/show-auth", inject_auth=("foo", "bar"))
    assert (
        r.status_code == 200 and r.content.decode().strip() == "User: None\nPwd: None"
    )

    app_setting("hellopy", "protect_against_basic_auth_spoofing", value="false")
    app_ssowatconf()

    r = request(f"https://{maindomain}/show-auth", inject_auth=("foo", "bar"))
    assert r.status_code == 200 and r.content.decode().strip() == "User: foo\nPwd: bar"


def test_sso_on_subdomain():
    if subdomain not in domain_list()["domains"]:
        domain_add(subdomain)

    app_change_url("hellopy", domain=subdomain, path="/")

    r = request(f"https://{subdomain}/")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{subdomain}/", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{subdomain}/show-auth", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip().startswith("User: alice")


def test_sso_on_secondary_domain():
    if secondarydomain not in domain_list()["domains"]:
        domain_add(secondarydomain)

    app_change_url("hellopy", domain=secondarydomain, path="/")

    r = request(f"https://{secondarydomain}/")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{secondarydomain}/", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{secondarydomain}/show-auth", logged_as="alice")
    # Getting 'User: None despite being logged on the main domain
    assert r.status_code == 200 and r.content.decode().strip().startswith("User: None")

    r = request(
        f"https://{secondarydomain}/show-auth",
        logged_as="alice",
        logged_on=secondarydomain,
    )
    assert r.status_code == 200 and r.content.decode().strip().startswith("User: alice")


# accès à l'api portal
# -> test des routes
#    apps publique (seulement si activé ?)
#    /me
#    /update


# accès aux trucs précédent meme avec une app installée sur la racine ?
# ou une app par défaut ?

# accès à un deuxième "domain principal"

# accès à un app sur un sous-domaine
# pas loggué -> redirect vers sso sur domaine principal
# se logger sur API sur domain principal, puis utilisation du cookie sur le sous-domaine
