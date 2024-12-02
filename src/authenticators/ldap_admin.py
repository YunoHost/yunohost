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

import jwt
import os
import logging
import ldap
import ldap.sasl
import time
import hashlib
from pathlib import Path

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.text import random_ascii

from yunohost.utils.error import YunohostError, YunohostAuthenticationError
from yunohost.utils.ldap import _get_ldap_interface

logger = logging.getLogger("yunohost.authenticators.ldap_admin")


def SESSION_SECRET():
    # Only load this once actually requested to avoid boring issues like
    # "secret doesnt exists yet" (before postinstall) and therefore service
    # miserably fail to start
    if not SESSION_SECRET.value:
        SESSION_SECRET.value = open("/etc/yunohost/.admin_cookie_secret").read().strip()
    assert SESSION_SECRET.value
    return SESSION_SECRET.value


SESSION_SECRET.value = None  # type: ignore
SESSION_FOLDER = "/var/cache/yunohost/sessions"
SESSION_VALIDITY = 3 * 24 * 3600  # 3 days

LDAP_URI = "ldap://localhost:389"
ADMIN_GROUP = "cn=admins,ou=groups"
AUTH_DN = "uid={uid},ou=users,dc=yunohost,dc=org"


def short_hash(data):
    return hashlib.shake_256(data.encode()).hexdigest(20)


class Authenticator(BaseAuthenticator):
    name = "ldap_admin"

    def __init__(self, *args, **kwargs):
        pass

    def _authenticate_credentials(self, credentials=None):
        try:
            admins = (
                _get_ldap_interface()
                .search(ADMIN_GROUP, attrs=["memberUid"])[0]
                .get("memberUid", [])
            )
        except ldap.SERVER_DOWN:
            # ldap is down, attempt to restart it before really failing
            logger.warning(m18n.n("ldap_server_is_down_restart_it"))
            os.system("systemctl restart slapd")
            time.sleep(10)  # waits 10 secondes so we are sure that slapd has restarted

            # Force-reset existing LDAP interface
            from yunohost.utils import ldap as ldaputils

            ldaputils._ldap_interface = None

            try:
                admins = (
                    _get_ldap_interface()
                    .search(ADMIN_GROUP, attrs=["memberUid"])[0]
                    .get("memberUid", [])
                )
            except ldap.SERVER_DOWN:
                raise YunohostError("ldap_server_down")

        try:
            uid, password = credentials.split(":", 1)
        except ValueError:
            raise YunohostError("invalid_credentials")

        # Here we're explicitly using set() which are handled as hash tables
        # and should prevent timing attacks to find out the admin usernames?
        if uid not in set(admins):
            raise YunohostError("invalid_credentials")

        dn = AUTH_DN.format(uid=uid)

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(
                LDAP_URI, retry_max=10, retry_delay=0.5
            )
            con.simple_bind_s(dn, password)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
            raise YunohostError("invalid_credentials")
        except ldap.SERVER_DOWN:
            # ldap is down, attempt to restart it before really failing
            logger.warning(m18n.n("ldap_server_is_down_restart_it"))
            os.system("systemctl restart slapd")
            time.sleep(10)  # waits 10 secondes so we are sure that slapd has restarted

            try:
                con = _reconnect()
            except ldap.SERVER_DOWN:
                raise YunohostError("ldap_server_down")

        # Check that we are indeed logged in with the expected identity
        try:
            # whoami_s return dn:..., then delete these 3 characters
            who = con.whoami_s()[3:]
        except Exception as e:
            logger.warning("Error during ldap authentication process: %s", e)
            raise
        else:
            if who != dn:
                raise YunohostError(
                    f"Not logged with the appropriate identity ? Found {who}, expected {dn} !?",
                    raw_msg=True,
                )
        finally:
            # Free the connection, we don't really need it to keep it open as the point is only to check authentication...
            if con:
                con.unbind_s()

        return {"user": uid}

    def set_session_cookie(self, infos):
        from bottle import response

        assert isinstance(infos, dict)
        assert "user" in infos

        # Create a session id, built as <user_hash> + some random ascii
        # Prefixing with the user hash is meant to provide the ability to invalidate all this user's session
        # (eg because the user gets deleted, or password gets changed)
        # User hashing not really meant for security, just to sort of anonymize/pseudonymize the session file name
        infos["id"] = short_hash(infos["user"]) + random_ascii(20)

        response.set_cookie(
            "yunohost.admin",
            jwt.encode(infos, SESSION_SECRET(), algorithm="HS256"),
            secure=True,
            httponly=True,
            path="/yunohost/api",
            samesite="strict",
        )

        # Create the session file (expiration mechanism)
        session_file = f'{SESSION_FOLDER}/{infos["id"]}'
        os.system(f'touch "{session_file}"')

    def get_session_cookie(self, raise_if_no_session_exists=True):
        from bottle import request, response

        try:
            token = request.get_cookie("yunohost.admin", default="").encode()
            infos = jwt.decode(
                token,
                SESSION_SECRET(),
                algorithms="HS256",
                options={"require": ["id", "user"]},
            )
        except Exception:
            raise YunohostAuthenticationError("unable_authenticate")

        if not infos:
            raise YunohostAuthenticationError("unable_authenticate")

        self.purge_expired_session_files()
        session_file = f'{SESSION_FOLDER}/{infos["id"]}'
        if not os.path.exists(session_file):
            response.delete_cookie("yunohost.admin", path="/yunohost/api")
            raise YunohostAuthenticationError("session_expired")

        # Otherwise, we 'touch' the file to extend the validity
        os.system(f'touch "{session_file}"')

        return infos

    def delete_session_cookie(self):
        from bottle import response

        try:
            infos = self.get_session_cookie()
            session_file = f'{SESSION_FOLDER}/{infos["id"]}'
            os.remove(session_file)
        except Exception as e:
            logger.debug(
                f"User logged out, but failed to properly invalidate the session : {e}"
            )

        response.delete_cookie("yunohost.admin", path="/yunohost/api")

    def purge_expired_session_files(self):

        for session_file in Path(SESSION_FOLDER).iterdir():
            if abs(session_file.stat().st_mtime - time.time()) > SESSION_VALIDITY:
                try:
                    session_file.unlink()
                except Exception as e:
                    logger.debug(f"Failed to delete session file {session_file} ? {e}")

    @staticmethod
    def invalidate_all_sessions_for_user(user):

        for file in Path(SESSION_FOLDER).glob(f"{short_hash(user)}*"):
            try:
                file.unlink()
            except Exception as e:
                logger.debug(f"Failed to delete session file {file} ? {e}")
