#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
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
import hashlib
import logging
import os
import time
from functools import cache
from pathlib import Path

import jwt
import ldap
import ldap.filter
import ldap.sasl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.filesystem import read_json
from moulinette.utils.text import random_ascii

from ..utils.error import YunohostAuthenticationError, YunohostError
from ..utils.ldap import _get_ldap_interface

logger = logging.getLogger("yunohostportal.authenticators.ldap_ynhuser")

SESSION_SECRET_PATH = Path("/etc/yunohost/.ssowat_cookie_secret")
SESSION_FOLDER = Path("/var/cache/yunohost-portal/sessions")
SESSION_VALIDITY = 3 * 24 * 3600  # 3 days


@cache
def SESSION_SECRET() -> str:
    # Only load this once actually requested to avoid boring issues like
    # "secret doesnt exists yet" (before postinstall) and therefore service
    # miserably fail to start
    return SESSION_SECRET_PATH.read_text().strip()


URI = "ldap://localhost:389"
USERDN = "uid={username},ou=users,dc=yunohost,dc=org"

# Cache on-disk settings to RAM for faster access
DOMAIN_USER_ACL_DICT: dict[str, dict] = {}
PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"


# Should a user have *minimal* access to a domain?
# - if the user has permission for an application with a URI on the domain, yes
# - if the user is an admin, yes
# - if the user has an email on the domain, yes
# - otherwise, no
def user_is_allowed_on_domain(user: str, domain: str) -> bool:
    assert "/" not in domain

    portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"

    if not portal_settings_path.exists():
        if "." not in domain:
            return False
        parent_domain = domain.split(".", 1)[-1]
        return user_is_allowed_on_domain(user, parent_domain)

    # Check that the domain permissions haven't changed on-disk since we read them
    # by comparing file mtime. If we haven't read the file yet, read it for the first time.
    # We compare mtime by equality not superiority because maybe the system clock has changed.
    mtime = portal_settings_path.stat().st_mtime
    if (
        domain not in DOMAIN_USER_ACL_DICT
        or DOMAIN_USER_ACL_DICT[domain]["mtime"] != mtime
    ):
        users: set[str] = set()
        for infos in read_json(str(portal_settings_path))["apps"].values():
            users = users.union(infos["users"])
        DOMAIN_USER_ACL_DICT[domain] = {}
        DOMAIN_USER_ACL_DICT[domain]["mtime"] = mtime
        DOMAIN_USER_ACL_DICT[domain]["users"] = users

    if user in DOMAIN_USER_ACL_DICT[domain]["users"]:
        # A user with explicit permission to an application is certainly welcome
        return True

    ADMIN_GROUP = "cn=admins,ou=groups"
    try:
        admins = (
            _get_ldap_interface()
            .search(ADMIN_GROUP, attrs=["memberUid"])[0]
            .get("memberUid", [])
        )
    except Exception as e:
        logger.error(f"Failed to list admin users: {e}")
        return False
    if user in admins:
        # Admins can access everything
        return True

    try:
        user_result = _get_ldap_interface().search("ou=users", f"uid={user}", ["mail"])
        if len(user_result) != 1:
            logger.error(
                f"User not found or many users found for {user}. How is this possible after so much validation?"
            )
            return False

        user_mail = user_result[0]["mail"]
        if len(user_mail) != 1:
            logger.error(
                f"User {user} found, but has the wrong number of email addresses: {user_mail}"
            )
            return False

        user_mail = user_mail[0]
        if "@" not in user_mail:
            logger.error(f"Invalid email address for {user}: {user_mail}")
            return False

        if user_mail.split("@")[1] == domain:
            # A user from that domain is welcome
            return True

        # Users from other domains don't belong here
        return False
    except Exception as e:
        logger.error(f"Failed to get email info for {user}: {e}")
        return False


def short_hash(data: str) -> str:
    return hashlib.shake_256(data.encode()).hexdigest(20)


class Authenticator(BaseAuthenticator):
    name = "ldap_ynhuser"

    def _authenticate_credentials(self, credentials=None):
        # FIXME we probably don't need this any more because now the authentication is handled by Authelia but
        # we might still need to provide an implementation for moulinette soo...
        from bottle import request

        try:
            username, password = credentials.split(":", 1)
        except ValueError:
            raise YunohostError("invalid_credentials")

        username = ldap.filter.escape_filter_chars(username)
        # Search username, if user give a mail instead
        if "@" in username:
            user = _get_ldap_interface().search("ou=users", f"mail={username}", ["uid"])
            if len(user) != 0:
                username = user[0]["uid"][0]

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(URI, retry_max=2, retry_delay=0.5)
            con.simple_bind_s(USERDN.format(username=username), password)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
            # FIXME FIXME FIXME : this should be properly logged and caught by Fail2ban ! !  ! ! ! ! !
            raise YunohostError("invalid_password")
        except ldap.SERVER_DOWN:
            logger.warning(m18n.n("ldap_server_down"))

        # Check that we are indeed logged in with the expected identity
        try:
            # whoami_s return dn:..., then delete these 3 characters
            who = con.whoami_s()[3:]
        except Exception as e:
            logger.warning("Error during ldap authentication process: %s", e)
            raise
        else:
            if who != USERDN.format(username=username):
                raise YunohostError(
                    "Not logged with the appropriate identity ?!",
                    raw_msg=True,
                )
        finally:
            # Free the connection, we don't really need it to keep it open as the point is only to check authentication...
            if con:
                con.unbind_s()

            ldap_user_infos = _get_ldap_interface().search(
                "ou=users", f"uid={username}", attrs=["cn", "mail"]
            )[0]

        if not user_is_allowed_on_domain(username, request.get_header("host")):
            raise YunohostAuthenticationError("unable_authenticate")

        return {
            "user": username,
            "pwd": encrypt(password),
            "email": ldap_user_infos["mail"][0],
            "fullname": ldap_user_infos["cn"][0],
        }

    def set_session_cookie(self, infos):
        # Session cookie are now handled by Authelia
        pass

    def get_session_cookie(self):
        from bottle import request, response

        try:
            infos = {
                'username': request.get_header("Ynh-User"),
                'host': request.get_header("host")
            } if request.get_header("Ynh-User") else None

        except Exception:
            raise YunohostAuthenticationError("unable_authenticate")

        if not infos:
            raise YunohostAuthenticationError("unable_authenticate")

        if infos["host"] != request.get_header("host"):
            raise YunohostAuthenticationError("unable_authenticate")

        if not user_is_allowed_on_domain(infos["user"], infos["host"]):
            raise YunohostAuthenticationError("unable_authenticate")

        return infos

    def delete_session_cookie(self):
        # Session cookie are now handled by Authelia
        pass

    def purge_expired_session_files(self):
        # Session cookie are now handled by Authelia
        pass

    @staticmethod
    def invalidate_all_sessions_for_user(user: str) -> None:
        for file in SESSION_FOLDER.glob(f"{short_hash(user)}*"):
            try:
                file.unlink()
            except Exception as e:
                logger.debug(f"Failed to delete session file {file} ? {e}")
