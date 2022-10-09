#
# Copyright (c) 2022 YunoHost Contributors
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
import logging
import ldap
import ldap.sasl
import time

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.text import random_ascii

from yunohost.utils.error import YunohostError, YunohostAuthenticationError
from yunohost.utils.ldap import _get_ldap_interface

session_secret = random_ascii()
logger = logging.getLogger("yunohost.authenticators.ldap_admin")

LDAP_URI = "ldap://localhost:389"
ADMIN_GROUP = "cn=admins,ou=groups"
AUTH_DN = "uid={uid},ou=users,dc=yunohost,dc=org"

class Authenticator(BaseAuthenticator):

    name = "ldap_admin"

    def __init__(self, *args, **kwargs):
        pass

    def _authenticate_credentials(self, credentials=None):

        try:
            admins = _get_ldap_interface().search(ADMIN_GROUP, attrs=["memberUid"])[0].get("memberUid", [])
        except ldap.SERVER_DOWN:
            # ldap is down, attempt to restart it before really failing
            logger.warning(m18n.n("ldap_server_is_down_restart_it"))
            os.system("systemctl restart slapd")
            time.sleep(10)  # waits 10 secondes so we are sure that slapd has restarted

            # Force-reset existing LDAP interface
            from yunohost.utils import ldap as ldaputils
            ldaputils._ldap_interface = None

            try:
                admins = _get_ldap_interface().search(ADMIN_GROUP, attrs=["memberUid"])[0].get("memberUid", [])
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
                raise YunohostError(f"Not logged with the appropriate identity ? Found {who}, expected {dn} !?", raw_msg=True)
        finally:
            # Free the connection, we don't really need it to keep it open as the point is only to check authentication...
            if con:
                con.unbind_s()

    def set_session_cookie(self, infos):

        from bottle import response

        assert isinstance(infos, dict)

        # This allows to generate a new session id or keep the existing one
        current_infos = self.get_session_cookie(raise_if_no_session_exists=False)
        new_infos = {"id": current_infos["id"]}
        new_infos.update(infos)

        response.set_cookie(
            "yunohost.admin",
            new_infos,
            secure=True,
            secret=session_secret,
            httponly=True,
            # samesite="strict", # Bottle 0.12 doesn't support samesite, to be added in next versions
        )

    def get_session_cookie(self, raise_if_no_session_exists=True):

        from bottle import request

        try:
            # N.B. : here we implicitly reauthenticate the cookie
            # because it's signed via the session_secret
            # If no session exists (or if session is invalid?)
            # it's gonna return the default empty dict,
            # which we interpret as an authentication failure
            infos = request.get_cookie(
                "yunohost.admin", secret=session_secret, default={}
            )
        except Exception:
            if not raise_if_no_session_exists:
                return {"id": random_ascii()}
            raise YunohostAuthenticationError("unable_authenticate")

        if not infos and raise_if_no_session_exists:
            raise YunohostAuthenticationError("unable_authenticate")

        if "id" not in infos:
            infos["id"] = random_ascii()

        # FIXME: Here, maybe we want to re-authenticate the session via the authenticator
        # For example to check that the username authenticated is still in the admin group...

        return infos

    def delete_session_cookie(self):

        from bottle import response

        response.set_cookie("yunohost.admin", "", max_age=-1)
        response.delete_cookie("yunohost.admin")
