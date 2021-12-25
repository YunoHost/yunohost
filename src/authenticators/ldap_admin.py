# -*- coding: utf-8 -*-

import os
import logging
import ldap
import ldap.sasl
import time

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.text import random_ascii

from yunohost.utils.error import YunohostError, YunohostAuthenticationError

logger = logging.getLogger("yunohost.authenticators.ldap_admin")

session_secret = random_ascii()


class Authenticator(BaseAuthenticator):

    name = "ldap_admin"

    def __init__(self, *args, **kwargs):
        self.uri = "ldap://localhost:389"
        self.basedn = "dc=yunohost,dc=org"
        self.admindn = "cn=admin,dc=yunohost,dc=org"

    def _authenticate_credentials(self, credentials=None):

        # TODO : change authentication format
        # to support another dn to support multi-admins

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(
                self.uri, retry_max=10, retry_delay=0.5
            )
            con.simple_bind_s(self.admindn, credentials)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
            raise YunohostError("invalid_password")
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
            if who != self.admindn:
                raise YunohostError(
                    f"Not logged with the appropriate identity ? Found {who}, expected {self.admindn} !?",
                    raw_msg=True,
                )
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

    @staticmethod
    def delete_session_cookie(self):

        from bottle import response

        response.set_cookie("yunohost.admin", "", max_age=-1)
        response.delete_cookie("yunohost.admin")
