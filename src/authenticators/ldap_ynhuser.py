# -*- coding: utf-8 -*-

import jwt
import logging
import ldap
import ldap.sasl
import datetime

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.text import random_ascii
from yunohost.utils.error import YunohostError, YunohostAuthenticationError

# FIXME : we shall generate this somewhere if it doesnt exists yet
# FIXME : fix permissions
session_secret = open("/etc/yunohost/.ssowat_cookie_secret").read()

logger = logging.getLogger("yunohostportal.authenticators.ldap_ynhuser")

URI = "ldap://localhost:389"
USERDN = "uid={username},ou=users,dc=yunohost,dc=org"


class Authenticator(BaseAuthenticator):

    name = "ldap_ynhuser"

    def _authenticate_credentials(self, credentials=None):

        # FIXME ':' should a legit char in the password ? shall we encode the password as base64 or something idk
        if ":" not in credentials or len(credentials.split(":")) != 2:
            raise YunohostError("invalid_credentials_format")

        username, password = credentials.split(":")

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(
                URI, retry_max=2, retry_delay=0.5
            )
            con.simple_bind_s(USERDN.format(username=username), password)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
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







        # FIXME FIXME FIXME : the password is to be encrypted to not expose it in the JWT cookie which is only signed and base64 encoded but not encrypted









        return {"user": username, "password": password}

    def set_session_cookie(self, infos):

        from bottle import response

        assert isinstance(infos, dict)

        # This allows to generate a new session id or keep the existing one
        current_infos = self.get_session_cookie(raise_if_no_session_exists=False)
        new_infos = {
            "id": current_infos["id"],
            # See https://pyjwt.readthedocs.io/en/latest/usage.html#registered-claim-names
            # for explanations regarding nbf, exp
            "nbf": int(datetime.datetime.now().timestamp()),
            "exp": int(datetime.datetime.now().timestamp()) + (7 * 24 * 3600)  # One week validity
        }
        new_infos.update(infos)

        response.set_cookie(
            "yunohost.portal",
            jwt.encode(new_infos, session_secret, algorithm="HS256").decode(),
            secure=True,
            httponly=True,
            path="/",
            # samesite="strict", # Bottle 0.12 doesn't support samesite, to be added in next versions
            # FIXME : add Expire clause
        )

    def get_session_cookie(self, raise_if_no_session_exists=True):

        from bottle import request

        try:
            token = request.get_cookie("yunohost.portal", default="").encode()
            infos = jwt.decode(token, session_secret, algorithms="HS256", options={"require": ["id", "user", "exp", "nbf"]})
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

        response.set_cookie("yunohost.portal", "", max_age=-1)
        response.delete_cookie("yunohost.portal")
