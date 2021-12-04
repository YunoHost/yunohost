# -*- coding: utf-8 -*-

import logging
import ldap
import ldap.sasl

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from yunohost.utils.error import YunohostError

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
