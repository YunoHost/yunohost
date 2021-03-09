# -*- coding: utf-8 -*-

import os
import logging
import ldap
import ldap.sasl
import time
import ldap.modlist as modlist

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.authentication import BaseAuthenticator
from yunohost.utils.error import YunohostError

logger = logging.getLogger("yunohost.authenticators.ldap_admin")

class Authenticator(BaseAuthenticator):

    """LDAP Authenticator

    Initialize a LDAP connexion for the given arguments. It attempts to
    authenticate a user if 'user_rdn' is given - by associating user_rdn
    and base_dn - and provides extra methods to manage opened connexion.

    Keyword arguments:
        - uri -- The LDAP server URI
        - base_dn -- The base dn
        - user_rdn -- The user rdn to authenticate

    """

    name = "ldap_admin"

    def __init__(self, *args, **kwargs):
        self.uri = "ldap://localhost:389"
        self.basedn = "dc=yunohost,dc=org"
        self.admindn = "cn=admin,dc=yunohost,dc=org"

    def authenticate(self, password=None):
        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(
                self.uri, retry_max=10, retry_delay=0.5
            )
            con.simple_bind_s(self.admindn, password)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
            raise MoulinetteError("invalid_password")
        except ldap.SERVER_DOWN:
            # ldap is down, attempt to restart it before really failing
            logger.warning(m18n.g("ldap_server_is_down_restart_it"))
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
                raise MoulinetteError(f"Not logged with the appropriate identity ? Found {who}, expected {self.admindn} !?")
        finally:
            # Free the connection, we don't really need it to keep it open as the point is only to check authentication...
            if con:
                con.unbind_s()
