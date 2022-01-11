# -*- coding: utf-8 -*-

import os
import logging
import ldap
import ldap.sasl
import time

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from yunohost.utils.error import YunohostError
from yunohost.utils.ldap import _get_ldap_interface


logger = logging.getLogger("yunohost.authenticators.ldap_admin")

LDAP_URI = "ldap://localhost:389"
ADMIN_GROUP = "cn=admins,ou=groups,dc=yunohost,dc=org"
AUTH_DN = "uid={uid},ou=users,dc=yunohost,dc=org"


class Authenticator(BaseAuthenticator):

    name = "ldap_admin"

    def __init__(self, *args, **kwargs):
        pass

    def _authenticate_credentials(self, credentials=None):

        admins = _get_ldap_interface().search(ADMIN_GROUP, attrs=["memberUid"])[0]["memberUid"]

        uid, password = credentials.split(":", 1)

        if uid not in admins:
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
