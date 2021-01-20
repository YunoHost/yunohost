# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2019 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

import os
import atexit
from moulinette.core import MoulinetteLdapIsDownError
from moulinette.authenticators import ldap
from yunohost.utils.error import YunohostError

# We use a global variable to do some caching
# to avoid re-authenticating in case we call _get_ldap_authenticator multiple times
_ldap_interface = None


def _get_ldap_interface():

    global _ldap_interface

    if _ldap_interface is None:

        conf = {
            "vendor": "ldap",
            "name": "as-root",
            "parameters": {
                "uri": "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
                "base_dn": "dc=yunohost,dc=org",
                "user_rdn": "gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth",
            },
            "extra": {},
        }

        try:
            _ldap_interface = ldap.Authenticator(**conf)
        except MoulinetteLdapIsDownError:
            raise YunohostError(
                "Service slapd is not running but is required to perform this action ... You can try to investigate what's happening with 'systemctl status slapd'"
            )

        assert_slapd_is_running()

    return _ldap_interface


def assert_slapd_is_running():

    # Assert slapd is running...
    if not os.system("pgrep slapd >/dev/null") == 0:
        raise YunohostError(
            "Service slapd is not running but is required to perform this action ... You can try to investigate what's happening with 'systemctl status slapd'"
        )


# We regularly want to extract stuff like 'bar' in ldap path like
# foo=bar,dn=users.example.org,ou=example.org,dc=org so this small helper allow
# to do this without relying of dozens of mysterious string.split()[0]
#
# e.g. using _ldap_path_extract(path, "foo") on the previous example will
# return bar


def _ldap_path_extract(path, info):
    for element in path.split(","):
        if element.startswith(info + "="):
            return element[len(info + "=") :]


# Add this to properly close / delete the ldap interface / authenticator
# when Python exits ...
# Otherwise there's a risk that some funky error appears at the very end
# of the command due to Python stuff being unallocated in wrong order.
def _destroy_ldap_interface():
    global _ldap_interface
    if _ldap_interface is not None:
        del _ldap_interface


atexit.register(_destroy_ldap_interface)
