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

import atexit
from moulinette.core import init_authenticator

# We use a global variable to do some caching
# to avoid re-authenticating in case we call _get_ldap_authenticator multiple times
_ldap_interface = None

def _get_ldap_interface():

    global _ldap_interface

    if _ldap_interface is None:
        # Instantiate LDAP Authenticator
        AUTH_IDENTIFIER = ('ldap', 'as-root')
        AUTH_PARAMETERS = {'uri': 'ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi',
                           'base_dn': 'dc=yunohost,dc=org',
                           'user_rdn': 'gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth'}
        _ldap_interface = init_authenticator(AUTH_IDENTIFIER, AUTH_PARAMETERS)

    return _ldap_interface

# Add this to properly close / delete the ldap interface / authenticator
# when Python exits ...
# Otherwise there's a risk that some funky error appears at the very end
# of the command due to Python stuff being unallocated in wrong order.
def _destroy_ldap_interface():
    global _ldap_interface
    if _ldap_interface is not None:
        del _ldap_interface

atexit.register(_destroy_ldap_interface)
