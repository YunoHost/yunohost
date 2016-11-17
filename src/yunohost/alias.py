# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2016 YUNOHOST.ORG

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

""" yunohost_alias.py

    Manage alias
"""

import errno

from moulinette.core import MoulinetteError
from yunohost.domain import domain_list


def alias_list(auth):
    """
    List aliases

    """
    _ensure_ldap_ou_is_created(auth)
    ldap_filter = '(&(objectclass=mailAccount)(objectclass=mailAlias))'
    ldap_attrs = ['mail', 'maildrop']
    result = auth.search('ou=aliases,dc=yunohost,dc=org', ldap_filter, ldap_attrs)
    return {'alias': result}


def alias_create(auth, alias, mailforward):
    """
    Create alias

    Keyword argument:
        alias -- Main mail address must be unique
        mailforward -- List of email to forward, separated by commas without space

    """
    _ensure_ldap_ou_is_created(auth)

    # Validate uniqueness of alias and mail in LDAP
    auth.validate_uniqueness({
        'mail': alias,
    })

    # Check that the mail domain exists
    alias_domain = alias[alias.find('@') + 1:]
    if alias_domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('mail_domain_unknown',
                                     alias_domain))

    # Adapt values for LDAP
    rdn = 'mail=%s,ou=aliases' % alias
    attr_dict = {
        'objectClass': ['mailAccount', 'mailAlias'],
        'mail': alias,
        'maildrop': mailforward.split(",")
    }

    success = auth.add(rdn, attr_dict)
    if not success:
        raise MoulinetteError(169, m18n.n('alias_creation_failed'))

    msignals.display(m18n.n('alias_created'), 'success')
    return {'alias': alias, 'maildrop': attr_dict['maildrop']}


def alias_update(auth, alias, add_mailforward=None, remove_mailforward=None):
    """
    Update alias informations
    Keyword argument:
        alias
        add_mailforward -- Mailforward addresses to add
        remove_mailforward -- Mailforward addresses to remove
    """
    _ensure_ldap_ou_is_created(auth)

    # normalize input
    if not isinstance(add_mailforward, list):
        add_mailforward = [add_mailforward]

    if not isinstance(add_mailforward, list):
        add_mailforward = [add_mailforward]

    alias_attrs = [
        'mail', 'maildrop'
    ]

    if len(alias.split('@')) == 2:
        ldap_filter = 'mail=%s' % alias
    else:
        # TODO better error message
        raise MoulinetteError(167, m18n.n('alias_info_failed'))

    result = auth.search('ou=aliases,dc=yunohost,dc=org', ldap_filter, alias_attrs)

    if not result:
        raise MoulinetteError(errno.EINVAL, m18n.n('alias_unknown'))

    current_alias_info = result[0]

    # Get modifications from arguments
    if add_mailforward:
        for mail in add_mailforward:
            if mail not in current_alias_info['maildrop']:
                current_alias_info['maildrop'].append(mail)

    if remove_mailforward:
        for mail in remove_mailforward:
            if mail in current_alias_info['maildrop'][1:]:
                current_alias_info['maildrop'].remove(mail)

    success = auth.update('mail=%s,ou=aliases' % alias, current_alias_info)
    if not success:
        raise MoulinetteError(169, m18n.n('alias_update_failed'))

    msignals.display(m18n.n('alias_updated'), 'success')
    return alias_info(auth, alias)


def alias_delete(auth, alias):
    """
    Delete alias

    Keyword argument:
        alias -- Alias to delete

    """
    _ensure_ldap_ou_is_created(auth)

    success = auth.remove('mail=%s,ou=aliases' % alias)
    if not success:
        raise MoulinetteError(169, m18n.n('alias_deletion_failed'))

    msignals.display(m18n.n('alias_deleted'), 'success')


def alias_info(auth, alias):
    """
    Get alias informations

    Keyword argument:
        alias -- Alias mail to get informations

    """
    _ensure_ldap_ou_is_created(auth)

    alias_attrs = [
        'mail', 'maildrop'
    ]

    if len(alias.split('@')) is 2:
        filter = 'mail=' + alias
    else:
        # TODO better error message
        raise MoulinetteError(167, m18n.n('alias_info_failed'))

    result = auth.search('ou=aliases,dc=yunohost,dc=org', filter, alias_attrs)

    if not result:
        raise MoulinetteError(errno.EINVAL, m18n.n('alias_unknown'))

    return result[0]


def _ensure_ldap_ou_is_created(auth):
    """
    Make sure the 'ou=aliases' tree is created, for holding aliases entries.
    Raises an exception in case of error.

    Keyword argument:
        auth -- the auth object from moulinette, managing the LDAP connection
    """
    rdn = 'ou=aliases'
    attr_dict = {
        'objectClass': ['organizationalUnit', 'top'],
    }

    result = auth.search('dc=yunohost,dc=org', rdn, attr_dict['objectClass'])

    if not result:
        if auth.add(rdn, attr_dict):
            msignals.display(m18n.n('alias_init'), 'success')
