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

def alias_list(auth, fields=None, filter=None, limit=None, offset=None):
    """
    List aliases

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for alias fetching
        limit -- Maximum number of alias fetched
        fields -- fields to fetch

    """
    _ensure_ldap_ou_is_created(auth)

    alias_attrs = { 'mail': 'alias',
                    'maildrop': 'mail-forward' }
    attrs = []
    result_list = []

    # Set default arguments values
    if offset is None:
        offset = 0
    if limit is None:
        limit = 1000
    if filter is None:
        filter = '(&(objectclass=mailAccount)(objectclass=mailAlias))'
    if fields:
        keys = alias_attrs.keys()
        for attr in fields:
            if attr in keys:
                attrs.append(attr)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('field_invalid', attr))
    else:
        attrs = [ 'mail', 'maildrop' ]

    result = auth.search('ou=aliases,dc=yunohost,dc=org', filter, attrs)

    if len(result) > offset and limit > 0:
        for alias in result[offset:offset+limit]:
            entry = {}
            for attr, values in alias.items():
                try:
                    entry[alias_attrs[attr]] = values[0:]
                except:
                    pass
            result_list.append(entry)
    return { 'alias' : result_list }


def alias_create(auth, alias, mailforward):
    """
    Create alias

    Keyword argument:
        alias -- Main mail address must be unique
        mailforward -- List of email to forward, separated by commas without space

    """
    from yunohost.domain import domain_list

    _ensure_ldap_ou_is_created(auth)

    # Validate uniqueness of alias and mail in LDAP
    auth.validate_uniqueness({
        'mail'      : alias
    })

    # Check that the mail domain exists
    if alias[alias.find('@')+1:] not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('mail_domain_unknown',
                                     alias[alias.find('@')+1:]))

    # Adapt values for LDAP
    rdn = 'mail=%s,ou=aliases' % alias
    attr_dict = {
        'objectClass'   : ['mailAccount', 'mailAlias'],
        'mail'          : alias
    }

    attr_dict['maildrop'] = mailforward.split(",")

    if auth.add(rdn, attr_dict):
        msignals.display(m18n.n('alias_created'), 'success')
        return { 'alias' : alias, 'mailforward' : attr_dict['maildrop'] }

    raise MoulinetteError(169, m18n.n('alias_creation_failed'))


def alias_delete(auth, alias):
    """
    Delete alias

    Keyword argument:
        alias -- Alias to delete

    """
    _ensure_ldap_ou_is_created(auth)

    if auth.remove('mail=%s,ou=aliases' % alias):
        pass
    else:
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

    if result:
        alias = result[0]
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('alias_unknown'))

    result_dict = {
        'alias': alias['mail'][0]
    }

    if len(alias['maildrop']) > 0:
        result_dict['mail-forward'] = alias['maildrop'][0:]

    if result:
        return result_dict
    else:
        raise MoulinetteError(167, m18n.n('alias_info_failed'))


def _ensure_ldap_ou_is_created(auth):
    """
    Make sure the 'ou=aliases' tree is created, for holding aliases entries.
    Raises an exception in case of error.
    
    Keyword argument:
        auth -- the auth object from moulinette, managing the LDAP connection
    """
    rdn = 'ou=aliases'
    attr_dict = {
           'objectClass'   : ['organizationalUnit', 'top'],
    }
    if not auth.search('dc=yunohost,dc=org', rdn, attr_dict['objectClass']) :
        if auth.add(rdn, attr_dict):
            msignals.display(m18n.n('alias_init'), 'success')
