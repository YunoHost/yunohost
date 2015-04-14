# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2014 YUNOHOST.ORG

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


def alias_init(auth):
    """
    Init alias schema, workaround to activate alias on an existing install, better solution needed
    """
    rdn = 'ou=alias'
    attr_dict = {
           'objectClass'   : ['organizationalUnit', 'top'],
    }
    if auth.add(rdn, attr_dict):
        msignals.display(m18n.n('alias_init'), 'success')

def alias_list(auth, fields=None, filter=None, limit=None, offset=None):
    """
    List alias

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for alias fetching
        limit -- Maximum number of alias fetched
        fields -- fields to fetch

    """
    alias_attrs = { 'mail': 'alias',
                   'cn': 'name',
                   'maildrop': 'mail-forward'}
    attrs = []
    result_list = []

    # Set default arguments values
    if offset is None:
        offset = 0
    if limit is None:
        limit = 1000
    if filter is None:
        filter = '(&(objectclass=mailAccount)(!(uid=root))(!(uid=nobody)))'
    if fields:
        keys = alias_attrs.keys()
        for attr in fields:
            if attr in keys:
                attrs.append(attr)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('field_invalid', attr))
    else:
        attrs = [ 'mail', 'cn', 'maildrop' ]

    result = auth.search('ou=alias,dc=yunohost,dc=org', filter, attrs)

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


def alias_create(auth, alias, name, mailforward):
    """
    Create alias

    Keyword argument:
        name --
        alias -- Main mail address must be unique
        mailforward -- List of email to forward, separated by commas without space

    """
    from yunohost.domain import domain_list

    # Validate uniqueness of alias and mail in LDAP
    auth.validate_uniqueness({
        'uid'       : alias,
        'mail'      : alias
    })

    # Check that the mail domain exists
    if alias[alias.find('@')+1:] not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('mail_domain_unknown',
                                     alias[alias.find('@')+1:]))

    # Adapt values for LDAP
    rdn = 'uid=%s,ou=alias' % alias
    attr_dict = {
        'objectClass'   : ['mailAccount', 'inetOrgPerson'],
        'sn'            : alias,
        'displayName'   : name,
        'cn'            : name,
        'uid'           : alias,
        'mail'          : alias
    }

    attr_dict['maildrop'] = mailforward.split(",")

    if auth.add(rdn, attr_dict):
        msignals.display(m18n.n('alias_created'), 'success')
        return { 'alias' : alias, 'name' : name, 'mailforward' : attr_dict['maildrop'] }

    raise MoulinetteError(169, m18n.n('alias_creation_failed'))


def alias_delete(auth, alias):
    """
    Delete alias

    Keyword argument:
        alias -- Alias to delete

    """

    if auth.remove('uid=%s,ou=alias' % alias):
        pass
    else:
        raise MoulinetteError(169, m18n.n('alias_deletion_failed'))

    msignals.display(m18n.n('alias_deleted'), 'success')


def alias_update(auth, alias, name=None, add_mailforward=None, remove_mailforward=None):
    """
    Update alias informations

    Keyword argument:
        alias
        name
        remove_mailforward -- Mailforward addresses to remove
        add_mailforward -- Mailforward addresses to add

    """

    attrs_to_fetch = ['uid', 'cn', 'displayName', 'maildrop']
    new_attr_dict = {}

    # Populate alias informations
    result = auth.search(base='ou=alias,dc=yunohost,dc=org', filter='uid=' + alias, attrs=attrs_to_fetch)
    if not result:
        raise MoulinetteError(errno.EINVAL, m18n.n('alias_unknown'))
    alias_fetched = result[0]

    # Get modifications from arguments
    if name:
        new_attr_dict['cn'] = name
        new_attr_dict['displayName'] = name

    if add_mailforward:
        add_mailforward = add_mailforward.split(",")
        for mail in add_mailforward:
            if mail in alias_fetched['maildrop'][1:]:
                continue
            alias_fetched['maildrop'].append(mail)
        new_attr_dict['maildrop'] = alias_fetched['maildrop']

    if remove_mailforward:
        remove_mailforward = remove_mailforward.split(",")
        for mail in remove_mailforward:
            if mail not in alias_fetched['maildrop'][1:]:
                continue
            alias_fetched['maildrop'].remove(mail)
        new_attr_dict['maildrop'] = alias_fetched['maildrop']

    if auth.update('uid=%s,ou=alias' % alias, new_attr_dict):
       msignals.display(m18n.n('alias_updated'), 'success')
       return alias_info(auth, alias)
    else:
       raise MoulinetteError(169, m18n.n('alias_update_failed'))


def alias_info(auth, alias):
    """
    Get alias informations

    Keyword argument:
        alias -- Alias mail to get informations

    """
    alias_attrs = [
        'cn', 'mail', 'uid', 'maildrop', 'givenName', 'sn'
    ]

    if len(alias.split('@')) is 2:
        filter = 'mail=' + alias
    else:
        filter = 'uid=' + alias

    result = auth.search('ou=alias,dc=yunohost,dc=org', filter, alias_attrs)

    if result:
        alias = result[0]
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('alias_unknown'))

    result_dict = {
        'alias': alias['mail'][0],
        'name': alias['cn'][0],
    }

    if len(alias['maildrop']) > 1:
        result_dict['mail-forward'] = alias['maildrop'][0:]

    if result:
        return result_dict
    else:
        raise MoulinetteError(167, m18n.n('alias_info_failed'))
