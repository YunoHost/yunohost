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

""" yunohost_user.py

    Manage users
"""
import os
import re
import pwd
import grp
import json
import crypt
import random
import string
import subprocess

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from yunohost.service import service_status
from yunohost.log import is_unit_operation

logger = getActionLogger('yunohost.user')


def user_list(fields=None):
    """
    List users

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for user fetching
        limit -- Maximum number of user fetched
        fields -- fields to fetch

    """
    from yunohost.utils.ldap import _get_ldap_interface

    user_attrs = {
        'uid': 'username',
        'cn': 'fullname',
        'mail': 'mail',
        'maildrop': 'mail-forward',
        'loginShell': 'shell',
        'homeDirectory': 'home_path',
        'mailuserquota': 'mailbox-quota'
    }

    attrs = ['uid']
    users = {}

    if fields:
        keys = user_attrs.keys()
        for attr in fields:
            if attr in keys:
                attrs.append(attr)
            else:
                raise YunohostError('field_invalid', attr)
    else:
        attrs = ['uid', 'cn', 'mail', 'mailuserquota', 'loginShell']

    ldap = _get_ldap_interface()
    result = ldap.search('ou=users,dc=yunohost,dc=org',
                         '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))',
                         attrs)

    for user in result:
        entry = {}
        for attr, values in user.items():
            if values:
                if attr == "loginShell":
                    if values[0].strip() == "/bin/false":
                        entry["ssh_allowed"] = False
                    else:
                        entry["ssh_allowed"] = True

                entry[user_attrs[attr]] = values[0]

        uid = entry[user_attrs['uid']]
        users[uid] = entry

    return {'users': users}


@is_unit_operation([('username', 'user')])
def user_create(operation_logger, username, firstname, lastname, mail, password,
                mailbox_quota="0"):
    """
    Create user

    Keyword argument:
        firstname
        lastname
        username -- Must be unique
        mail -- Main mail address must be unique
        password
        mailbox_quota -- Mailbox size quota

    """
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.hook import hook_callback
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.utils.ldap import _get_ldap_interface

    # Ensure sufficiently complex password
    assert_password_is_strong_enough("user", password)

    ldap = _get_ldap_interface()

    # Validate uniqueness of username and mail in LDAP
    ldap.validate_uniqueness({
        'uid': username,
        'mail': mail,
        'cn': username
    })

    # Validate uniqueness of username in system users
    all_existing_usernames = {x.pw_name for x in pwd.getpwall()}
    if username in all_existing_usernames:
        raise YunohostError('system_username_exists')

    main_domain = _get_maindomain()
    aliases = [
        'root@' + main_domain,
        'admin@' + main_domain,
        'webmaster@' + main_domain,
        'postmaster@' + main_domain,
    ]

    if mail in aliases:
        raise YunohostError('mail_unavailable')

    # Check that the mail domain exists
    if mail.split("@")[1] not in domain_list()['domains']:
        raise YunohostError('mail_domain_unknown', domain=mail.split("@")[1])

    operation_logger.start()

    # Get random UID/GID
    all_uid = {x.pw_uid for x in pwd.getpwall()}
    all_gid = {x.gr_gid for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        uid = str(random.randint(200, 99999))
        uid_guid_found = uid not in all_uid and uid not in all_gid

    # Adapt values for LDAP
    fullname = '%s %s' % (firstname, lastname)
    attr_dict = {
        'objectClass': ['mailAccount', 'inetOrgPerson', 'posixAccount', 'userPermissionYnh'],
        'givenName': firstname,
        'sn': lastname,
        'displayName': fullname,
        'cn': fullname,
        'uid': username,
        'mail': mail,
        'maildrop': username,
        'mailuserquota': mailbox_quota,
        'userPassword': _hash_user_password(password),
        'gidNumber': uid,
        'uidNumber': uid,
        'homeDirectory': '/home/' + username,
        'loginShell': '/bin/false'
    }

    # If it is the first user, add some aliases
    if not ldap.search(base='ou=users,dc=yunohost,dc=org', filter='uid=*'):
        attr_dict['mail'] = [attr_dict['mail']] + aliases

        # If exists, remove the redirection from the SSO
        try:
            with open('/etc/ssowat/conf.json.persistent') as json_conf:
                ssowat_conf = json.loads(str(json_conf.read()))
        except ValueError as e:
            raise YunohostError('ssowat_persistent_conf_read_error', error=e.strerror)
        except IOError:
            ssowat_conf = {}

        if 'redirected_urls' in ssowat_conf and '/' in ssowat_conf['redirected_urls']:
            del ssowat_conf['redirected_urls']['/']
            try:
                with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
                    json.dump(ssowat_conf, f, sort_keys=True, indent=4)
            except IOError as e:
                raise YunohostError('ssowat_persistent_conf_write_error', error=e.strerror)

    if ldap.add('uid=%s,ou=users' % username, attr_dict):
        # Invalidate passwd to take user creation into account
        subprocess.call(['nscd', '-i', 'passwd'])

        try:
            # Attempt to create user home folder
            subprocess.check_call(
                ['su', '-', username, '-c', "''"])
        except subprocess.CalledProcessError:
            if not os.path.isdir('/home/{0}'.format(username)):
                logger.warning(m18n.n('user_home_creation_failed'),
                               exc_info=1)

        # Create group for user and add to group 'all_users'
        user_group_add(groupname=username, gid=uid, sync_perm=False)
        user_group_update(groupname=username, add_user=username, force=True, sync_perm=False)
        user_group_update(groupname='all_users', add_user=username, force=True, sync_perm=True)

        # TODO: Send a welcome mail to user
        logger.success(m18n.n('user_created'))

        hook_callback('post_user_create',
                      args=[username, mail, password, firstname, lastname])

        return {'fullname': fullname, 'username': username, 'mail': mail}

    raise YunohostError('user_creation_failed')


@is_unit_operation([('username', 'user')])
def user_delete(operation_logger, username, purge=False):
    """
    Delete user

    Keyword argument:
        username -- Username to delete
        purge

    """
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface

    operation_logger.start()

    ldap = _get_ldap_interface()
    if ldap.remove('uid=%s,ou=users' % username):
        # Invalidate passwd to take user deletion into account
        subprocess.call(['nscd', '-i', 'passwd'])

        if purge:
            subprocess.call(['rm', '-rf', '/home/{0}'.format(username)])
            subprocess.call(['rm', '-rf', '/var/mail/{0}'.format(username)])
    else:
        raise YunohostError('user_deletion_failed')

    user_group_delete(username, force=True, sync_perm=True)

    group_list = ldap.search('ou=groups,dc=yunohost,dc=org',
                             '(&(objectclass=groupOfNamesYnh)(memberUid=%s))'
                             % username, ['cn'])
    for group in group_list:
        user_list = ldap.search('ou=groups,dc=yunohost,dc=org',
                                'cn=' + group['cn'][0],
                                ['memberUid'])[0]
        user_list['memberUid'].remove(username)
        if not ldap.update('cn=%s,ou=groups' % group['cn'][0], user_list):
            raise YunohostError('group_update_failed')

    hook_callback('post_user_delete', args=[username, purge])

    logger.success(m18n.n('user_deleted'))


@is_unit_operation([('username', 'user')], exclude=['change_password'])
def user_update(operation_logger, username, firstname=None, lastname=None, mail=None,
                change_password=None, add_mailforward=None, remove_mailforward=None,
                add_mailalias=None, remove_mailalias=None, mailbox_quota=None):
    """
    Update user informations

    Keyword argument:
        lastname
        mail
        firstname
        add_mailalias -- Mail aliases to add
        remove_mailforward -- Mailforward addresses to remove
        username -- Username of user to update
        add_mailforward -- Mailforward addresses to add
        change_password -- New password to set
        remove_mailalias -- Mail aliases to remove

    """
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.app import app_ssowatconf
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.utils.ldap import _get_ldap_interface

    domains = domain_list()['domains']

    # Populate user informations
    ldap = _get_ldap_interface()
    attrs_to_fetch = ['givenName', 'sn', 'mail', 'maildrop']
    result = ldap.search(base='ou=users,dc=yunohost,dc=org', filter='uid=' + username, attrs=attrs_to_fetch)
    if not result:
        raise YunohostError('user_unknown', user=username)
    user = result[0]

    # Get modifications from arguments
    new_attr_dict = {}
    if firstname:
        new_attr_dict['givenName'] = firstname  # TODO: Validate
        new_attr_dict['cn'] = new_attr_dict['displayName'] = firstname + ' ' + user['sn'][0]

    if lastname:
        new_attr_dict['sn'] = lastname  # TODO: Validate
        new_attr_dict['cn'] = new_attr_dict['displayName'] = user['givenName'][0] + ' ' + lastname

    if lastname and firstname:
        new_attr_dict['cn'] = new_attr_dict['displayName'] = firstname + ' ' + lastname

    if change_password:
        # Ensure sufficiently complex password
        assert_password_is_strong_enough("user", change_password)

        new_attr_dict['userPassword'] = _hash_user_password(change_password)

    if mail:
        main_domain = _get_maindomain()
        aliases = [
            'root@' + main_domain,
            'admin@' + main_domain,
            'webmaster@' + main_domain,
            'postmaster@' + main_domain,
        ]
        ldap.validate_uniqueness({'mail': mail})
        if mail[mail.find('@') + 1:] not in domains:
            raise YunohostError('mail_domain_unknown', domain=mail[mail.find('@') + 1:])
        if mail in aliases:
            raise YunohostError('mail_unavailable')

        del user['mail'][0]
        new_attr_dict['mail'] = [mail] + user['mail']

    if add_mailalias:
        if not isinstance(add_mailalias, list):
            add_mailalias = [add_mailalias]
        for mail in add_mailalias:
            ldap.validate_uniqueness({'mail': mail})
            if mail[mail.find('@') + 1:] not in domains:
                raise YunohostError('mail_domain_unknown', domain=mail[mail.find('@') + 1:])
            user['mail'].append(mail)
        new_attr_dict['mail'] = user['mail']

    if remove_mailalias:
        if not isinstance(remove_mailalias, list):
            remove_mailalias = [remove_mailalias]
        for mail in remove_mailalias:
            if len(user['mail']) > 1 and mail in user['mail'][1:]:
                user['mail'].remove(mail)
            else:
                raise YunohostError('mail_alias_remove_failed', mail=mail)
        new_attr_dict['mail'] = user['mail']

    if add_mailforward:
        if not isinstance(add_mailforward, list):
            add_mailforward = [add_mailforward]
        for mail in add_mailforward:
            if mail in user['maildrop'][1:]:
                continue
            user['maildrop'].append(mail)
        new_attr_dict['maildrop'] = user['maildrop']

    if remove_mailforward:
        if not isinstance(remove_mailforward, list):
            remove_mailforward = [remove_mailforward]
        for mail in remove_mailforward:
            if len(user['maildrop']) > 1 and mail in user['maildrop'][1:]:
                user['maildrop'].remove(mail)
            else:
                raise YunohostError('mail_forward_remove_failed', mail=mail)
        new_attr_dict['maildrop'] = user['maildrop']

    if mailbox_quota is not None:
        new_attr_dict['mailuserquota'] = mailbox_quota

    operation_logger.start()

    if ldap.update('uid=%s,ou=users' % username, new_attr_dict):
        logger.success(m18n.n('user_updated'))
        app_ssowatconf()
        return user_info(username)
    else:
        raise YunohostError('user_update_failed')


def user_info(username):
    """
    Get user informations

    Keyword argument:
        username -- Username or mail to get informations

    """
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    user_attrs = [
        'cn', 'mail', 'uid', 'maildrop', 'givenName', 'sn', 'mailuserquota'
    ]

    if len(username.split('@')) == 2:
        filter = 'mail=' + username
    else:
        filter = 'uid=' + username

    result = ldap.search('ou=users,dc=yunohost,dc=org', filter, user_attrs)

    if result:
        user = result[0]
    else:
        raise YunohostError('user_unknown', user=username)

    result_dict = {
        'username': user['uid'][0],
        'fullname': user['cn'][0],
        'firstname': user['givenName'][0],
        'lastname': user['sn'][0],
        'mail': user['mail'][0]
    }

    if len(user['mail']) > 1:
        result_dict['mail-aliases'] = user['mail'][1:]

    if len(user['maildrop']) > 1:
        result_dict['mail-forward'] = user['maildrop'][1:]

    if 'mailuserquota' in user:
        userquota = user['mailuserquota'][0]

        if isinstance(userquota, int):
            userquota = str(userquota)

        # Test if userquota is '0' or '0M' ( quota pattern is ^(\d+[bkMGT])|0$ )
        is_limited = not re.match('0[bkMGT]?', userquota)
        storage_use = '?'

        if service_status("dovecot")["status"] != "running":
            logger.warning(m18n.n('mailbox_used_space_dovecot_down'))
        elif not user_permission_list(app="mail", permission="main", username=username)['permissions']:
            logger.warning(m18n.n('mailbox_disabled', user=username))
        else:
            cmd = 'doveadm -f flow quota get -u %s' % user['uid'][0]
            cmd_result = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                                 shell=True)
            # Exemple of return value for cmd:
            # """Quota name=User quota Type=STORAGE Value=0 Limit=- %=0
            # Quota name=User quota Type=MESSAGE Value=0 Limit=- %=0"""
            has_value = re.search(r'Value=(\d+)', cmd_result)

            if has_value:
                storage_use = int(has_value.group(1))
                storage_use = _convertSize(storage_use)

                if is_limited:
                    has_percent = re.search(r'%=(\d+)', cmd_result)

                    if has_percent:
                        percentage = int(has_percent.group(1))
                        storage_use += ' (%s%%)' % percentage

        result_dict['mailbox-quota'] = {
            'limit': userquota if is_limited else m18n.n('unlimit'),
            'use': storage_use
        }

    if result:
        return result_dict
    else:
        raise YunohostError('user_info_failed')


#
# Group subcategory
#
def user_group_list(fields=None):
    """
    List users

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for user fetching
        limit -- Maximum number of user fetched
        fields -- fields to fetch

    """
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()
    group_attr = {
        'cn': 'groupname',
        'member': 'members',
        'permission': 'permission'
    }
    attrs = ['cn']
    groups = {}

    if fields:
        keys = group_attr.keys()
        for attr in fields:
            if attr in keys:
                attrs.append(attr)
            else:
                raise YunohostError('field_invalid', attr)
    else:
        attrs = ['cn', 'member']

    result = ldap.search('ou=groups,dc=yunohost,dc=org',
                         '(objectclass=groupOfNamesYnh)',
                         attrs)

    for group in result:
        # The group "admins" should be hidden for the user
        if group_attr['cn'] == "admins":
            continue
        entry = {}
        for attr, values in group.items():
            if values:
                if attr == "member":
                    entry[group_attr[attr]] = []
                    for v in values:
                        entry[group_attr[attr]].append(v.split("=")[1].split(",")[0])
                elif attr == "permission":
                    entry[group_attr[attr]] = {}
                    for v in values:
                        permission = v.split("=")[1].split(",")[0].split(".")[1]
                        pType = v.split("=")[1].split(",")[0].split(".")[0]
                        if permission in entry[group_attr[attr]]:
                            entry[group_attr[attr]][permission].append(pType)
                        else:
                            entry[group_attr[attr]][permission] = [pType]
                else:
                    entry[group_attr[attr]] = values[0]

        groupname = entry[group_attr['cn']]
        groups[groupname] = entry

    return {'groups': groups}


@is_unit_operation([('groupname', 'user')])
def user_group_add(operation_logger, groupname, gid=None, sync_perm=True):
    """
    Create group

    Keyword argument:
        groupname -- Must be unique

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    operation_logger.start()

    ldap = _get_ldap_interface()

    # Validate uniqueness of groupname in LDAP
    conflict = ldap.get_conflict({
        'cn': groupname
    }, base_dn='ou=groups,dc=yunohost,dc=org')
    if conflict:
        raise YunohostError('group_name_already_exist', name=groupname)

    # Validate uniqueness of groupname in system group
    all_existing_groupnames = {x.gr_name for x in grp.getgrall()}
    if groupname in all_existing_groupnames:
        raise YunohostError('system_groupname_exists')

    if not gid:
        # Get random GID
        all_gid = {x.gr_gid for x in grp.getgrall()}

        uid_guid_found = False
        while not uid_guid_found:
            gid = str(random.randint(200, 99999))
            uid_guid_found = gid not in all_gid

    attr_dict = {
        'objectClass': ['top', 'groupOfNamesYnh', 'posixGroup'],
        'cn': groupname,
        'gidNumber': gid,
    }

    if ldap.add('cn=%s,ou=groups' % groupname, attr_dict):
        logger.success(m18n.n('group_created', group=groupname))
        if sync_perm:
            permission_sync_to_user()
        return {'name': groupname}

    raise YunohostError('group_creation_failed', group=groupname)


@is_unit_operation([('groupname', 'user')])
def user_group_delete(operation_logger, groupname, force=False, sync_perm=True):
    """
    Delete user

    Keyword argument:
        groupname -- Groupname to delete

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    forbidden_groups = ["all_users", "admins"] + user_list(fields=['uid'])['users'].keys()
    if not force and groupname in forbidden_groups:
        raise YunohostError('group_deletion_not_allowed', group=groupname)

    operation_logger.start()
    ldap = _get_ldap_interface()
    if not ldap.remove('cn=%s,ou=groups' % groupname):
        raise YunohostError('group_deletion_failed', group=groupname)

    logger.success(m18n.n('group_deleted', group=groupname))
    if sync_perm:
        permission_sync_to_user()


@is_unit_operation([('groupname', 'user')])
def user_group_update(operation_logger, groupname, add_user=None, remove_user=None, force=False, sync_perm=True):
    """
    Update user informations

    Keyword argument:
        groupname -- Groupname to update
        add_user -- User to add in group
        remove_user -- User to remove in group

    """

    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    if (groupname == 'all_users' or groupname == 'admins') and not force:
        raise YunohostError('edit_group_not_allowed', group=groupname)

    ldap = _get_ldap_interface()

    # Populate group informations
    attrs_to_fetch = ['member']
    result = ldap.search(base='ou=groups,dc=yunohost,dc=org',
                         filter='cn=' + groupname, attrs=attrs_to_fetch)
    if not result:
        raise YunohostError('group_unknown', group=groupname)
    group = result[0]

    new_group_list = {'member': set(), 'memberUid': set()}
    if 'member' in group:
        new_group_list['member'] = set(group['member'])
    else:
        group['member'] = []

    existing_users = user_list(fields=['uid'])['users'].keys()

    if add_user:
        if not isinstance(add_user, list):
            add_user = [add_user]

        for user in add_user:
            if user not in existing_users:
                raise YunohostError('user_unknown', user=user)

        for user in add_user:
            userDN = "uid=" + user + ",ou=users,dc=yunohost,dc=org"
            if userDN in group['member']:
                logger.warning(m18n.n('user_already_in_group', user=user, group=groupname))
            new_group_list['member'].add(userDN)

    if remove_user:
        if not isinstance(remove_user, list):
            remove_user = [remove_user]

        for user in remove_user:
            if user == groupname:
                raise YunohostError('remove_user_of_group_not_allowed', user=user, group=groupname)

        for user in remove_user:
            userDN = "uid=" + user + ",ou=users,dc=yunohost,dc=org"
            if 'member' in group and userDN in group['member']:
                new_group_list['member'].remove(userDN)
            else:
                logger.warning(m18n.n('user_not_in_group', user=user, group=groupname))

    # Sychronise memberUid with member (to keep the posix group structure)
    # In posixgroup the main group of each user is only written in the gid number of the user
    for member in new_group_list['member']:
        member_Uid = member.split("=")[1].split(",")[0]
        # Don't add main user in the group.
        # Note that in the Unix system the main user of the group is linked by the gid in the user attribute.
        # So the main user need to be not in the memberUid list of his own group.
        if member_Uid != groupname:
            new_group_list['memberUid'].add(member_Uid)

    operation_logger.start()

    if new_group_list['member'] != set(group['member']):
        if not ldap.update('cn=%s,ou=groups' % groupname, new_group_list):
            raise YunohostError('group_update_failed', group=groupname)

    logger.success(m18n.n('group_updated', group=groupname))
    if sync_perm:
        permission_sync_to_user()
    return user_group_info(groupname)


def user_group_info(groupname):
    """
    Get user informations

    Keyword argument:
        groupname -- Groupname to get informations

    """

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    group_attrs = [
        'cn', 'member', 'permission'
    ]
    result = ldap.search('ou=groups,dc=yunohost,dc=org', "cn=" + groupname, group_attrs)

    if not result:
        raise YunohostError('group_unknown', group=groupname)

    group = result[0]

    result_dict = {
        'groupname': group['cn'][0],
        'member': None
    }
    if 'member' in group:
        result_dict['member'] = {m.split("=")[1].split(",")[0] for m in group['member']}
    return result_dict


#
# Permission subcategory
#

def user_permission_list(app=None, permission=None, username=None, group=None, sync_perm=True):
    import yunohost.permission
    return yunohost.permission.user_permission_list(app, permission, username, group)


@is_unit_operation([('app', 'user')])
def user_permission_add(operation_logger, app, permission="main", username=None, group=None, sync_perm=True):
    import yunohost.permission
    return yunohost.permission.user_permission_update(operation_logger, app, permission=permission,
                                                      add_username=username, add_group=group,
                                                      del_username=None, del_group=None,
                                                      sync_perm=sync_perm)


@is_unit_operation([('app', 'user')])
def user_permission_remove(operation_logger, app, permission="main", username=None, group=None, sync_perm=True):
    import yunohost.permission
    return yunohost.permission.user_permission_update(operation_logger, app, permission=permission,
                                                      add_username=None, add_group=None,
                                                      del_username=username, del_group=group,
                                                      sync_perm=sync_perm)


@is_unit_operation([('app', 'user')])
def user_permission_clear(operation_logger, app, permission=None, sync_perm=True):
    import yunohost.permission
    return yunohost.permission.user_permission_clear(operation_logger, app, permission,
                                                     sync_perm=sync_perm)


#
# SSH subcategory
#
import yunohost.ssh


def user_ssh_allow(username):
    return yunohost.ssh.user_ssh_allow(username)


def user_ssh_disallow(username):
    return yunohost.ssh.user_ssh_disallow(username)


def user_ssh_list_keys(username):
    return yunohost.ssh.user_ssh_list_keys(username)


def user_ssh_add_key(username, key, comment):
    return yunohost.ssh.user_ssh_add_key(username, key, comment)


def user_ssh_remove_key(username, key):
    return yunohost.ssh.user_ssh_remove_key(username, key)

#
# End SSH subcategory
#


def _convertSize(num, suffix=''):
    for unit in ['K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def _hash_user_password(password):
    """
    This function computes and return a salted hash for the password in input.
    This implementation is inspired from [1].

    The hash follows SHA-512 scheme from Linux/glibc.
    Hence the {CRYPT} and $6$ prefixes
    - {CRYPT} means it relies on the OS' crypt lib
    - $6$ corresponds to SHA-512, the strongest hash available on the system

    The salt is generated using random.SystemRandom(). It is the crypto-secure
    pseudo-random number generator according to the python doc [2] (c.f. the
    red square). It internally relies on /dev/urandom

    The salt is made of 16 characters from the set [./a-zA-Z0-9]. This is the
    max sized allowed for salts according to [3]

    [1] https://www.redpill-linpro.com/techblog/2016/08/16/ldap-password-hash.html
    [2] https://docs.python.org/2/library/random.html
    [3] https://www.safaribooksonline.com/library/view/practical-unix-and/0596003234/ch04s03.html
    """

    char_set = string.ascii_uppercase + string.ascii_lowercase + string.digits + "./"
    salt = ''.join([random.SystemRandom().choice(char_set) for x in range(16)])

    salt = '$6$' + salt + '$'
    return '{CRYPT}' + crypt.crypt(str(password), salt)
