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
    from yunohost.app import app_ssowatconf
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.utils.ldap import _get_ldap_interface

    # Ensure sufficiently complex password
    assert_password_is_strong_enough("user", password)

    ldap = _get_ldap_interface()

    # Validate uniqueness of username and mail in LDAP
    ldap.validate_uniqueness({
        'uid': username,
        'mail': mail
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
    all_gid = {x.pw_gid for x in pwd.getpwall()}

    uid_guid_found = False
    while not uid_guid_found:
        uid = str(random.randint(200, 99999))
        uid_guid_found = uid not in all_uid and uid not in all_gid

    # Adapt values for LDAP
    fullname = '%s %s' % (firstname, lastname)
    attr_dict = {
        'objectClass': ['mailAccount', 'inetOrgPerson', 'posixAccount'],
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

        # Update SFTP user group
        memberlist = ldap.search(filter='cn=sftpusers', attrs=['memberUid'])[0]['memberUid']
        memberlist.append(username)
        if ldap.update('cn=sftpusers,ou=groups', {'memberUid': memberlist}):
            try:
                # Attempt to create user home folder
                subprocess.check_call(
                    ['su', '-', username, '-c', "''"])
            except subprocess.CalledProcessError:
                if not os.path.isdir('/home/{0}'.format(username)):
                    logger.warning(m18n.n('user_home_creation_failed'),
                                   exc_info=1)
            app_ssowatconf()
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
    from yunohost.app import app_ssowatconf
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface

    operation_logger.start()

    ldap = _get_ldap_interface()
    if ldap.remove('uid=%s,ou=users' % username):
        # Invalidate passwd to take user deletion into account
        subprocess.call(['nscd', '-i', 'passwd'])

        # Update SFTP user group
        memberlist = ldap.search(filter='cn=sftpusers', attrs=['memberUid'])[0]['memberUid']
        try:
            memberlist.remove(username)
        except:
            pass
        if ldap.update('cn=sftpusers,ou=groups', {'memberUid': memberlist}):
            if purge:
                subprocess.call(['rm', '-rf', '/home/{0}'.format(username)])
                subprocess.call(['rm', '-rf', '/var/mail/{0}'.format(username)])
    else:
        raise YunohostError('user_deletion_failed')

    app_ssowatconf()

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

    ldap = _get_ldap_interface()
    attrs_to_fetch = ['givenName', 'sn', 'mail', 'maildrop']
    new_attr_dict = {}
    domains = domain_list()['domains']

    # Populate user informations
    result = ldap.search(base='ou=users,dc=yunohost,dc=org', filter='uid=' + username, attrs=attrs_to_fetch)
    if not result:
        raise YunohostError('user_unknown', user=username)
    user = result[0]

    # Get modifications from arguments
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

    if len(username.split('@')) is 2:
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
# SSH subcategory
#
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
