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
import crypt
import random
import string
import subprocess
import copy

from moulinette import msignals, msettings, m18n
from moulinette.utils.log import getActionLogger

from yunohost.utils.error import YunohostError
from yunohost.service import service_status
from yunohost.log import is_unit_operation

logger = getActionLogger('yunohost.user')

CSV_FIELDNAMES = [u'username', u'firstname', u'lastname', u'password', u'mailbox-quota', u'mail', u'mail-alias', u'mail-forward', u'groups']
VALIDATORS = {
    'username': r'^[a-z0-9_]+$',
    'firstname': r'^([^\W\d_]{1,30}[ ,.\'-]{0,3})+$', #FIXME Merge first and lastname and support more name (arabish, chinese...)
    'lastname': r'^([^\W\d_]{1,30}[ ,.\'-]{0,3})+$',
    'password': r'^|(.{3,})$',
    'mail': r'^([\w.-]+@([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,}))$',
    'mail-alias': r'^|([\w.-]+@([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,}),?)+$',
    'mail-forward': r'^|([\w\+.-]+@([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,}),?)+$',
    'mailbox-quota': r'^(\d+[bkMGT])|0$',
    'groups': r'^|([a-z0-9_]+(,?[a-z0-9_]+)*)$'
}
FIRST_ALIASES = ['root@', 'admin@', 'webmaster@', 'postmaster@', 'abuse@']
SMTP_TLS_VERSION_SECURED = ['TLSv1.3', 'TLSv1.2']

def user_list(fields=None):

    from yunohost.utils.ldap import _get_ldap_interface

    ldap_attrs = {
        'username': 'uid',
        'password': 'uid',
        'fullname': 'cn',
        'firstname': 'givenName',
        'lastname': 'sn',
        'mail': 'mail',
        'recovery': 'recovery',
        'mail-alias': 'mail',
        'mail-forward': 'maildrop',
        'mailbox-quota': 'mailuserquota',
        'groups': 'memberOf',
        'shell': 'loginShell',
        'home-path': 'homeDirectory'
    }

    def display_default(values, _):
        return values[0] if len(values) == 1 else values

    display = {
        'password': lambda values, user: '',
        'mail': lambda values, user: display_default(values[:1], user),
        'mail-alias': lambda values, _: values[1:],
        'mail-forward': lambda values, user: [forward for forward in values if forward != user['uid'][0]],
        'groups': lambda values, user: [
            group[3:].split(',')[0]
            for group in values
            if not group.startswith('cn=all_users,') and
            not group.startswith('cn=' + user['uid'][0] + ',')],
        'shell': lambda values, _: len(values) > 0 and values[0].strip() == "/bin/false"
    }

    attrs = set(['uid'])
    users = {}

    if not fields:
        fields = ['username', 'fullname', 'mail', 'mailbox-quota', 'recovery', 'shell']

    for field in fields:
        if field in ldap_attrs:
            attrs |= set([ldap_attrs[field]])
        else:
            raise YunohostError('field_invalid', field)

    ldap = _get_ldap_interface()
    result = ldap.search('ou=users,dc=yunohost,dc=org',
                         '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))',
                         attrs)

    for user in result:
        entry = {}
        for field in fields:
            values = []
            if ldap_attrs[field] in user:
                values = user[ldap_attrs[field]]
            entry[field] = display.get(field, display_default)(values, user)

        users[entry['username']] = entry

    return {'users': users}


@is_unit_operation([('username', 'user')])
def user_create(operation_logger, username, domain, password, fullname=None,
                mailbox_quota="0", mail=None, password_recovery=None,
                firstname=None, lastname=None, imported=False):

    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.hook import hook_callback
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.utils.ldap import _get_ldap_interface

    # Ensure sufficiently complex password
    assert_password_is_strong_enough("user", password)

    # Names validation
    if not fullname:
        if firstname and lastname:
            fullname = f"{firstname} {lastname}"
        elif msettings.get('interface') == 'api':
            raise YunohostError('fullname_missing')
        else:
            while not fullname:
                fullname = msignals.prompt(m18n.n('ask_fullname'))
    if not firstname:
        if lastname:
            firstname = fullname.replace(f"${lastname}", "").strip()
        else:
            firstname = fullname.split(" ").pop(0)
    if not lastname:
        lastname = fullname.replace(f"${firstname}", "").strip()

    # Validate domain used for email address/xmpp account
    if domain is None:
        if msettings.get('interface') == 'api':
            raise YunohostError('Invalide usage, specify domain argument')
        else:
            # On affiche les differents domaines possibles
            msignals.display(m18n.n('domains_available'))
            for domain in domain_list()['domains']:
                msignals.display("- {}".format(domain))

            maindomain = _get_maindomain()
            domain = msignals.prompt(m18n.n('ask_user_domain') + ' (default: %s)' % maindomain)
            if not domain:
                domain = maindomain

    # Check that the domain exists
    if domain not in domain_list()['domains']:
        raise YunohostError('domain_name_unknown', domain=domain)

    mail_account = username + '@' + domain

    if mail is None:
        mail = mail_account

    ldap = _get_ldap_interface()

    if username in user_list()["users"]:
        raise YunohostError("user_already_exists", user=username)

    # Validate uniqueness of username and mail in LDAP
    try:
        ldap.validate_uniqueness({
            'uid': username,
            'mail': mail,
            'cn': username
        })
    except Exception as e:
        raise YunohostError('user_creation_failed', user=username, error=e)

    # Validate uniqueness of username in system users
    all_existing_usernames = {x.pw_name for x in pwd.getpwall()}
    if username in all_existing_usernames:
        raise YunohostError('system_username_exists')

    main_domain = _get_maindomain()
    aliases = [alias + main_domain for alias in FIRST_ALIASES]

    if mail_account in aliases:
        raise YunohostError('mail_unavailable')

    if password_recovery and _smtp_is_secured_enough(password_recovery):
        raise YunohostError('user_mailrecovery_unsecured')

    if not imported:
        operation_logger.start()

    # Get random UID/GID
    all_uid = {str(x.pw_uid) for x in pwd.getpwall()}
    all_gid = {str(x.gr_gid) for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        # LXC uid number is limited to 65536 by default
        uid = str(random.randint(1001, 65000))
        uid_guid_found = uid not in all_uid and uid not in all_gid


    attr_dict = {
        'objectClass': ['mailAccount', 'inetOrgPerson', 'posixAccount', 'userPermissionYnh'],
        'givenName': [firstname],
        'sn': [lastname],
        'displayName': [fullname],
        'cn': [fullname],
        'uid': [username],
        'mail': mail,  # NOTE: this one seems to be already a list
        'recovery': [password_recovery] if password_recovery else [],
        'mailalias': [mail_account],
        'maildrop': [username],
        'mailuserquota': [mailbox_quota],
        'userPassword': [_hash_user_password(password)],
        'gidNumber': [uid],
        'uidNumber': [uid],
        'homeDirectory': ['/home/' + username],
        'loginShell': ['/bin/false']
    }

    # If it is the first user, add some aliases
    if not ldap.search(base='ou=users,dc=yunohost,dc=org', filter='uid=*'):
        attr_dict['mailalias'] = [attr_dict['mailalias']] + aliases

    try:
        ldap.add('uid=%s,ou=users' % username, attr_dict)
    except Exception as e:
        raise YunohostError('user_creation_failed', user=username, error=e)

    # Invalidate passwd and group to take user and group creation into account
    subprocess.call(['nscd', '-i', 'passwd'])
    subprocess.call(['nscd', '-i', 'group'])

    try:
        # Attempt to create user home folder
        subprocess.check_call(["mkhomedir_helper", username])
    except subprocess.CalledProcessError:
        home = '/home/{0}'.format(username)
        if not os.path.isdir(home):
            logger.warning(m18n.n('user_home_creation_failed', home=home),
                           exc_info=1)

    # Create group for user and add to group 'all_users'
    user_group_create(groupname=username, gid=uid, primary_group=True, sync_perm=False)
    user_group_update(groupname='all_users', add=username, force=True, sync_perm=True)

    hook_callback('post_user_create',
                  args=[username, mail, password, firstname, lastname])

    # TODO: Send a welcome mail to user
    if not imported:
        logger.success(m18n.n('user_created'))

    return {'fullname': name, 'username': username, 'mail': mail}


@is_unit_operation([('username', 'user')])
def user_delete(operation_logger, username, purge=False, imported=False):
    """
    Delete user

    Keyword argument:
        username -- Username to delete
        purge

    """
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface

    if username not in user_list()["users"]:
        raise YunohostError('user_unknown', user=username)

    if not imported:
        operation_logger.start()

    user_group_update("all_users", remove=username, force=True, sync_perm=False)
    for group, infos in user_group_list()["groups"].items():
        if group == "all_users":
            continue
        # If the user is in this group (and it's not the primary group),
        # remove the member from the group
        if username != group and username in infos["members"]:
            user_group_update(group, remove=username, sync_perm=False)

    # Delete primary group if it exists (why wouldnt it exists ?  because some
    # epic bug happened somewhere else and only a partial removal was
    # performed...)
    if username in user_group_list()['groups'].keys():
        user_group_delete(username, force=True, sync_perm=True)

    ldap = _get_ldap_interface()
    try:
        ldap.remove('uid=%s,ou=users' % username)
    except Exception as e:
        raise YunohostError('user_deletion_failed', user=username, error=e)

    # Invalidate passwd to take user deletion into account
    subprocess.call(['nscd', '-i', 'passwd'])

    if purge:
        subprocess.call(['rm', '-rf', '/home/{0}'.format(username)])
        subprocess.call(['rm', '-rf', '/var/mail/{0}'.format(username)])

    hook_callback('post_user_delete', args=[username, purge])

    if not imported:
        logger.success(m18n.n('user_deleted'))


@is_unit_operation([('username', 'user')], exclude=['change_password'])
def user_update(operation_logger, username, change_password=None,
                fullname=None, firstname=None, lastname=None,
                mail=None, password_recovery=None,
                add_mailalias=None, remove_mailalias=None, mailbox_quota=None,
                add_mailforward=None, remove_mailforward=None,
                imported=False):
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
        new_attr_dict['givenName'] = [firstname]  # TODO: Validate
        new_attr_dict['cn'] = new_attr_dict['displayName'] = [firstname + ' ' + user['sn'][0]]

    if lastname:
        new_attr_dict['sn'] = [lastname]  # TODO: Validate
        new_attr_dict['cn'] = new_attr_dict['displayName'] = [user['givenName'][0] + ' ' + lastname]

    if lastname and firstname:
        new_attr_dict['cn'] = new_attr_dict['displayName'] = [firstname + ' ' + lastname]

    # change_password is None if user_update is not called to change the password
    if change_password is not None:
        # when in the cli interface if the option to change the password is called
        # without a specified value, change_password will be set to the const 0.
        # In this case we prompt for the new password.
        if msettings.get('interface') == 'cli' and not change_password:
            change_password = msignals.prompt(m18n.n("ask_password"), True, True)
        # Ensure sufficiently complex password
        assert_password_is_strong_enough("user", change_password)

        new_attr_dict['userPassword'] = [_hash_user_password(change_password)]

    if mail:
        main_domain = _get_maindomain()
        aliases = [alias + main_domain for alias in FIRST_ALIASES]

        if mail in user['mail']:
            user['mail'].remove(mail)
        else:
            try:
                ldap.validate_uniqueness({'mail': mail})
            except Exception as e:
                raise YunohostError('user_update_failed', user=username, error=e)
        if mail[mail.find('@') + 1:] not in domains:
            raise YunohostError('mail_domain_unknown', domain=mail[mail.find('@') + 1:])
        if mail in aliases:
            raise YunohostError('mail_unavailable')

        new_attr_dict['mail'] = [mail] + user['mail'][1:]

    if password_recovery:
        if _smtp_is_secured_enough(password_recovery):
            raise YunohostError('user_mailrecovery_unsecured')

        user['recovery'] = password_recovery

    if add_mailalias:
        if not isinstance(add_mailalias, list):
            add_mailalias = [add_mailalias]
        for mail in add_mailalias:
            if mail in user['mail']:
                user['mail'].remove(mail)
            else:
                try:
                    ldap.validate_uniqueness({'mail': mail})
                except Exception as e:
                    raise YunohostError('user_update_failed', user=username, error=e)
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
        new_attr_dict['mailuserquota'] = [mailbox_quota]

    if not imported:
        operation_logger.start()

    try:
        ldap.update('uid=%s,ou=users' % username, new_attr_dict)
    except Exception as e:
        raise YunohostError('user_update_failed', user=username, error=e)

    if not imported:
        app_ssowatconf()
        logger.success(m18n.n('user_updated'))
        return user_info(username)


@is_unit_operation([('username', 'user')], exclude=['change_password'])
def user_reset_password(operation_logger, user, token=None,
                        change_password=None)
    """
    Send a password recovery link by email if exists

    Keyword argument:
        user -- username or email address
        token -- token sent by email
        change_password -- New password to set

    """
    from moulinette.utils.text import random_ascii

    # FIXME time attack

    # Send reset password token
    if token is None:
        token = random_ascii(25)
        try:
            info = user_info(user)
        except YunohostError:
            return {} # Important: we return nothing to avoid some attack

        if info['recovery']:
            maindomain = _get_maindomain()
            from_ = "root@%s" % (maindomain)
            to = info['recovery']
            subject = m18n.n('user_password_reset_subject')
            content = m18n.n('user_password_reset_body', login=info['username'],
                             token=token)
            message = """
From: %s
To: %s
Subject: %s

%s
""" % (from_, to, subject, content)
            import smtplib
            smtp = smtplib.SMTP("localhost")
            smtp.sendmail(from_, [to], message)
            smtp.quit()
        return {} # Important: we return nothing to avoid some attack

    # Authenticate with token
    #TODO store token and read token
    if token != registered_token:
        # TODO BAN if too much error like this
        raise YunoHostError("user_password_reset_token_expired")

    # Ensure sufficiently complex password
    assert_password_is_strong_enough("user", change_password)

    # Invalidate token
    # TODO

    # Change password
    # TODO refactor in a function ?
    new_attr_dict = {}
    # when in the cli interface if the option to change the password is called
    # without a specified value, change_password will be set to the const 0.
    # In this case we prompt for the new password.
    if msettings.get('interface') == 'cli' and not change_password:
        change_password = msignals.prompt(m18n.n("ask_password"), True, True)

    new_attr_dict['userPassword'] = [_hash_user_password(change_password)]

    try:
        ldap.update('uid=%s,ou=users' % username, new_attr_dict)
    except Exception as e:
        raise YunohostError('user_password_update_failed', user=username, error=e)

    return {} # Important: we return nothing to avoid some attack


def user_info(username):
    """
    Get user informations

    Keyword argument:
        username -- Username or mail to get informations

    """
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    user_attrs = [
        'cn', 'mail', 'uid', 'maildrop', 'recovery', 'givenName', 'sn', 'mailuserquota'
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
        'mail': user['mail'][0],
        'recovery': False,
        'mail-aliases': [],
        'mail-forward': []
    }

    if len(user['mail']) > 1:
        result_dict['mail-aliases'] = user['mail'][1:]

    if len(user['maildrop']) > 1:
        result_dict['mail-forward'] = user['maildrop'][1:]

    if 'recovery' in user:
        result_dict['recovery'] = user['mailrecovery'][0]

    if 'mailuserquota' in user:
        userquota = user['mailuserquota'][0]

        if isinstance(userquota, int):
            userquota = str(userquota)

        # Test if userquota is '0' or '0M' ( quota pattern is ^(\d+[bkMGT])|0$ )
        is_limited = not re.match('0[bkMGT]?', userquota)
        storage_use = '?'

        if service_status("dovecot")["status"] != "running":
            logger.warning(m18n.n('mailbox_used_space_dovecot_down'))
        elif username not in user_permission_info("mail.main")["corresponding_users"]:
            logger.warning(m18n.n('mailbox_disabled', user=username))
        else:
            try:
                cmd = 'doveadm -f flow quota get -u %s' % user['uid'][0]
                cmd_result = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                                     shell=True)
            except Exception as e:
                cmd_result = ""
                logger.warning("Failed to fetch quota info ... : %s " % str(e))

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

    return result_dict


def user_export():
    """
    Export users into CSV

    Keyword argument:
        csv -- CSV file with columns username;firstname;lastname;password;mailbox-quota;mail;mail-alias;mail-forward;groups

    """
    import csv  # CSV are needed only in this function
    from io import BytesIO
    with BytesIO() as csv_io:
        writer = csv.DictWriter(csv_io, CSV_FIELDNAMES,
                                delimiter=';', quotechar='"')
        writer.writeheader()
        users = user_list(CSV_FIELDNAMES)['users']
        for username, user in users.items():
            user['mail-alias'] = ','.join(user['mail-alias'])
            user['mail-forward'] = ','.join(user['mail-forward'])
            user['groups'] = ','.join(user['groups'])
            writer.writerow(user)

        body = csv_io.getvalue().rstrip()
    if msettings.get('interface') == 'api':
        # We return a raw bottle HTTPresponse (instead of serializable data like
        # list/dict, ...), which is gonna be picked and used directly by moulinette
        from bottle import HTTPResponse
        response = HTTPResponse(body=body,
                        headers={
                            "Content-Disposition": "attachment; filename=users.csv",
                            "Content-Type": "text/csv",
                        })
        return response
    else:
        return body


@is_unit_operation()
def user_import(operation_logger, csvfile, update=False, delete=False):
    """
    Import users from CSV

    Keyword argument:
        csv -- CSV file with columns username;firstname;lastname;password;mailbox_quota;mail;alias;forward;groups

    """

    import csv # CSV are needed only in this function
    from moulinette.utils.text import random_ascii
    from yunohost.permission import permission_sync_to_user
    from yunohost.app import app_ssowatconf
    # Pre-validate data and prepare what should be done
    actions = {
        'created': [],
        'updated': [],
        'deleted': []
    }
    is_well_formatted = True

    def to_list(str_list):
        return str_list.split(',') if str_list else []

    existing_users = user_list()['users']
    past_lines = []
    reader = csv.DictReader(csvfile, delimiter=';', quotechar='"')
    for user in reader:
        # Validation
        try:
            format_errors = [key + ':' + str(user[key])
                            for key, validator in VALIDATORS.items()
                         if user[key] is None or not re.match(validator, user[key])]
        except KeyError, e:
            logger.error(m18n.n('user_import_missing_column',
                                column=str(e)))
            is_well_formatted = False
            break

        if 'username' in user:
            if user['username'] in past_lines:
                format_errors.append('username: %s (duplicated)' % user['username'])
            past_lines.append(user['username'])
        if format_errors:
            logger.error(m18n.n('user_import_bad_line',
                                line=reader.line_num,
                                details=', '.join(format_errors)))
            is_well_formatted = False
            continue

        # Choose what to do with this line and prepare data
        user['groups'] = to_list(user['groups'])
        user['mail-alias'] = to_list(user['mail-alias'])
        user['mail-forward'] = to_list(user['mail-forward'])
        user['domain'] = user['mail'].split('@')[1]
        if user['username'] not in existing_users:
            # Generate password if not exists
            # This could be used when reset password will be merged
            if not user['password']:
                user['password'] = random_ascii(70)
            actions['created'].append(user)
        else:
            if update:
                actions['updated'].append(user)
            del existing_users[user['username']]

    if delete:
        for user in existing_users:
            actions['deleted'].append(user)

    if not is_well_formatted:
        raise YunohostError('user_import_bad_file')

    total = len(actions['created'] + actions['updated'] + actions['deleted'])

    if total == 0:
        logger.info(m18n.n('user_import_nothing_to_do'))
        return

    # Apply creation, update and deletion operation
    result = {
        'created': 0,
        'updated': 0,
        'deleted': 0,
        'errors': 0
    }

    def progress(info=""):
        progress.nb += 1
        width = 20
        bar = int(progress.nb * width / total)
        bar = "[" + "#" * bar + "." * (width - bar) + "]"
        if info:
            bar += " > " + info
        if progress.old == bar:
            return
        progress.old = bar
        logger.info(bar)
    progress.nb = 0
    progress.old = ""

    def on_failure(user, exception):
        result['errors'] += 1
        logger.error(user + ': ' + str(exception))

    def update(user, info=False):
        remove_alias = None
        remove_forward = None
        if info:
            user['mail'] = None if info['mail'] == user['mail'] else user['mail']
            remove_alias = list(set(info['mail-alias']) - set(user['mail-alias']))
            remove_forward = list(set(info['mail-forward']) - set(user['mail-forward']))
            user['mail-alias'] = list(set(user['mail-alias']) - set(info['mail-alias']))
            user['mail-forward'] = list(set(user['mail-forward']) - set(info['mail-forward']))
            for group, infos in user_group_list()["groups"].items():
                if group == "all_users":
                    continue
                # If the user is in this group (and it's not the primary group),
                # remove the member from the group
                if user['username'] != group and user['username'] in infos["members"]:
                    user_group_update(group, remove=user['username'], sync_perm=False, imported=True)

        user_update(user['username'],
                user['firstname'], user['lastname'],
                user['mail'], user['password'],
                mailbox_quota=user['mailbox-quota'],
                mail=user['mail'], add_mailalias=user['mail-alias'],
                remove_mailalias=remove_alias,
                remove_mailforward=remove_forward,
                add_mailforward=user['mail-forward'], imported=True)

        for group in user['groups']:
            user_group_update(group, add=user['username'], sync_perm=False, imported=True)

    users = user_list(CSV_FIELDNAMES)['users']
    operation_logger.start()
    # We do delete and update before to avoid mail uniqueness issues
    for user in actions['deleted']:
        try:
            user_delete(user, purge=True, imported=True)
            result['deleted'] += 1
        except YunohostError as e:
            on_failure(user, e)
        progress("Deletion")

    for user in actions['updated']:
        try:
            update(user, users[user['username']])
            result['updated'] += 1
        except YunohostError as e:
            on_failure(user['username'], e)
        progress("Update")

    for user in actions['created']:
        try:
            user_create(user['username'],
                        user['firstname'], user['lastname'],
                        user['domain'], user['password'],
                        user['mailbox-quota'], imported=True)
            update(user)
            result['created'] += 1
        except YunohostError as e:
            on_failure(user['username'], e)
        progress("Creation")



    permission_sync_to_user()
    app_ssowatconf()

    if result['errors']:
        msg = m18n.n('user_import_partial_failed')
        if result['created'] + result['updated'] + result['deleted'] == 0:
            msg = m18n.n('user_import_failed')
        logger.error(msg)
        operation_logger.error(msg)
    else:
        logger.success(m18n.n('user_import_success'))
        operation_logger.success()
    return result


#
# Group subcategory
#
def user_group_list(short=False, full=False, include_primary_groups=True):
    """
    List users

    Keyword argument:
        short -- Only list the name of the groups without any additional info
        full -- List all the info available for each groups
        include_primary_groups -- Include groups corresponding to users (which should always only contains this user)
                                  This option is set to false by default in the action map because we don't want to have
                                  these displayed when the user runs `yunohost user group list`, but internally we do want
                                  to list them when called from other functions
    """

    # Fetch relevant informations

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract
    ldap = _get_ldap_interface()
    groups_infos = ldap.search('ou=groups,dc=yunohost,dc=org',
                               '(objectclass=groupOfNamesYnh)',
                               ["cn", "member", "permission"])

    # Parse / organize information to be outputed

    users = user_list()["users"]
    groups = {}
    for infos in groups_infos:

        name = infos["cn"][0]

        if not include_primary_groups and name in users:
            continue

        groups[name] = {}

        groups[name]["members"] = [_ldap_path_extract(p, "uid") for p in infos.get("member", [])]

        if full:
            groups[name]["permissions"] = [_ldap_path_extract(p, "cn") for p in infos.get("permission", [])]

    if short:
        groups = groups.keys()

    return {'groups': groups}


@is_unit_operation([('groupname', 'group')])
def user_group_create(operation_logger, groupname, gid=None, primary_group=False, sync_perm=True):
    """
    Create group

    Keyword argument:
        groupname -- Must be unique

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    # Validate uniqueness of groupname in LDAP
    conflict = ldap.get_conflict({
        'cn': groupname
    }, base_dn='ou=groups,dc=yunohost,dc=org')
    if conflict:
        raise YunohostError('group_already_exist', group=groupname)

    # Validate uniqueness of groupname in system group
    all_existing_groupnames = {x.gr_name for x in grp.getgrall()}
    if groupname in all_existing_groupnames:
        if primary_group:
            logger.warning(m18n.n('group_already_exist_on_system_but_removing_it', group=groupname))
            subprocess.check_call("sed --in-place '/^%s:/d' /etc/group" % groupname, shell=True)
        else:
            raise YunohostError('group_already_exist_on_system', group=groupname)

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

    # Here we handle the creation of a primary group
    # We want to initialize this group to contain the corresponding user
    # (then we won't be able to add/remove any user in this group)
    if primary_group:
        attr_dict["member"] = ["uid=" + groupname + ",ou=users,dc=yunohost,dc=org"]

    operation_logger.start()
    try:
        ldap.add('cn=%s,ou=groups' % groupname, attr_dict)
    except Exception as e:
        raise YunohostError('group_creation_failed', group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if not primary_group:
        logger.success(m18n.n('group_created', group=groupname))
    else:
        logger.debug(m18n.n('group_created', group=groupname))

    return {'name': groupname}


@is_unit_operation([('groupname', 'group')])
def user_group_delete(operation_logger, groupname, force=False, sync_perm=True):
    """
    Delete user

    Keyword argument:
        groupname -- Groupname to delete

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    existing_groups = user_group_list()['groups'].keys()
    if groupname not in existing_groups:
        raise YunohostError('group_unknown', group=groupname)

    # Refuse to delete primary groups of a user (e.g. group 'sam' related to user 'sam')
    # without the force option...
    #
    # We also can't delete "all_users" because that's a special group...
    existing_users = user_list()['users'].keys()
    undeletable_groups = existing_users + ["all_users", "visitors"]
    if groupname in undeletable_groups and not force:
        raise YunohostError('group_cannot_be_deleted', group=groupname)

    operation_logger.start()
    ldap = _get_ldap_interface()
    try:
        ldap.remove('cn=%s,ou=groups' % groupname)
    except Exception as e:
        raise YunohostError('group_deletion_failed', group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if groupname not in existing_users:
        logger.success(m18n.n('group_deleted', group=groupname))
    else:
        logger.debug(m18n.n('group_deleted', group=groupname))


@is_unit_operation([('groupname', 'group')])
def user_group_update(operation_logger, groupname, add=None, remove=None, force=False, sync_perm=True, imported=False):
    """
    Update user informations

    Keyword argument:
        groupname -- Groupname to update
        add -- User(s) to add in group
        remove -- User(s) to remove in group

    """

    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    existing_users = user_list()['users'].keys()

    # Refuse to edit a primary group of a user (e.g. group 'sam' related to user 'sam')
    # Those kind of group should only ever contain the user (e.g. sam) and only this one.
    # We also can't edit "all_users" without the force option because that's a special group...
    if not force:
        if groupname == "all_users":
            raise YunohostError('group_cannot_edit_all_users')
        elif groupname == "visitors":
            raise YunohostError('group_cannot_edit_visitors')
        elif groupname in existing_users:
            raise YunohostError('group_cannot_edit_primary_group', group=groupname)

    # We extract the uid for each member of the group to keep a simple flat list of members
    current_group = user_group_info(groupname)["members"]
    new_group = copy.copy(current_group)

    if add:
        users_to_add = [add] if not isinstance(add, list) else add

        for user in users_to_add:
            if user not in existing_users:
                raise YunohostError('user_unknown', user=user)

            if user in current_group:
                logger.warning(m18n.n('group_user_already_in_group', user=user, group=groupname))
            else:
                operation_logger.related_to.append(('user', user))

        new_group += users_to_add

    if remove:
        users_to_remove = [remove] if not isinstance(remove, list) else remove

        for user in users_to_remove:
            if user not in current_group:
                logger.warning(m18n.n('group_user_not_in_group', user=user, group=groupname))
            else:
                operation_logger.related_to.append(('user', user))

        # Remove users_to_remove from new_group
        # Kinda like a new_group -= users_to_remove
        new_group = [u for u in new_group if u not in users_to_remove]

    new_group_dns = ["uid=" + user + ",ou=users,dc=yunohost,dc=org" for user in new_group]

    if set(new_group) != set(current_group):
        if not imported:
            operation_logger.start()
        ldap = _get_ldap_interface()
        try:
            ldap.update('cn=%s,ou=groups' % groupname, {"member": set(new_group_dns), "memberUid": set(new_group)})
        except Exception as e:
            raise YunohostError('group_update_failed', group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if not imported:
        if groupname != "all_users":
            logger.success(m18n.n('group_updated', group=groupname))
        else:
            logger.debug(m18n.n('group_updated', group=groupname))

        return user_group_info(groupname)


def user_group_info(groupname):
    """
    Get user informations

    Keyword argument:
        groupname -- Groupname to get informations

    """

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract
    ldap = _get_ldap_interface()

    # Fetch info for this group
    result = ldap.search('ou=groups,dc=yunohost,dc=org',
                         "cn=" + groupname,
                         ["cn", "member", "permission"])

    if not result:
        raise YunohostError('group_unknown', group=groupname)

    infos = result[0]

    # Format data

    return {
        'members': [_ldap_path_extract(p, "uid") for p in infos.get("member", [])],
        'permissions': [_ldap_path_extract(p, "cn") for p in infos.get("permission", [])]
    }


#
# Permission subcategory
#

def user_permission_list(short=False, full=False):
    import yunohost.permission
    return yunohost.permission.user_permission_list(short, full, absolute_urls=True)


def user_permission_update(permission, add=None, remove=None, label=None, show_tile=None, sync_perm=True):
    import yunohost.permission
    return yunohost.permission.user_permission_update(permission,
                                                      add=add, remove=remove,
                                                      label=label, show_tile=show_tile,
                                                      sync_perm=sync_perm)


def user_permission_reset(permission, sync_perm=True):
    import yunohost.permission
    return yunohost.permission.user_permission_reset(permission,
                                                     sync_perm=sync_perm)


def user_permission_info(permission):
    import yunohost.permission
    return yunohost.permission.user_permission_info(permission)


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


def _smtp_is_secured_enough(mail):
    """
    Test if all SMTP behind a mail are secured enough to send reset password
    email.
    """

    from datetime import datetime, timedelta

    domain = mail.split('@')[1]

    # Cache mechanism to avoid evil user who could want to trigger security
    # test too much
    if domain in _smtp_is_secured_enough.cache:
        start, result = _smtp_is_secured_enough.cache[domain]
        if datetime.now() < start + timedelta(hours=12):
            return result

    result = False
    found, mxs = dig(domain, "MX")

    if not found:
        raise YunohostError("mx_not_found", domain=domain)

    for mx in mxs:
        mx = mx[:-1] if mx[-1:] == "." else mx + "." + domain

        # Check if it's a true SMTP server
        try:
            smtp = SMTP(mx[:-1])
            ehlo = smtp.ehlo()
        except socket.gaierror:
            raise YunohostError("mx_not_found", domain=domain)
        except smtplib.SMTPException:
            raise YunohostError("mx_unable_to_connect")

        # Check if it's support STARTTLS
        if "STARTTLS" not in ehlo:
            break

        try:
            smtp.starttls()
        except smtplib.SMTPException:
            break

        # Check if it uses a decent TLS version
        if smtp.sock not in SMTP_TLS_VERSION_SECURED:
            break

        # Check if it uses a valid and trusted certificate
        # FIXME
    else:
        result = True


    _smtp_is_secured_enough.cache[domain] = (datetime.now() ,result)
    return result
_smtp_is_secured_enough.cache = {}
