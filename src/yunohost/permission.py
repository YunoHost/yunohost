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

""" yunohost_permission.py

    Manage permissions
"""

import grp
import random

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from yunohost.utils.error import YunohostError
from yunohost.user import user_list
from yunohost.log import is_unit_operation

logger = getActionLogger('yunohost.user')


def user_permission_list(auth, app=None, permission=None, username=None, group=None):
    """
    List permission for specific application

    Keyword argument:
        app        -- an application OR sftp, xmpp (metronome), mail
        permission -- name of the permission ("main" by default)
        username   -- Username to get informations
        group      -- Groupname to get informations

    """

    permission_attrs = [
        'cn',
        'groupPermission',
        'inheritPermission',
        'URL',
    ]

    # Normally app is alway defined but it should be possible to set it
    if app and not isinstance(app, list):
        app = [app]
    if permission and not isinstance(permission, list):
        permission = [permission]
    if not isinstance(username, list):
        username = [username]
    if not isinstance(group, list):
        group = [group]

    permissions = {}

    result = auth.search('ou=permission,dc=yunohost,dc=org',
                         '(objectclass=permissionYnh)', permission_attrs)

    for res in result:
        permission_name = res['cn'][0].split('.')[0]
        try:
            app_name = res['cn'][0].split('.')[1]
        except:
            logger.warning(m18n.n('permission_name_not_valid', permission=per))
        group_name = []
        if 'groupPermission' in res:
            for g in res['groupPermission']:
                group_name.append(g.split("=")[1].split(",")[0])
        user_name = []
        if 'inheritPermission' in res:
            for u in res['inheritPermission']:
                user_name.append(u.split("=")[1].split(",")[0])

        # Don't show the result if the user defined a specific permission, user or group
        if app and app_name not in app:
            continue
        if permission and permission_name not in permission:
            continue
        if username[0] and not set(username) & set(user_name):
            continue
        if group[0] and not set(group) & set(group_name):
            continue

        if app_name not in permissions:
            permissions[app_name] = {}

        permissions[app_name][permission_name] = {'allowed_users': [], 'allowed_groups': []}
        for g in group_name:
            permissions[app_name][permission_name]['allowed_groups'].append(g)
        for u in user_name:
            permissions[app_name][permission_name]['allowed_users'].append(u)
        if 'URL' in res:
            permissions[app_name][permission_name]['URL'] = []
            for u in res['URL']:
                permissions[app_name][permission_name]['URL'].append(u)

    return {'permissions': permissions}


def user_permission_update(operation_logger, auth, app=[], permission=None, add_username=None, add_group=None, del_username=None, del_group=None, sync_perm=True):
    """
    Allow or Disallow a user or group to a permission for a specific application

    Keyword argument:
        app            -- an application OR sftp, xmpp (metronome), mail
        permission     -- name of the permission ("main" by default)
        add_username   -- Username to allow
        add_group      -- Groupname to allow
        del_username   -- Username to disallow
        del_group      -- Groupname to disallow

    """
    from yunohost.hook import hook_callback
    from yunohost.user import user_group_list

    if permission:
        if not isinstance(permission, list):
            permission = [permission]
    else:
        permission = ["main"]

    if add_group:
        if not isinstance(add_group, list):
            add_group = [add_group]
    else:
        add_group = []

    if add_username:
        if not isinstance(add_username, list):
            add_username = [add_username]
    else:
        add_username = []

    if del_group:
        if not isinstance(del_group, list):
            del_group = [del_group]
    else:
        del_group = []

    if del_username:
        if not isinstance(del_username, list):
            del_username = [del_username]
    else:
        del_username = []

    # Validate that the group exist
    for g in add_group:
        if g not in user_group_list(auth, ['cn'])['groups']:
            raise YunohostError('group_unknown', group=g)
    for u in add_username:
        if u not in user_list(auth, ['uid'])['users']:
            raise YunohostError('user_unknown', user=u)
    for g in del_group:
        if g not in user_group_list(auth, ['cn'])['groups']:
            raise YunohostError('group_unknown', group=g)
    for u in del_username:
        if u not in user_list(auth, ['uid'])['users']:
            raise YunohostError('user_unknown', user=u)

    # Merge user and group (note that we consider all user as a group)
    add_group.extend(add_username)
    del_group.extend(del_username)

    if 'all_users' in add_group or 'all_users' in del_group:
        raise YunohostError('edit_permission_with_group_all_users_not_allowed')

    # Populate permission informations
    permission_attrs = [
        'cn',
        'groupPermission',
    ]
    result = auth.search('ou=permission,dc=yunohost,dc=org',
                         '(objectclass=permissionYnh)', permission_attrs)
    result = {p['cn'][0]: p for p in result}

    new_per_dict = {}

    for a in app:
        for per in permission:
            permission_name = per + '.' + a
            if permission_name not in result:
                raise YunohostError('permission_not_found', permission=per, app=a)
            new_per_dict[permission_name] = set()
            if 'groupPermission' in result[permission_name]:
                new_per_dict[permission_name] = set(result[permission_name]['groupPermission'])

            for g in del_group:
                if 'cn=all_users,ou=groups,dc=yunohost,dc=org' in new_per_dict[permission_name]:
                    raise YunohostError('need_define_permission_before')
                group_name = 'cn=' + g + ',ou=groups,dc=yunohost,dc=org'
                if group_name not in new_per_dict[permission_name]:
                    logger.warning(m18n.n('group_already_disallowed', permission=per, app=a, group=g))
                else:
                    new_per_dict[permission_name].remove(group_name)

            if 'cn=all_users,ou=groups,dc=yunohost,dc=org' in new_per_dict[permission_name]:
                new_per_dict[permission_name].remove('cn=all_users,ou=groups,dc=yunohost,dc=org')
            for g in add_group:
                group_name = 'cn=' + g + ',ou=groups,dc=yunohost,dc=org'
                if group_name in new_per_dict[permission_name]:
                    logger.warning(m18n.n('group_already_allowed', permission=per, app=a, group=g))
                else:
                    new_per_dict[permission_name].add(group_name)

    operation_logger.start()

    for per, val in new_per_dict.items():
        # Don't update LDAP if we update exactly the same values
        if val == set(result[per]['groupPermission'] if 'groupPermission' in result[per] else []):
            continue
        if auth.update('cn=%s,ou=permission' % per, {'groupPermission': val}):
            p = per.split('.')
            logger.success(m18n.n('permission_updated', permission=p[0], app=p[1]))
        else:
            raise YunohostError('permission_update_failed')

    if sync_perm:
        permission_sync_to_user(auth)

    for a in app:
        allowed_users = set()
        disallowed_users = set()
        group_list = user_group_list(auth, ['member'])['groups']

        for g in add_group:
            if 'members' in group_list[g]:
                allowed_users.union(group_list[g]['members'])
        for g in del_group:
            if 'members' in group_list[g]:
                disallowed_users.union(group_list[g]['members'])

        allowed_users = ','.join(allowed_users)
        disallowed_users = ','.join(disallowed_users)
        if add_group:
            hook_callback('post_app_addaccess', args=[app, allowed_users])
        if del_group:
            hook_callback('post_app_removeaccess', args=[app, disallowed_users])

    return user_permission_list(auth, app, permission)


def user_permission_clear(operation_logger, auth, app=[], permission=None, sync_perm=True):
    """
    Reset the permission for a specific application

    Keyword argument:
        app        -- an application OR sftp, xmpp (metronome), mail
        permission -- name of the permission ("main" by default)
        username   -- Username to get informations (all by default)
        group      -- Groupname to get informations (all by default)

    """
    from yunohost.hook import hook_callback

    if permission:
        if not isinstance(permission, list):
            permission = [permission]
    else:
        permission = ["main"]

    default_permission = {'groupPermission': ['cn=all_users,ou=groups,dc=yunohost,dc=org']}

    # Populate permission informations
    permission_attrs = [
        'cn',
        'groupPermission',
    ]
    result = auth.search('ou=permission,dc=yunohost,dc=org',
                         '(objectclass=permissionYnh)', permission_attrs)
    result = {p['cn'][0]: p for p in result}

    for a in app:
        for per in permission:
            permission_name = per + '.' + a
            if permission_name not in result:
                raise YunohostError('permission_not_found', permission=per, app=a)
            if 'groupPermission' in result[permission_name] and 'cn=all_users,ou=groups,dc=yunohost,dc=org' in result[permission_name]['groupPermission']:
                logger.warning(m18n.n('permission_already_clear', permission=per, app=a))
                continue
            if auth.update('cn=%s,ou=permission' % permission_name, default_permission):
                logger.success(m18n.n('permission_updated', permission=per, app=a))
            else:
                raise YunohostError('permission_update_failed')

    permission_sync_to_user(auth)

    for a in app:
        permission_name = 'main.' + a
        result = auth.search('ou=permission,dc=yunohost,dc=org',
                             filter='cn=' + permission_name, attrs=['inheritPermission'])
        if result:
            allowed_users = result[0]['inheritPermission']
            new_user_list = ','.join(allowed_users)
            hook_callback('post_app_removeaccess', args=[app, new_user_list])

    return user_permission_list(auth, app, permission)


@is_unit_operation(['permission', 'app'])
def permission_add(operation_logger, auth, app, permission, urls=None, default_allow=True, sync_perm=True):
    """
    Create a new permission for a specific application

    Keyword argument:
        app        -- an application OR sftp, xmpp (metronome), mail
        permission -- name of the permission ("main" by default)
        urls       -- list of urls to specify for the permission

    """
    from yunohost.domain import _normalize_domain_path

    # Validate uniqueness of permission in LDAP
    permission_name = str(permission + '.' + app)  # str(...) Fix encoding issue
    conflict = auth.get_conflict({
        'cn': permission_name
    }, base_dn='ou=permission,dc=yunohost,dc=org')
    if conflict:
        raise YunohostError('permission_already_exist', permission=permission, app=app)

    # Get random GID
    all_gid = {x.gr_gid for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        gid = str(random.randint(200, 99999))
        uid_guid_found = gid not in all_gid

    attr_dict = {
        'objectClass': ['top', 'permissionYnh', 'posixGroup'],
        'cn': permission_name,
        'gidNumber': gid,
    }
    if default_allow:
        attr_dict['groupPermission'] = 'cn=all_users,ou=groups,dc=yunohost,dc=org'

    if urls:
        attr_dict['URL'] = []
        for url in urls:
            domain = url[:url.index('/')]
            path = url[url.index('/'):]
            domain, path = _normalize_domain_path(domain, path)
            attr_dict['URL'].append(domain + path)

    operation_logger.start()
    if auth.add('cn=%s,ou=permission' % permission_name, attr_dict):
        if sync_perm:
            permission_sync_to_user(auth)
        logger.success(m18n.n('permission_created', permission=permission, app=app))
        return user_permission_list(auth, app, permission)

    raise YunohostError('permission_creation_failed')


@is_unit_operation(['permission', 'app'])
def permission_update(operation_logger, auth, app, permission, add_url=None, remove_url=None, sync_perm=True):
    """
    Update a permission for a specific application

    Keyword argument:
        app            -- an application OR sftp, xmpp (metronome), mail
        permission     -- name of the permission ("main" by default)
        add_url        -- Add a new url for a permission
        remove_url     -- Remove a url for a permission

    """
    from yunohost.domain import _normalize_domain_path

    permission_name = str(permission + '.' + app)  # str(...) Fix encoding issue

    # Populate permission informations
    result = auth.search(base='ou=permission,dc=yunohost,dc=org',
                         filter='cn=' + permission_name, attrs=['URL'])
    if not result:
        raise YunohostError('permission_not_found', permission=permission, app=app)
    permission_obj = result[0]

    if 'URL' not in permission_obj:
        permission_obj['URL'] = []

    url = set(permission_obj['URL'])

    if add_url:
        for u in add_url:
            domain = u[:u.index('/')]
            path = u[u.index('/'):]
            domain, path = _normalize_domain_path(domain, path)
            url.add(domain + path)
    if remove_url:
        for u in remove_url:
            domain = u[:u.index('/')]
            path = u[u.index('/'):]
            domain, path = _normalize_domain_path(domain, path)
            url.discard(domain + path)

    if url == set(permission_obj['URL']):
        logger.warning(m18n.n('permission_update_nothing_to_do'))
        return user_permission_list(auth, app, permission)

    operation_logger.start()
    if auth.update('cn=%s,ou=permission' % permission_name, {'cn': permission_name, 'URL': url}):
        if sync_perm:
            permission_sync_to_user(auth)
        logger.success(m18n.n('permission_updated', permission=permission, app=app))
        return user_permission_list(auth, app, permission)

    raise YunohostError('premission_update_failed')


@is_unit_operation(['permission', 'app'])
def permission_remove(operation_logger, auth, app, permission, force=False, sync_perm=True):
    """
    Remove a permission for a specific application

    Keyword argument:
        app        -- an application OR sftp, xmpp (metronome), mail
        permission -- name of the permission ("main" by default)

    """

    if permission == "main" and not force:
        raise YunohostError('remove_main_permission_not_allowed')

    operation_logger.start()
    if not auth.remove('cn=%s,ou=permission' % str(permission + '.' + app)):
        raise YunohostError('permission_deletion_failed', permission=permission, app=app)
    if sync_perm:
        permission_sync_to_user(auth)
    logger.success(m18n.n('permission_deleted', permission=permission, app=app))


def permission_sync_to_user(auth, force=False):
    """
    Sychronise the inheritPermission attribut in the permission object from the
    user<->group link and the group<->permission link

    Keyword argument:
        force    -- Force to recreate all attributes. Used generally with the
        backup which uses "slapadd" which doesnt' use the memberOf overlay.
        Note that by removing all value and adding a new time, we force the
        overlay to update all attributes
    """
    # Note that a LDAP operation with the same value that is in LDAP crash SLAP.
    # So we need to check before each ldap operation that we really change something in LDAP
    import os
    from yunohost.app import app_ssowatconf

    permission_attrs = [
        'cn',
        'member',
    ]
    group_info = auth.search('ou=groups,dc=yunohost,dc=org',
                             '(objectclass=groupOfNamesYnh)', permission_attrs)
    group_info = {g['cn'][0]: g for g in group_info}

    for per in auth.search('ou=permission,dc=yunohost,dc=org',
                           '(objectclass=permissionYnh)',
                           ['cn', 'inheritPermission', 'groupPermission', 'memberUid']):
        if 'groupPermission' not in per:
            continue
        user_permission = set()
        for group in per['groupPermission']:
            group = group.split("=")[1].split(",")[0]
            if 'member' not in group_info[group]:
                continue
            for user in group_info[group]['member']:
                user_permission.add(user)

        if 'inheritPermission' not in per:
            per['inheritPermission'] = []
        if 'memberUid' not in per:
            per['memberUid'] = []

        uid_val = [v.split("=")[1].split(",")[0] for v in user_permission]
        if user_permission == set(per['inheritPermission']) and set(uid_val) == set(per['memberUid']) and not force:
            continue
        inheritPermission = {'inheritPermission': user_permission, 'memberUid': uid_val}
        if force:
            if per['groupPermission']:
                if not auth.update('cn=%s,ou=permission' % per['cn'][0], {'groupPermission': []}):
                    raise YunohostError('permission_update_failed_clear')
                if not auth.update('cn=%s,ou=permission' % per['cn'][0], {'groupPermission': per['groupPermission']}):
                    raise YunohostError('permission_update_failed_populate')
            if per['inheritPermission']:
                if not auth.update('cn=%s,ou=permission' % per['cn'][0], {'inheritPermission': []}):
                    raise YunohostError('permission_update_failed_clear')
            if user_permission:
                if not auth.update('cn=%s,ou=permission' % per['cn'][0], inheritPermission):
                    raise YunohostError('permission_update_failed')
        else:
            if not auth.update('cn=%s,ou=permission' % per['cn'][0], inheritPermission):
                raise YunohostError('permission_update_failed')
    logger.success(m18n.n('permission_generated'))

    app_ssowatconf(auth)

    # Reload unscd, otherwise the group ain't propagated to the LDAP database
    os.system('nscd --invalidate=passwd')
    os.system('nscd --invalidate=group')
