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

import copy
import grp
import random

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from yunohost.utils.error import YunohostError
from yunohost.user import user_list
from yunohost.log import is_unit_operation

logger = getActionLogger('yunohost.user')

#
#
#  The followings are the methods exposed through the "yunohost user permission" interface
#
#


def user_permission_list(short=False, full=False):
    """
    List permissions and corresponding accesses
    """

    # Fetch relevant informations

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract
    ldap = _get_ldap_interface()
    permissions_infos = ldap.search('ou=permission,dc=yunohost,dc=org',
                                    '(objectclass=permissionYnh)',
                                    ["cn", 'groupPermission', 'inheritPermission', 'URL'])

    # Parse / organize information to be outputed

    permissions = {}
    for infos in permissions_infos:

        name = infos['cn'][0]
        permissions[name] = {}

        permissions[name]["allowed"] = [_ldap_path_extract(p, "cn") for p in infos.get('groupPermission', [])]

        if full:
            permissions[name]["corresponding_users"] = [_ldap_path_extract(p, "uid") for p in infos.get('inheritPermission', [])]
            permissions[name]["urls"] = infos.get("URL", [])

    if short:
        permissions = permissions.keys()

    return {'permissions': permissions}


def user_permission_update(operation_logger, permission, add=None, remove=None, sync_perm=True):
    """
    Allow or Disallow a user or group to a permission for a specific application

    Keyword argument:
        permission     -- Name of the permission (e.g. mail.mail or wordpress.editors)
        add            -- List of groups or usernames to add to this permission
        remove         -- List of groups or usernames to remove from to this permission
    """
    from yunohost.hook import hook_callback
    from yunohost.user import user_group_list
    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract
    ldap = _get_ldap_interface()

    # Fetch currently allowed groups for this permission

    existing_permission = user_permission_list(full=True)["permissions"].get(permission, None)
    if existing_permission is None:
        raise YunohostError('permission_not_found', permission=permission)

    current_allowed_groups = existing_permission["allowed"]
    all_existing_groups = user_group_list()['groups'].keys()

    # Compute new allowed group list (and make sure what we're doing make sense)

    new_allowed_groups = copy.copy(current_allowed_groups)

    if add:
        groups_to_add = [add] if not isinstance(add, list) else add
        for group in groups_to_add:
            if group not in all_existing_groups:
                raise YunohostError('group_unknown', group=group)
            if group in current_allowed_groups:
                logger.warning(m18n.n('group_already_allowed', permission=permission, group=group))

        new_allowed_groups += groups_to_add

    if remove:
        groups_to_remove = [remove] if not isinstance(remove, list) else remove
        for group in groups_to_remove:
            if group not in all_existing_groups:
                raise YunohostError('group_unknown', group=group)
            if group not in current_allowed_groups:
                logger.warning(m18n.n('group_already_disallowed', permission=permission, group=group))

        new_allowed_groups = [g for g in new_allowed_groups if g not in groups_to_remove]

    # If we end up with something like allowed groups is ["all_users", "volunteers"]
    # we shall warn the users that they should probably choose between one or the other,
    # because the current situation is probably not what they expect / is temporary ?

    if len(new_allowed_groups) > 1 and "all_users" in new_allowed_groups:
        # FIXME : i18n
        # FIXME : write a better explanation ?
        logger.warning("This permission is currently enabled for all users in addition to other groups. You probably want to either remove the 'all_users' permission or remove the specific groups currently allowed.")

    # Commit the new allowed group list

    operation_logger.start()

    # Don't update LDAP if we update exactly the same values
    if set(new_allowed_groups) == set(current_allowed_groups):
        # FIXME : i18n
        logger.warning("No change was applied because not relevant modification were found")
    elif ldap.update('cn=%s,ou=permission' % permission,
                     {'groupPermission': ['cn=' + g + ',ou=groups,dc=yunohost,dc=org' for g in new_allowed_groups]}):
        logger.debug(m18n.n('permission_updated', permission=permission))

        # Trigger permission sync if asked

        if sync_perm:
            permission_sync_to_user()

        new_permission = user_permission_list(full=True)["permissions"][permission]

        # Trigger app callbacks

        app = permission.split(".")[0]

        old_allowed_users = set(existing_permission["corresponding_users"])
        new_allowed_users = set(new_permission["corresponding_users"])

        effectively_added_users = new_allowed_users - old_allowed_users
        effectively_removed_users = old_allowed_users - new_allowed_users

        if effectively_added_users:
            hook_callback('post_app_addaccess', args=[app, ','.join(effectively_added_users)])
        if effectively_removed_users:
            hook_callback('post_app_removeaccess', args=[app, ','.join(effectively_removed_users)])

        return new_permission

    else:
        raise YunohostError('permission_update_failed')


def user_permission_reset(operation_logger, permission, sync_perm=True):
    """
    Reset a given permission to just 'all_users'

    Keyword argument:
        permission -- The name of the permission to be reseted
    """
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    # Fetch existing permission

    existing_permission = user_permission_list(full=True)["permissions"].get(permission, None)
    if existing_permission is None:
        raise YunohostError('permission_not_found', permission=permission)

    # Update permission with default (all_users)

    default_permission = {'groupPermission': ['cn=all_users,ou=groups,dc=yunohost,dc=org']}
    if ldap.update('cn=%s,ou=permission' % permission, default_permission):
        logger.debug(m18n.n('permission_updated', permission=permission))
    else:
        raise YunohostError('permission_update_failed')

    if sync_perm:
        permission_sync_to_user()

    new_permission = user_permission_list(full=True)["permissions"][permission]

    # Trigger app callbacks

    app = permission.split(".")[0]

    old_allowed_users = set(existing_permission["corresponding_users"])
    new_allowed_users = set(new_permission["corresponding_users"])

    effectively_added_users = new_allowed_users - old_allowed_users
    effectively_removed_users = old_allowed_users - new_allowed_users

    if effectively_added_users:
        hook_callback('post_app_addaccess', args=[app, ','.join(effectively_added_users)])
    if effectively_removed_users:
        hook_callback('post_app_removeaccess', args=[app, ','.join(effectively_removed_users)])

    return new_permission

#
#
#  The followings methods are *not* directly exposed.
#  They are used to create/delete the permissions (e.g. during app install/remove)
#  and by some app helpers to possibly add additional permissions and tweak the urls
#
#


@is_unit_operation(['permission', 'app'])
def permission_create(operation_logger, app, permission, urls=None, default_allow=True, sync_perm=True):
    """
    Create a new permission for a specific application

    Keyword argument:
        app        -- an application OR sftp, xmpp (metronome), mail
        permission -- name of the permission ("main" by default)
        urls       -- list of urls to specify for the permission

    """
    from yunohost.domain import _normalize_domain_path
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    # Validate uniqueness of permission in LDAP
    permission_name = str(permission + '.' + app)  # str(...) Fix encoding issue
    conflict = ldap.get_conflict({
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
    if ldap.add('cn=%s,ou=permission' % permission_name, attr_dict):
        if sync_perm:
            permission_sync_to_user()
        logger.debug(m18n.n('permission_created', permission=permission, app=app))
        return user_permission_list(app, permission)

    raise YunohostError('permission_creation_failed')


@is_unit_operation(['permission', 'app'])
def permission_urls(operation_logger, app, permission, add_url=None, remove_url=None, sync_perm=True):
    """
    Update urls related to a permission for a specific application

    Keyword argument:
        app            -- an application OR sftp, xmpp (metronome), mail
        permission     -- name of the permission ("main" by default)
        add_url        -- Add a new url for a permission
        remove_url     -- Remove a url for a permission

    """
    from yunohost.domain import _normalize_domain_path
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    permission_name = str(permission + '.' + app)  # str(...) Fix encoding issue

    # Populate permission informations
    result = ldap.search(base='ou=permission,dc=yunohost,dc=org',
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
        return user_permission_list(app, permission)

    operation_logger.start()
    if ldap.update('cn=%s,ou=permission' % permission_name, {'cn': permission_name, 'URL': url}):
        if sync_perm:
            permission_sync_to_user()
        logger.debug(m18n.n('permission_updated', permission=permission, app=app))
        return user_permission_list(app, permission)

    raise YunohostError('premission_update_failed')


@is_unit_operation(['permission', 'app'])
def permission_delete(operation_logger, app, permission, force=False, sync_perm=True):
    """
    Remove a permission for a specific application

    Keyword argument:
        app        -- an application OR sftp, xmpp (metronome), mail
        permission -- name of the permission ("main" by default)

    """

    if permission == "main" and not force:
        raise YunohostError('remove_main_permission_not_allowed')

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    operation_logger.start()
    if not ldap.remove('cn=%s,ou=permission' % str(permission + '.' + app)):
        raise YunohostError('permission_deletion_failed', permission=permission, app=app)
    if sync_perm:
        permission_sync_to_user()
    logger.debug(m18n.n('permission_deleted', permission=permission, app=app))


def permission_sync_to_user(force=False):
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
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    permission_attrs = [
        'cn',
        'member',
    ]
    group_info = ldap.search('ou=groups,dc=yunohost,dc=org',
                             '(objectclass=groupOfNamesYnh)', permission_attrs)
    group_info = {g['cn'][0]: g for g in group_info}

    for per in ldap.search('ou=permission,dc=yunohost,dc=org',
                           '(objectclass=permissionYnh)',
                           ['cn', 'inheritPermission', 'groupPermission', 'memberUid']):

        if 'groupPermission' not in per:
            per['groupPermission'] = []
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
                if not ldap.update('cn=%s,ou=permission' % per['cn'][0], {'groupPermission': []}):
                    raise YunohostError('permission_update_failed_clear')
                if not ldap.update('cn=%s,ou=permission' % per['cn'][0], {'groupPermission': per['groupPermission']}):
                    raise YunohostError('permission_update_failed_populate')
            if per['inheritPermission']:
                if not ldap.update('cn=%s,ou=permission' % per['cn'][0], {'inheritPermission': []}):
                    raise YunohostError('permission_update_failed_clear')
            if user_permission:
                if not ldap.update('cn=%s,ou=permission' % per['cn'][0], inheritPermission):
                    raise YunohostError('permission_update_failed')
        else:
            if not ldap.update('cn=%s,ou=permission' % per['cn'][0], inheritPermission):
                raise YunohostError('permission_update_failed')
    logger.debug(m18n.n('permission_generated'))

    app_ssowatconf()

    # Reload unscd, otherwise the group ain't propagated to the LDAP database
    os.system('nscd --invalidate=passwd')
    os.system('nscd --invalidate=group')
