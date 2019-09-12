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

SYSTEM_PERMS = ["mail", "xmpp", "stfp"]

#
#
#  The followings are the methods exposed through the "yunohost user permission" interface
#
#


def user_permission_list(short=False, full=False, ignore_system_perms=False):
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

        if ignore_system_perms and name.split(".")[0] in SYSTEM_PERMS:
            continue

        permissions[name] = {}
        permissions[name]["allowed"] = [_ldap_path_extract(p, "cn") for p in infos.get('groupPermission', [])]

        if full:
            permissions[name]["corresponding_users"] = [_ldap_path_extract(p, "uid") for p in infos.get('inheritPermission', [])]
            permissions[name]["urls"] = infos.get("URL", [])

    if short:
        permissions = permissions.keys()

    return {'permissions': permissions}


@is_unit_operation()
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
    operation_logger.related_to.append(('app', permission.split(".")[0]))

    # Compute new allowed group list (and make sure what we're doing make sense)

    new_allowed_groups = copy.copy(current_allowed_groups)

    if add:
        groups_to_add = [add] if not isinstance(add, list) else add
        for group in groups_to_add:
            if group not in all_existing_groups:
                raise YunohostError('group_unknown', group=group)
            if group in current_allowed_groups:
                logger.warning(m18n.n('permission_already_allowed', permission=permission, group=group))
            else:
                operation_logger.related_to.append(('group', group))

        new_allowed_groups += groups_to_add

    if remove:
        groups_to_remove = [remove] if not isinstance(remove, list) else remove
        for group in groups_to_remove:
            if group not in all_existing_groups:
                raise YunohostError('group_unknown', group=group)
            if group not in current_allowed_groups:
                logger.warning(m18n.n('permission_already_disallowed', permission=permission, group=group))
            else:
                operation_logger.related_to.append(('group', group))

        new_allowed_groups = [g for g in new_allowed_groups if g not in groups_to_remove]

    # If we end up with something like allowed groups is ["all_users", "volunteers"]
    # we shall warn the users that they should probably choose between one or the other,
    # because the current situation is probably not what they expect / is temporary ?

    if len(new_allowed_groups) > 1 and "all_users" in new_allowed_groups:
        # FIXME : i18n
        # FIXME : write a better explanation ?
        logger.warning("This permission is currently enabled for all users in addition to other groups. You probably want to either remove the 'all_users' permission or remove the specific groups currently allowed.")

    # Don't update LDAP if we update exactly the same values
    if set(new_allowed_groups) == set(current_allowed_groups):
        # FIXME : i18n
        logger.warning("No change was applied because not relevant modification were found")
        return

    # Commit the new allowed group list

    operation_logger.start()

    try:
        ldap.update('cn=%s,ou=permission' % permission,
                    {'groupPermission': ['cn=' + g + ',ou=groups,dc=yunohost,dc=org' for g in new_allowed_groups]})
    except Exception as e:
        raise YunohostError('permission_update_failed', permission=permission, error=e)

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


@is_unit_operation()
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

    operation_logger.related_to.append(('app', permission.split(".")[0]))
    operation_logger.start()

    default_permission = {'groupPermission': ['cn=all_users,ou=groups,dc=yunohost,dc=org']}
    try:
        ldap.update('cn=%s,ou=permission' % permission, default_permission)
    except Exception as e:
        raise YunohostError('permission_update_failed', permission=permission, error=e)

    logger.debug(m18n.n('permission_updated', permission=permission))

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


@is_unit_operation()
def permission_create(operation_logger, permission, urls=None, sync_perm=True):
    """
    Create a new permission for a specific application

    Keyword argument:
        permission -- Name of the permission (e.g. nextcloud.main or wordpress.editors)
        urls       -- list of urls to specify for the permission
    """

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    # Validate uniqueness of permission in LDAP
    if ldap.get_conflict({'cn': permission},
                         base_dn='ou=permission,dc=yunohost,dc=org'):
        raise YunohostError('permission_already_exist', permission=permission)

    # Get random GID
    all_gid = {x.gr_gid for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        gid = str(random.randint(200, 99999))
        uid_guid_found = gid not in all_gid

    attr_dict = {
        'objectClass': ['top', 'permissionYnh', 'posixGroup'],
        'cn': str(permission),
        'gidNumber': gid,
    }

    # For main permission, we add all users by default
    if permission.endswith(".main"):
        attr_dict['groupPermission'] = ['cn=all_users,ou=groups,dc=yunohost,dc=org']

    if urls:
        attr_dict['URL'] = [_normalize_url(url) for url in urls]

    operation_logger.related_to.append(('app', permission.split(".")[0]))
    operation_logger.start()

    try:
        ldap.add('cn=%s,ou=permission' % permission, attr_dict)
    except Exception as e:
        raise YunohostError('permission_creation_failed', permission=permission, error=e)

    if sync_perm:
        permission_sync_to_user()

    logger.debug(m18n.n('permission_created', permission=permission))
    return user_permission_list(full=True)["permissions"][permission]


@is_unit_operation()
def permission_urls(operation_logger, permission, add=None, remove=None, sync_perm=True):
    """
    Update urls related to a permission for a specific application

    Keyword argument:
        permission -- Name of the permission (e.g. nextcloud.main or wordpress.editors)
        add        -- List of urls to add
        remove     -- List of urls to remove

    """
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    # Fetch existing permission

    existing_permission = user_permission_list(full=True)["permissions"].get(permission, None)
    if not existing_permission:
        raise YunohostError('permission_not_found', permission=permission)

    # Compute new url list

    new_urls = copy.copy(existing_permission["urls"])

    if add:
        urls_to_add = [add] if not isinstance(add, list) else add
        urls_to_add = [_normalize_url(url) for url in urls_to_add]
        new_urls += urls_to_add
    if remove:
        urls_to_remove = [remove] if not isinstance(remove, list) else remove
        urls_to_remove = [_normalize_url(url) for url in urls_to_remove]
        new_urls = [u for u in new_urls if u not in urls_to_remove]

    if set(new_urls) == set(existing_permission["urls"]):
        logger.warning(m18n.n('permission_update_nothing_to_do'))
        return existing_permission

    # Actually commit the change

    operation_logger.related_to.append(('app', permission.split(".")[0]))
    operation_logger.start()

    try:
        ldap.update('cn=%s,ou=permission' % permission, {'URL': new_urls})
    except Exception as e:
        raise YunohostError('permission_update_failed', permission=permission, error=e)

    if sync_perm:
        permission_sync_to_user()

    logger.debug(m18n.n('permission_updated', permission=permission))
    return user_permission_list(full=True)["permissions"][permission]


@is_unit_operation()
def permission_delete(operation_logger, permission, force=False, sync_perm=True):
    """
    Delete a permission

    Keyword argument:
        permission -- Name of the permission (e.g. nextcloud.main or wordpress.editors)
    """

    if permission.endswith("main") and not force:
        raise YunohostError('permission_cannot_remove_main')

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    # Make sure this permission exists

    existing_permission = user_permission_list(full=True)["permissions"].get(permission, None)
    if not existing_permission:
        raise YunohostError('permission_not_found', permission=permission)

    # Actually delete the permission

    operation_logger.related_to.append(('app', permission.split(".")[0]))
    operation_logger.start()

    try:
        ldap.remove('cn=%s,ou=permission' % permission)
    except Exception as e:
        raise YunohostError('permission_deletion_failed', permission=permission, error=e)

    if sync_perm:
        permission_sync_to_user()
    logger.debug(m18n.n('permission_deleted', permission=permission))


def permission_sync_to_user():
    """
    Sychronise the inheritPermission attribut in the permission object from the
    user<->group link and the group<->permission link
    """
    import os
    from yunohost.app import app_ssowatconf
    from yunohost.user import user_group_list
    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    groups = user_group_list(full=True)["groups"]
    permissions = user_permission_list(full=True)["permissions"]

    for permission_name, permission_infos in permissions.items():

        # These are the users currently allowed because there's an 'inheritPermission' object corresponding to it
        currently_allowed_users = set(permission_infos["corresponding_users"])

        # These are the users that should be allowed because they are member of a group that is allowed for this permission ...
        should_be_allowed_users = set([user for group in permission_infos["allowed"] for user in groups[group]["members"]])

        # Note that a LDAP operation with the same value that is in LDAP crash SLAP.
        # So we need to check before each ldap operation that we really change something in LDAP
        if currently_allowed_users == should_be_allowed_users:
            # We're all good, this permission is already correctly synchronized !
            continue

        new_inherited_perms = {'inheritPermission': ["uid=%s,ou=users,dc=yunohost,dc=org" % u for u in should_be_allowed_users],
                               'memberUid': should_be_allowed_users}

        # Commit the change with the new inherited stuff
        try:
            ldap.update('cn=%s,ou=permission' % permission_name, new_inherited_perms)
        except Exception as e:
            raise YunohostError('permission_update_failed', permission=permission_name, error=e)

    logger.debug("The permission database has been resynchronized")

    app_ssowatconf()

    # Reload unscd, otherwise the group ain't propagated to the LDAP database
    os.system('nscd --invalidate=passwd')
    os.system('nscd --invalidate=group')


def _normalize_url(url):
    from yunohost.domain import _normalize_domain_path
    domain = url[:url.index('/')]
    path = url[url.index('/'):]
    domain, path = _normalize_domain_path(domain, path)
    return domain + path
