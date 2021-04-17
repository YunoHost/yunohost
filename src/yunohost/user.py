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
from moulinette.utils.process import check_output

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.service import service_status
from yunohost.log import is_unit_operation

logger = getActionLogger("yunohost.user")


def user_list(fields=None):

    from yunohost.utils.ldap import _get_ldap_interface

    user_attrs = {
        "uid": "username",
        "cn": "fullname",
        "mail": "mail",
        "maildrop": "mail-forward",
        "homeDirectory": "home_path",
        "mailuserquota": "mailbox-quota",
    }

    attrs = ["uid"]
    users = {}

    if fields:
        keys = user_attrs.keys()
        for attr in fields:
            if attr in keys:
                attrs.append(attr)
            else:
                raise YunohostError("field_invalid", attr)
    else:
        attrs = ["uid", "cn", "mail", "mailuserquota"]

    ldap = _get_ldap_interface()
    result = ldap.search(
        "ou=users,dc=yunohost,dc=org",
        "(&(objectclass=person)(!(uid=root))(!(uid=nobody)))",
        attrs,
    )

    for user in result:
        entry = {}
        for attr, values in user.items():
            if values:
                entry[user_attrs[attr]] = values[0]

        uid = entry[user_attrs["uid"]]
        users[uid] = entry

    return {"users": users}


@is_unit_operation([("username", "user")])
def user_create(
    operation_logger,
    username,
    firstname,
    lastname,
    domain,
    password,
    mailbox_quota="0",
    mail=None,
):

    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.hook import hook_callback
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.utils.ldap import _get_ldap_interface

    # Ensure sufficiently complex password
    assert_password_is_strong_enough("user", password)

    if mail is not None:
        logger.warning(
            "Packagers ! Using --mail in 'yunohost user create' is deprecated ... please use --domain instead."
        )
        domain = mail.split("@")[-1]

    # Validate domain used for email address/xmpp account
    if domain is None:
        if msettings.get("interface") == "api":
            raise YunohostValidationError(
                "Invalid usage, you should specify a domain argument"
            )
        else:
            # On affiche les differents domaines possibles
            msignals.display(m18n.n("domains_available"))
            for domain in domain_list()["domains"]:
                msignals.display("- {}".format(domain))

            maindomain = _get_maindomain()
            domain = msignals.prompt(
                m18n.n("ask_user_domain") + " (default: %s)" % maindomain
            )
            if not domain:
                domain = maindomain

    # Check that the domain exists
    if domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

    mail = username + "@" + domain
    ldap = _get_ldap_interface()

    if username in user_list()["users"]:
        raise YunohostValidationError("user_already_exists", user=username)

    # Validate uniqueness of username and mail in LDAP
    try:
        ldap.validate_uniqueness({"uid": username, "mail": mail, "cn": username})
    except Exception as e:
        raise YunohostValidationError("user_creation_failed", user=username, error=e)

    # Validate uniqueness of username in system users
    all_existing_usernames = {x.pw_name for x in pwd.getpwall()}
    if username in all_existing_usernames:
        raise YunohostValidationError("system_username_exists")

    main_domain = _get_maindomain()
    aliases = [
        "root@" + main_domain,
        "admin@" + main_domain,
        "webmaster@" + main_domain,
        "postmaster@" + main_domain,
        "abuse@" + main_domain,
    ]

    if mail in aliases:
        raise YunohostValidationError("mail_unavailable")

    operation_logger.start()

    # Get random UID/GID
    all_uid = {str(x.pw_uid) for x in pwd.getpwall()}
    all_gid = {str(x.gr_gid) for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        # LXC uid number is limited to 65536 by default
        uid = str(random.randint(1001, 65000))
        uid_guid_found = uid not in all_uid and uid not in all_gid

    # Adapt values for LDAP
    fullname = "%s %s" % (firstname, lastname)

    attr_dict = {
        "objectClass": [
            "mailAccount",
            "inetOrgPerson",
            "posixAccount",
            "userPermissionYnh",
        ],
        "givenName": [firstname],
        "sn": [lastname],
        "displayName": [fullname],
        "cn": [fullname],
        "uid": [username],
        "mail": mail,  # NOTE: this one seems to be already a list
        "maildrop": [username],
        "mailuserquota": [mailbox_quota],
        "userPassword": [_hash_user_password(password)],
        "gidNumber": [uid],
        "uidNumber": [uid],
        "homeDirectory": ["/home/" + username],
        "loginShell": ["/bin/bash"],
    }

    # If it is the first user, add some aliases
    if not ldap.search(base="ou=users,dc=yunohost,dc=org", filter="uid=*"):
        attr_dict["mail"] = [attr_dict["mail"]] + aliases

    try:
        ldap.add("uid=%s,ou=users" % username, attr_dict)
    except Exception as e:
        raise YunohostError("user_creation_failed", user=username, error=e)

    # Invalidate passwd and group to take user and group creation into account
    subprocess.call(["nscd", "-i", "passwd"])
    subprocess.call(["nscd", "-i", "group"])

    try:
        # Attempt to create user home folder
        subprocess.check_call(["mkhomedir_helper", username])
    except subprocess.CalledProcessError:
        if not os.path.isdir("/home/{0}".format(username)):
            logger.warning(m18n.n("user_home_creation_failed"), exc_info=1)

    try:
        subprocess.check_call(
            ["setfacl", "-m", "g:all_users:---", "/home/%s" % username]
        )
    except subprocess.CalledProcessError:
        logger.warning("Failed to protect /home/%s" % username, exc_info=1)

    # Create group for user and add to group 'all_users'
    user_group_create(groupname=username, gid=uid, primary_group=True, sync_perm=False)
    user_group_update(groupname="all_users", add=username, force=True, sync_perm=True)

    # Trigger post_user_create hooks
    env_dict = {
        "YNH_USER_USERNAME": username,
        "YNH_USER_MAIL": mail,
        "YNH_USER_PASSWORD": password,
        "YNH_USER_FIRSTNAME": firstname,
        "YNH_USER_LASTNAME": lastname,
    }

    hook_callback("post_user_create", args=[username, mail], env=env_dict)

    # TODO: Send a welcome mail to user
    logger.success(m18n.n("user_created"))

    return {"fullname": fullname, "username": username, "mail": mail}


@is_unit_operation([("username", "user")])
def user_delete(operation_logger, username, purge=False):
    """
    Delete user

    Keyword argument:
        username -- Username to delete
        purge

    """
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface

    if username not in user_list()["users"]:
        raise YunohostValidationError("user_unknown", user=username)

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
    if username in user_group_list()["groups"].keys():
        user_group_delete(username, force=True, sync_perm=True)

    ldap = _get_ldap_interface()
    try:
        ldap.remove("uid=%s,ou=users" % username)
    except Exception as e:
        raise YunohostError("user_deletion_failed", user=username, error=e)

    # Invalidate passwd to take user deletion into account
    subprocess.call(["nscd", "-i", "passwd"])

    if purge:
        subprocess.call(["rm", "-rf", "/home/{0}".format(username)])
        subprocess.call(["rm", "-rf", "/var/mail/{0}".format(username)])

    hook_callback("post_user_delete", args=[username, purge])

    logger.success(m18n.n("user_deleted"))


@is_unit_operation([("username", "user")], exclude=["change_password"])
def user_update(
    operation_logger,
    username,
    firstname=None,
    lastname=None,
    mail=None,
    change_password=None,
    add_mailforward=None,
    remove_mailforward=None,
    add_mailalias=None,
    remove_mailalias=None,
    mailbox_quota=None,
):
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
    from yunohost.hook import hook_callback

    domains = domain_list()["domains"]

    # Populate user informations
    ldap = _get_ldap_interface()
    attrs_to_fetch = ["givenName", "sn", "mail", "maildrop"]
    result = ldap.search(
        base="ou=users,dc=yunohost,dc=org",
        filter="uid=" + username,
        attrs=attrs_to_fetch,
    )
    if not result:
        raise YunohostValidationError("user_unknown", user=username)
    user = result[0]
    env_dict = {"YNH_USER_USERNAME": username}

    # Get modifications from arguments
    new_attr_dict = {}
    if firstname:
        new_attr_dict["givenName"] = [firstname]  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = [
            firstname + " " + user["sn"][0]
        ]
        env_dict["YNH_USER_FIRSTNAME"] = firstname

    if lastname:
        new_attr_dict["sn"] = [lastname]  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = [
            user["givenName"][0] + " " + lastname
        ]
        env_dict["YNH_USER_LASTNAME"] = lastname

    if lastname and firstname:
        new_attr_dict["cn"] = new_attr_dict["displayName"] = [
            firstname + " " + lastname
        ]

    # change_password is None if user_update is not called to change the password
    if change_password is not None:
        # when in the cli interface if the option to change the password is called
        # without a specified value, change_password will be set to the const 0.
        # In this case we prompt for the new password.
        if msettings.get("interface") == "cli" and not change_password:
            change_password = msignals.prompt(m18n.n("ask_password"), True, True)
        # Ensure sufficiently complex password
        assert_password_is_strong_enough("user", change_password)

        new_attr_dict["userPassword"] = [_hash_user_password(change_password)]
        env_dict["YNH_USER_PASSWORD"] = change_password

    if mail:
        main_domain = _get_maindomain()
        aliases = [
            "root@" + main_domain,
            "admin@" + main_domain,
            "webmaster@" + main_domain,
            "postmaster@" + main_domain,
        ]
        try:
            ldap.validate_uniqueness({"mail": mail})
        except Exception as e:
            raise YunohostValidationError("user_update_failed", user=username, error=e)
        if mail[mail.find("@") + 1 :] not in domains:
            raise YunohostValidationError(
                "mail_domain_unknown", domain=mail[mail.find("@") + 1 :]
            )
        if mail in aliases:
            raise YunohostValidationError("mail_unavailable")

        del user["mail"][0]
        new_attr_dict["mail"] = [mail] + user["mail"]

    if add_mailalias:
        if not isinstance(add_mailalias, list):
            add_mailalias = [add_mailalias]
        for mail in add_mailalias:
            try:
                ldap.validate_uniqueness({"mail": mail})
            except Exception as e:
                raise YunohostValidationError(
                    "user_update_failed", user=username, error=e
                )
            if mail[mail.find("@") + 1 :] not in domains:
                raise YunohostValidationError(
                    "mail_domain_unknown", domain=mail[mail.find("@") + 1 :]
                )
            user["mail"].append(mail)
        new_attr_dict["mail"] = user["mail"]

    if remove_mailalias:
        if not isinstance(remove_mailalias, list):
            remove_mailalias = [remove_mailalias]
        for mail in remove_mailalias:
            if len(user["mail"]) > 1 and mail in user["mail"][1:]:
                user["mail"].remove(mail)
            else:
                raise YunohostValidationError("mail_alias_remove_failed", mail=mail)
        new_attr_dict["mail"] = user["mail"]

    if "mail" in new_attr_dict:
        env_dict["YNH_USER_MAILS"] = ",".join(new_attr_dict["mail"])

    if add_mailforward:
        if not isinstance(add_mailforward, list):
            add_mailforward = [add_mailforward]
        for mail in add_mailforward:
            if mail in user["maildrop"][1:]:
                continue
            user["maildrop"].append(mail)
        new_attr_dict["maildrop"] = user["maildrop"]

    if remove_mailforward:
        if not isinstance(remove_mailforward, list):
            remove_mailforward = [remove_mailforward]
        for mail in remove_mailforward:
            if len(user["maildrop"]) > 1 and mail in user["maildrop"][1:]:
                user["maildrop"].remove(mail)
            else:
                raise YunohostValidationError("mail_forward_remove_failed", mail=mail)
        new_attr_dict["maildrop"] = user["maildrop"]

    if "maildrop" in new_attr_dict:
        env_dict["YNH_USER_MAILFORWARDS"] = ",".join(new_attr_dict["maildrop"])

    if mailbox_quota is not None:
        new_attr_dict["mailuserquota"] = [mailbox_quota]
        env_dict["YNH_USER_MAILQUOTA"] = mailbox_quota

    operation_logger.start()

    try:
        ldap.update("uid=%s,ou=users" % username, new_attr_dict)
    except Exception as e:
        raise YunohostError("user_update_failed", user=username, error=e)

    # Trigger post_user_update hooks
    hook_callback("post_user_update", env=env_dict)

    logger.success(m18n.n("user_updated"))
    app_ssowatconf()
    return user_info(username)


def user_info(username):
    """
    Get user informations

    Keyword argument:
        username -- Username or mail to get informations

    """
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    user_attrs = ["cn", "mail", "uid", "maildrop", "givenName", "sn", "mailuserquota"]

    if len(username.split("@")) == 2:
        filter = "mail=" + username
    else:
        filter = "uid=" + username

    result = ldap.search("ou=users,dc=yunohost,dc=org", filter, user_attrs)

    if result:
        user = result[0]
    else:
        raise YunohostValidationError("user_unknown", user=username)

    result_dict = {
        "username": user["uid"][0],
        "fullname": user["cn"][0],
        "firstname": user["givenName"][0],
        "lastname": user["sn"][0],
        "mail": user["mail"][0],
    }

    if len(user["mail"]) > 1:
        result_dict["mail-aliases"] = user["mail"][1:]

    if len(user["maildrop"]) > 1:
        result_dict["mail-forward"] = user["maildrop"][1:]

    if "mailuserquota" in user:
        userquota = user["mailuserquota"][0]

        if isinstance(userquota, int):
            userquota = str(userquota)

        # Test if userquota is '0' or '0M' ( quota pattern is ^(\d+[bkMGT])|0$ )
        is_limited = not re.match("0[bkMGT]?", userquota)
        storage_use = "?"

        if service_status("dovecot")["status"] != "running":
            logger.warning(m18n.n("mailbox_used_space_dovecot_down"))
        elif username not in user_permission_info("mail.main")["corresponding_users"]:
            logger.warning(m18n.n("mailbox_disabled", user=username))
        else:
            try:
                cmd = "doveadm -f flow quota get -u %s" % user["uid"][0]
                cmd_result = check_output(cmd)
            except Exception as e:
                cmd_result = ""
                logger.warning("Failed to fetch quota info ... : %s " % str(e))

            # Exemple of return value for cmd:
            # """Quota name=User quota Type=STORAGE Value=0 Limit=- %=0
            # Quota name=User quota Type=MESSAGE Value=0 Limit=- %=0"""
            has_value = re.search(r"Value=(\d+)", cmd_result)

            if has_value:
                storage_use = int(has_value.group(1))
                storage_use = _convertSize(storage_use)

                if is_limited:
                    has_percent = re.search(r"%=(\d+)", cmd_result)

                    if has_percent:
                        percentage = int(has_percent.group(1))
                        storage_use += " (%s%%)" % percentage

        result_dict["mailbox-quota"] = {
            "limit": userquota if is_limited else m18n.n("unlimit"),
            "use": storage_use,
        }

    return result_dict


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
    groups_infos = ldap.search(
        "ou=groups,dc=yunohost,dc=org",
        "(objectclass=groupOfNamesYnh)",
        ["cn", "member", "permission"],
    )

    # Parse / organize information to be outputed

    users = user_list()["users"]
    groups = {}
    for infos in groups_infos:

        name = infos["cn"][0]

        if not include_primary_groups and name in users:
            continue

        groups[name] = {}

        groups[name]["members"] = [
            _ldap_path_extract(p, "uid") for p in infos.get("member", [])
        ]

        if full:
            groups[name]["permissions"] = [
                _ldap_path_extract(p, "cn") for p in infos.get("permission", [])
            ]

    if short:
        groups = list(groups.keys())

    return {"groups": groups}


@is_unit_operation([("groupname", "group")])
def user_group_create(
    operation_logger, groupname, gid=None, primary_group=False, sync_perm=True
):
    """
    Create group

    Keyword argument:
        groupname -- Must be unique

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    # Validate uniqueness of groupname in LDAP
    conflict = ldap.get_conflict(
        {"cn": groupname}, base_dn="ou=groups,dc=yunohost,dc=org"
    )
    if conflict:
        raise YunohostValidationError("group_already_exist", group=groupname)

    # Validate uniqueness of groupname in system group
    all_existing_groupnames = {x.gr_name for x in grp.getgrall()}
    if groupname in all_existing_groupnames:
        if primary_group:
            logger.warning(
                m18n.n("group_already_exist_on_system_but_removing_it", group=groupname)
            )
            subprocess.check_call(
                "sed --in-place '/^%s:/d' /etc/group" % groupname, shell=True
            )
        else:
            raise YunohostValidationError(
                "group_already_exist_on_system", group=groupname
            )

    if not gid:
        # Get random GID
        all_gid = {x.gr_gid for x in grp.getgrall()}

        uid_guid_found = False
        while not uid_guid_found:
            gid = str(random.randint(200, 99999))
            uid_guid_found = gid not in all_gid

    attr_dict = {
        "objectClass": ["top", "groupOfNamesYnh", "posixGroup"],
        "cn": groupname,
        "gidNumber": gid,
    }

    # Here we handle the creation of a primary group
    # We want to initialize this group to contain the corresponding user
    # (then we won't be able to add/remove any user in this group)
    if primary_group:
        attr_dict["member"] = ["uid=" + groupname + ",ou=users,dc=yunohost,dc=org"]

    operation_logger.start()
    try:
        ldap.add("cn=%s,ou=groups" % groupname, attr_dict)
    except Exception as e:
        raise YunohostError("group_creation_failed", group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if not primary_group:
        logger.success(m18n.n("group_created", group=groupname))
    else:
        logger.debug(m18n.n("group_created", group=groupname))

    return {"name": groupname}


@is_unit_operation([("groupname", "group")])
def user_group_delete(operation_logger, groupname, force=False, sync_perm=True):
    """
    Delete user

    Keyword argument:
        groupname -- Groupname to delete

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    existing_groups = list(user_group_list()["groups"].keys())
    if groupname not in existing_groups:
        raise YunohostValidationError("group_unknown", group=groupname)

    # Refuse to delete primary groups of a user (e.g. group 'sam' related to user 'sam')
    # without the force option...
    #
    # We also can't delete "all_users" because that's a special group...
    existing_users = list(user_list()["users"].keys())
    undeletable_groups = existing_users + ["all_users", "visitors"]
    if groupname in undeletable_groups and not force:
        raise YunohostValidationError("group_cannot_be_deleted", group=groupname)

    operation_logger.start()
    ldap = _get_ldap_interface()
    try:
        ldap.remove("cn=%s,ou=groups" % groupname)
    except Exception as e:
        raise YunohostError("group_deletion_failed", group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if groupname not in existing_users:
        logger.success(m18n.n("group_deleted", group=groupname))
    else:
        logger.debug(m18n.n("group_deleted", group=groupname))


@is_unit_operation([("groupname", "group")])
def user_group_update(
    operation_logger, groupname, add=None, remove=None, force=False, sync_perm=True
):
    """
    Update user informations

    Keyword argument:
        groupname -- Groupname to update
        add -- User(s) to add in group
        remove -- User(s) to remove in group

    """

    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    existing_users = list(user_list()["users"].keys())

    # Refuse to edit a primary group of a user (e.g. group 'sam' related to user 'sam')
    # Those kind of group should only ever contain the user (e.g. sam) and only this one.
    # We also can't edit "all_users" without the force option because that's a special group...
    if not force:
        if groupname == "all_users":
            raise YunohostValidationError("group_cannot_edit_all_users")
        elif groupname == "visitors":
            raise YunohostValidationError("group_cannot_edit_visitors")
        elif groupname in existing_users:
            raise YunohostValidationError(
                "group_cannot_edit_primary_group", group=groupname
            )

    # We extract the uid for each member of the group to keep a simple flat list of members
    current_group = user_group_info(groupname)["members"]
    new_group = copy.copy(current_group)

    if add:
        users_to_add = [add] if not isinstance(add, list) else add

        for user in users_to_add:
            if user not in existing_users:
                raise YunohostValidationError("user_unknown", user=user)

            if user in current_group:
                logger.warning(
                    m18n.n("group_user_already_in_group", user=user, group=groupname)
                )
            else:
                operation_logger.related_to.append(("user", user))

        new_group += users_to_add

    if remove:
        users_to_remove = [remove] if not isinstance(remove, list) else remove

        for user in users_to_remove:
            if user not in current_group:
                logger.warning(
                    m18n.n("group_user_not_in_group", user=user, group=groupname)
                )
            else:
                operation_logger.related_to.append(("user", user))

        # Remove users_to_remove from new_group
        # Kinda like a new_group -= users_to_remove
        new_group = [u for u in new_group if u not in users_to_remove]

    new_group_dns = [
        "uid=" + user + ",ou=users,dc=yunohost,dc=org" for user in new_group
    ]

    if set(new_group) != set(current_group):
        operation_logger.start()
        ldap = _get_ldap_interface()
        try:
            ldap.update(
                "cn=%s,ou=groups" % groupname,
                {"member": set(new_group_dns), "memberUid": set(new_group)},
            )
        except Exception as e:
            raise YunohostError("group_update_failed", group=groupname, error=e)

    if groupname != "all_users":
        logger.success(m18n.n("group_updated", group=groupname))
    else:
        logger.debug(m18n.n("group_updated", group=groupname))

    if sync_perm:
        permission_sync_to_user()
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
    result = ldap.search(
        "ou=groups,dc=yunohost,dc=org",
        "cn=" + groupname,
        ["cn", "member", "permission"],
    )

    if not result:
        raise YunohostValidationError("group_unknown", group=groupname)

    infos = result[0]

    # Format data

    return {
        "members": [_ldap_path_extract(p, "uid") for p in infos.get("member", [])],
        "permissions": [
            _ldap_path_extract(p, "cn") for p in infos.get("permission", [])
        ],
    }


def user_group_add(groupname, usernames, force=False, sync_perm=True):
    """
    Add user(s) to a group

    Keyword argument:
        groupname -- Groupname to update
        usernames -- User(s) to add in the group

    """
    return user_group_update(groupname, add=usernames, force=force, sync_perm=sync_perm)


def user_group_remove(groupname, usernames, force=False, sync_perm=True):
    """
    Remove user(s) from a group

    Keyword argument:
        groupname -- Groupname to update
        usernames -- User(s) to remove from the group

    """
    return user_group_update(
        groupname, remove=usernames, force=force, sync_perm=sync_perm
    )


#
# Permission subcategory
#


def user_permission_list(short=False, full=False, apps=[]):
    import yunohost.permission

    return yunohost.permission.user_permission_list(
        short, full, absolute_urls=True, apps=apps
    )


def user_permission_update(permission, label=None, show_tile=None, sync_perm=True):
    import yunohost.permission

    return yunohost.permission.user_permission_update(
        permission, label=label, show_tile=show_tile, sync_perm=sync_perm
    )


def user_permission_add(permission, names, protected=None, force=False, sync_perm=True):
    import yunohost.permission

    return yunohost.permission.user_permission_update(
        permission, add=names, protected=protected, force=force, sync_perm=sync_perm
    )


def user_permission_remove(
    permission, names, protected=None, force=False, sync_perm=True
):
    import yunohost.permission

    return yunohost.permission.user_permission_update(
        permission, remove=names, protected=protected, force=force, sync_perm=sync_perm
    )


def user_permission_reset(permission, sync_perm=True):
    import yunohost.permission

    return yunohost.permission.user_permission_reset(permission, sync_perm=sync_perm)


def user_permission_info(permission):
    import yunohost.permission

    return yunohost.permission.user_permission_info(permission)


#
# SSH subcategory
#
import yunohost.ssh


def user_ssh_list_keys(username):
    return yunohost.ssh.user_ssh_list_keys(username)


def user_ssh_add_key(username, key, comment):
    return yunohost.ssh.user_ssh_add_key(username, key, comment)


def user_ssh_remove_key(username, key):
    return yunohost.ssh.user_ssh_remove_key(username, key)


#
# End SSH subcategory
#


def _convertSize(num, suffix=""):
    for unit in ["K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, "Yi", suffix)


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
    salt = "".join([random.SystemRandom().choice(char_set) for x in range(16)])

    salt = "$6$" + salt + "$"
    return "{CRYPT}" + crypt.crypt(str(password), salt)
