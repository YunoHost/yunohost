# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2021 YUNOHOST.ORG

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
from typing import Union

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json

from yunohost.authenticators.ldap_ynhuser import Authenticator as Auth
from yunohost.utils.ldap import LDAPInterface
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.password import (
    assert_password_is_compatible,
    assert_password_is_strong_enough,
)
from yunohost.user import _hash_user_password

logger = getActionLogger("portal")

ADMIN_ALIASES = ["root", "admin", "admins", "webmaster", "postmaster", "abuse"]


def _get_user_infos(user_attrs: list[str]):
    auth = Auth().get_session_cookie(decrypt_pwd=True)
    username = auth["user"]
    ldap = LDAPInterface(username, auth["pwd"])
    result = ldap.search("ou=users", f"uid={username}", user_attrs)
    if not result:
        raise YunohostValidationError("user_unknown", user=username)

    return username, result[0], ldap


def portal_me():
    """
    Get user informations
    """

    username, user, ldap = _get_user_infos(
        ["cn", "mail", "maildrop", "mailuserquota", "memberOf", "permission"]
    )

    groups = [
        g.replace("cn=", "").replace(",ou=groups,dc=yunohost,dc=org", "")
        for g in user["memberOf"]
    ]
    groups = [g for g in groups if g not in [username, "all_users"]]

    permissions = [
        p.replace("cn=", "").replace(",ou=permission,dc=yunohost,dc=org", "")
        for p in user["permission"]
    ]

    ssowat_conf = read_json("/etc/ssowat/conf.json")
    apps = {
        perm.replace(".main", ""): {"label": infos["label"], "url": infos["uris"][0]}
        for perm, infos in ssowat_conf["permissions"].items()
        if perm in permissions and infos["show_tile"] and username in infos["users"]
    }

    result_dict = {
        "username": username,
        "fullname": user["cn"][0],
        "mail": user["mail"][0],
        "mailalias": user["mail"][1:],
        "mailforward": user["maildrop"][1:],
        "groups": groups,
        "apps": apps,
    }

    # FIXME / TODO : add mail quota status ?
    #  result_dict["mailbox-quota"] = {
    #      "limit": userquota if is_limited else m18n.n("unlimit"),
    #      "use": storage_use,
    #  }
    # Could use : doveadm -c /dev/null -f flow quota recalc -u johndoe
    # But this requires to be in the mail group ...

    return result_dict


def portal_update(
    fullname: Union[str, None] = None,
    mailforward: Union[list[str], None] = None,
    mailalias: Union[list[str], None] = None,
):
    from yunohost.domain import domain_list

    domains = domain_list()["domains"]
    username, current_user, ldap = _get_user_infos(
        ["givenName", "sn", "cn", "mail", "maildrop", "memberOf"]
    )
    new_attr_dict = {}

    if fullname is not None and fullname != current_user["cn"]:
        fullname = fullname.strip()
        firstname = fullname.split()[0]
        lastname = (
            " ".join(fullname.split()[1:]) or " "
        )  # Stupid hack because LDAP requires the sn/lastname attr, but it accepts a single whitespace...
        new_attr_dict["givenName"] = [firstname]  # TODO: Validate
        new_attr_dict["sn"] = [lastname]  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = [
            (firstname + " " + lastname).strip()
        ]

    if mailalias is not None:
        mailalias = [mail.strip() for mail in mailalias if mail and mail.strip()]
        # keep first current mail unaltered
        mails = [current_user["mail"][0]]

        for index, mail in enumerate(mailalias):
            if mail in current_user["mail"]:
                if mail != current_user["mail"][0]:
                    mails.append(mail)
                continue  # already in mails, skip validation

            local_part, domain = mail.strip().split("@")
            if local_part in ADMIN_ALIASES:
                raise YunohostValidationError(
                    "mail_unavailable", path="mailalias", index=index
                )

            try:
                ldap.validate_uniqueness({"mail": mail})
            except Exception as e:
                raise YunohostError("user_update_failed", user=username, error=e)

            if domain not in domains:
                raise YunohostError("mail_domain_unknown", domain=domain)

            mails.append(mail)

        new_attr_dict["mail"] = mails

    if mailforward is not None:
        new_attr_dict["maildrop"] = [current_user["maildrop"][0]] + [
            mail.strip()
            for mail in mailforward
            if mail and mail.strip() and mail != current_user["maildrop"][0]
        ]

    try:
        ldap.update(f"uid={username},ou=users", new_attr_dict)
    except Exception as e:
        raise YunohostError("user_update_failed", user=username, error=e)

    # FIXME: Here we could want to trigger "post_user_update" hook but hooks has to
    # be run as root

    return {
        "fullname": new_attr_dict["cn"][0],
        "mailalias": new_attr_dict["mail"][1:],
        "mailforward": new_attr_dict["maildrop"][1:],
    }


def portal_update_password(current: str, password: str):
    username, current_user, ldap = _get_user_infos(["userPassword", "memberOf"])
    is_admin = "cn=admins,ou=groups,dc=yunohost,dc=org" in current_user["memberOf"]

    # FIXME: Verify current password ?

    # Ensure compatibility and sufficiently complex password
    assert_password_is_compatible(password)
    assert_password_is_strong_enough("admin" if is_admin else "user", password)

    try:
        ldap.update(
            f"uid={username},ou=users",
            {"userPassword": [_hash_user_password(password)]},
        )
    except Exception as e:
        raise YunohostError("user_update_failed", user=username, error=e)
