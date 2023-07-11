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

# from moulinette import Moulinette, m18n
from moulinette.utils.log import getActionLogger

from yunohost.authenticators.ldap_ynhuser import Authenticator as Auth
from yunohost.utils.ldap import LDAPInterface
from yunohost.utils.error import YunohostValidationError

logger = getActionLogger("yunohostportal.user")


def portal_me():
    """
    Get user informations
    """

    auth = Auth().get_session_cookie(decrypt_pwd=True)
    username = auth["user"]

    ldap = LDAPInterface(username, auth["pwd"])

    user_attrs = ["cn", "mail", "uid", "maildrop", "givenName", "sn", "mailuserquota"]

    filter = "uid=" + username
    result = ldap.search("ou=users", filter, user_attrs)

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
        "mail-aliases": [],
        "mail-forward": [],
    }

    if len(user["mail"]) > 1:
        result_dict["mail-aliases"] = user["mail"][1:]

    if len(user["maildrop"]) > 1:
        result_dict["mail-forward"] = user["maildrop"][1:]

    if "mailuserquota" in user:
        pass
        #  FIXME
        #  result_dict["mailbox-quota"] = {
        #      "limit": userquota if is_limited else m18n.n("unlimit"),
        #      "use": storage_use,
        #  }

    # FIXME : should also parse "permission" key in ldap maybe ?
    #          and list of groups / memberof ?
    # (in particular to have e.g. the mail / xmpp / ssh / ... perms)

    return result_dict


def apps(username):
    return {"foo": "bar"}
    #  FIXME: should list available apps and corresponding infos ?
    # from /etc/ssowat/conf.json ?
