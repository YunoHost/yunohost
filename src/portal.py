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

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json

from yunohost.authenticators.ldap_ynhuser import Authenticator as Auth
from yunohost.utils.ldap import LDAPInterface
from yunohost.utils.error import YunohostValidationError

logger = getActionLogger("portal")


def portal_me():
    """
    Get user informations
    """

    auth = Auth().get_session_cookie(decrypt_pwd=True)
    username = auth["user"]

    ldap = LDAPInterface(username, auth["pwd"])

    user_attrs = ["cn", "mail", "maildrop", "mailuserquota", "memberOf", "permission"]

    result = ldap.search("ou=users", f"uid={username}", user_attrs)

    if result:
        user = result[0]
    else:
        raise YunohostValidationError("user_unknown", user=username)

    groups = [g.replace("cn=", "").replace(",ou=groups,dc=yunohost,dc=org", "") for g in user["memberOf"]]
    groups = [g for g in groups if g not in [username, "all_users"]]

    permissions = [p.replace("cn=", "").replace(",ou=permission,dc=yunohost,dc=org", "") for p in user["permission"]]

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
        "mail-aliases": user["mail"][1:],
        "mail-forward": user["maildrop"][1:],
        "groups": groups,
        "apps": apps
    }

    # FIXME / TODO : add mail quota status ?
    #  result_dict["mailbox-quota"] = {
    #      "limit": userquota if is_limited else m18n.n("unlimit"),
    #      "use": storage_use,
    #  }
    # Could use : doveadm -c /dev/null -f flow quota recalc -u johndoe
    # But this requires to be in the mail group ...

    return result_dict
