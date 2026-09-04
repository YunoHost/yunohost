#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import json
import time
import logging
from pathlib import Path
from typing import Any, Union

import ldap

from .authenticators.ldap_ynhuser import Authenticator as Auth
from .authenticators.ldap_ynhuser import user_is_allowed_on_domain
from .utils.error import YunohostError, YunohostValidationError
from .utils.file_utils import read_json
from .utils.ldap import LDAPInterface, _get_ldap_interface, _ldap_path_extract
from .utils.password import (
    _hash_user_password,
    assert_password_is_compatible,
    assert_password_is_strong_enough,
)
from moulinette import m18n

logger = logging.getLogger("portal")

PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"
ADMIN_ALIASES = ["root", "admin", "admins", "webmaster", "postmaster", "abuse"]

ANTIBOT_CHALLENGE_VALIDITY = 3600
ANTIBOT_CHALLENGE_MIN_DURATION = 10

USER_PENDING_INVITATIONS = Path("/etc/yunohost/.user_invitations/")
YUNOHOST_SOCKET_API = "/run/yunohost-socket-api.sock"


def _get_user_infos(
    user_attrs: list[str],
) -> tuple[str, str, dict[str, Any]]:
    auth = Auth().get_session_cookie()
    username = auth["user"]
    result = _get_ldap_interface().search("ou=users", f"uid={username}", user_attrs)
    if not result:
        raise YunohostValidationError("user_unknown", user=username)

    return username, auth["host"], result[0]


def _get_portal_settings(
    domain: Union[str, None] = None, username: Union[str, None] = None
) -> dict[str, Any]:
    """
    Returns domain's portal settings which are a combo of domain's portal config panel options
    and the list of apps availables on this domain computed by `app.app_ssowatconf()`.
    """

    if not domain:
        from bottle import request

        domain = request.get_header("host")

    assert domain and "/" not in domain

    settings: dict[str, Any] = {
        "apps": {},
        "public": False,
        "portal_logo": "",
        "portal_theme": "system",
        "portal_tile_theme": "simple",
        "portal_title": "YunoHost",
        "show_other_domains_apps": True,
        "domain": domain,
        "portal_allow_edit_email": False,
        "portal_allow_edit_email_alias": False,
        "portal_allow_edit_email_forward": False,
        "enable_self_registration": False,
        "registration_require_and_verify_email": False,
        "registration_self_registration_notes": None,
        "registration_tos": None
    }

    portal_settings_path = Path(f"{PORTAL_SETTINGS_DIR}/{domain}.json")

    if portal_settings_path.exists():
        settings.update(read_json(str(portal_settings_path)))  # type: ignore[arg-type]
        # Portal may be public (no login required)
        settings["public"] = bool(settings.pop("enable_public_apps_page", False))

    # Make sure the self-registration-related infos are empty if self-registration aint enabled
    if not settings["enable_self_registration"]:
        settings["registration_self_registration_notes"] = None
        settings["registration_tos"] = None
        settings["registration_require_and_verify_email"] = False

    # First clear apps since it may contains private apps
    apps: dict[str, Any] = settings.pop("apps", {})
    settings["apps"] = {}

    if settings["show_other_domains_apps"]:
        # Enhanced apps with all other domain's apps
        import glob

        for path in glob.glob(f"{PORTAL_SETTINGS_DIR}/*.json"):
            if path != str(portal_settings_path):
                path_dict: dict[str, dict] = read_json(path)  # type: ignore[assignment]
                apps.update(path_dict["apps"])

    if username:
        # Add user allowed or public apps
        settings["apps"] = {
            app: infos
            for app, infos in apps.items()
            if username in infos["users"] or infos["public"]
        }
    elif settings["public"]:
        # Add public apps (e.g. with "visitors" in group permission)
        settings["apps"] = {
            app: infos
            for app, infos in apps.items()
            if infos["public"] and not infos.get("hide_from_public")
        }

    # Sort dictionnary according to the "order" info
    settings["apps"] = dict(
        sorted(
            [(app, infos) for app, infos in settings["apps"].items()],
            key=lambda v: (v[1].get("order", 100), v[0]),
        )
    )

    return settings


def portal_public():
    """
    Get public settings
    If the portal is set as public, it will include the list of public apps
    """

    portal_settings = _get_portal_settings()

    try:
        Auth().get_session_cookie()
    except Exception:
        if "portal_user_intro" in portal_settings:
            del portal_settings["portal_user_intro"]

    # Prevent leaking the list of users
    for infos in portal_settings["apps"].values():
        del infos["users"]

    return portal_settings


def portal_me():
    """
    Get user informations
    """
    username, domain, user = _get_user_infos(
        ["cn", "mail", "maildrop", "mailuserquota", "memberOf", "permission"]
    )

    groups = [_ldap_path_extract(g, "cn") for g in user["memberOf"]]
    groups = [g for g in groups if g not in [username, "all_users"]]
    # Get user allowed apps
    apps = _get_portal_settings(domain, username)["apps"]

    # Prevent leaking the list of users
    for infos in apps.values():
        del infos["users"]

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
    mail: Union[str, None] = None,
    mailforward: Union[list[str], None] = None,
    mailalias: Union[list[str], None] = None,
    currentpassword: Union[str, None] = None,
    newpassword: Union[str, None] = None,
):
    from .domain import domain_list

    domains = domain_list()["domains"]
    username, domain, current_user = _get_user_infos(
        ["givenName", "sn", "cn", "mail", "maildrop", "memberOf"]
    )
    new_attr_dict: dict[str, Any] = {}
    portal_settings = _get_portal_settings(domain, username)

    if fullname is not None and fullname != current_user["cn"]:
        fullname = fullname.strip()
        firstname = fullname.split()[0]
        lastname = (
            " ".join(fullname.split()[1:]) or " "
        )  # Stupid hack because LDAP requires the sn/lastname attr, but it accepts a single whitespace...
        new_attr_dict["givenName"] = firstname  # TODO: Validate
        new_attr_dict["sn"] = lastname  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = (
            firstname + " " + lastname
        ).strip()

    new_mails = current_user["mail"]

    if mail is not None:
        is_allowed_to_edit_main_email = portal_settings["portal_allow_edit_email"]
        if not is_allowed_to_edit_main_email:
            raise YunohostValidationError("mail_edit_operation_unauthorized")

        if mail not in new_mails:
            local_part, domain = mail.split("@")
            if local_part in ADMIN_ALIASES:
                raise YunohostValidationError("mail_unavailable")

            try:
                _get_ldap_interface().validate_uniqueness({"mail": mail})
            except YunohostError:
                raise YunohostValidationError("mail_already_exists", mail=mail)

            if domain not in domains or not user_is_allowed_on_domain(username, domain):
                raise YunohostValidationError("mail_alias_unauthorized", domain=domain)
            new_mails[0] = mail
        else:
            # email already exist in the list we just move it on the first place
            new_mails.remove(mail)
            new_mails = [mail] + new_mails[1:]

        new_attr_dict["mail"] = new_mails

    if mailalias is not None:
        is_allowed_to_edit_mail_alias = portal_settings["portal_allow_edit_email_alias"]
        if not is_allowed_to_edit_mail_alias:
            raise YunohostValidationError("mail_edit_operation_unauthorized")

        mailalias = [mail.strip() for mail in mailalias if mail and mail.strip()]
        # keep first current mail unaltered
        mails = [new_mails[0]]

        for index, mail in enumerate(mailalias):
            if mail in new_mails:
                if mail != new_mails[0] and mail not in mails:
                    mails.append(mail)
                continue  # already in mails, skip validation

            local_part, domain = mail.split("@")
            if local_part in ADMIN_ALIASES:
                raise YunohostValidationError(
                    "mail_unavailable", path=f"mailalias[{index}]"
                )

            try:
                _get_ldap_interface().validate_uniqueness({"mail": mail})
            except YunohostError:
                raise YunohostValidationError(
                    "mail_already_exists", mail=mail, path=f"mailalias[{index}]"
                )

            if domain not in domains or not user_is_allowed_on_domain(username, domain):
                raise YunohostValidationError("mail_alias_unauthorized", domain=domain)

            mails.append(mail)

        new_attr_dict["mail"] = mails

    if mailforward is not None:
        is_allowed_to_edit_mail_forward = portal_settings[
            "portal_allow_edit_email_forward"
        ]
        if not is_allowed_to_edit_mail_forward:
            raise YunohostValidationError("mail_edit_operation_unauthorized")

        new_attr_dict["maildrop"] = [current_user["maildrop"][0]] + [
            mail.strip()
            for mail in mailforward
            if mail and mail.strip() and mail != current_user["maildrop"][0]
        ]

    if newpassword:
        # Ensure compatibility and sufficiently complex password
        try:
            assert_password_is_compatible(newpassword)
            is_admin = (
                "cn=admins,ou=groups,dc=yunohost,dc=org" in current_user["memberOf"]
            )
            assert_password_is_strong_enough(
                "admin" if is_admin else "user", newpassword
            )
        except YunohostValidationError as e:
            raise YunohostValidationError(e.key, path="newpassword")

        new_attr_dict["userPassword"] = _hash_user_password(newpassword)

    # Check that current password is valid
    # To be able to edit the user info, an authenticated ldap session is needed
    if newpassword:
        # When setting the password, check the user provided the valid current password
        try:
            ldap_interface = LDAPInterface(username, currentpassword)
        except ldap.INVALID_CREDENTIALS:
            raise YunohostValidationError("invalid_password", path="currentpassword")
    else:
        # Otherwise we use the encrypted password stored in the cookie
        ldap_interface = LDAPInterface(
            username, Auth().get_session_cookie(decrypt_pwd=True)["pwd"]
        )

    try:
        ldap_interface.update(f"uid={username},ou=users", new_attr_dict)
    except Exception as e:
        raise YunohostError("user_update_failed", user=username, error=e)
    finally:
        del ldap_interface

    if "userPassword" in new_attr_dict:
        Auth.invalidate_all_sessions_for_user(username)

    # FIXME: Here we could want to trigger "post_user_update" hook but hooks has to
    # be run as root
    if all(field is not None for field in (fullname, mailalias, mailforward)):
        return {
            "fullname": new_attr_dict["cn"],
            "mail": new_attr_dict["mail"][0],
            "mailalias": new_attr_dict["mail"][1:],
            "mailforward": new_attr_dict["maildrop"][1:],
        }
    else:
        return {}


def portal_invitation_get(token):

    from stat import filemode

    try:
        Auth().get_session_cookie()
    except Exception:
        pass
    else:
        raise YunohostValidationError("You cannot register a new account while already logged-in. Please log out first.", raw_msg=True)

    from bottle import request
    domain = request.get_header("host")
    assert domain and "/" not in domain

    _assert_token_is_valid(token)

    # Assert the permissions are right, which otherwise would be an indication that it can't be trusted
    if not (USER_PENDING_INVITATIONS.owner(), USER_PENDING_INVITATIONS.group(), filemode(USER_PENDING_INVITATIONS.stat().st_mode)) == ("root", "ynh-portal", "drwx--x---"):
        raise YunohostError(f"Uhoh, permissions on folder {USER_PENDING_INVITATIONS} are not right?", raw_msg=True)

    # Assert the permissions are right, which otherwise would be an indication that it can't be trusted
    invite_file = USER_PENDING_INVITATIONS / f"{token}.json"
    if not (invite_file.owner(), invite_file.group(), filemode(invite_file.stat().st_mode)) == ("root", "ynh-portal", "-r--r-----"):
        raise YunohostError(f"Uhoh, permissions on file {invite_file} are not right?", raw_msg=True)

    infos = read_json(str(invite_file))
    if infos["expires"] < time.time() or infos["domain"] != domain:
        raise YunohostValidationError("user_invitation_expired_or_doesnt_exist")

    tos = None
    custom_notes = None

    portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"
    if portal_settings_path.exists():
        portal_settings = read_json(str(portal_settings_path))
        tos = (portal_settings.get("registration_tos") or "").strip() or None
        custom_notes = (portal_settings.get("registration_invite_notes") or "").strip() or None

    return {
        "username": infos["username"],
        "domain": infos["domain"],
        # "expires"
        # "groups"
        "external_email": infos["external_email"],
        # "mailbox_quota"
        "tos": tos,
        "custom_notes": custom_notes
    }


def _assert_token_is_valid(token: str) -> None:

    if not (isinstance(token, str) and token.isalnum() and len(token) == 64):
        raise YunohostValidationError("user_invitation_token_is_invalid")

    invite_file = USER_PENDING_INVITATIONS / f"{token}.json"
    # See this quick study https://github.com/YunoHost/yunohost/pull/2309/changes#r3436493337
    # on how .exists() can be considered safe against timing attacks
    if not invite_file.exists():
        raise YunohostValidationError("user_invitation_expired_or_doesnt_exist")


def _call_socket_api(action: str, args: dict[str, Any]) -> None:

    import socket

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:

        sock.connect(YUNOHOST_SOCKET_API)

        payload = json.dumps({"action": action, "args": args, "locale": m18n.locale}).encode()
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    # the standard output is likely to contain INFO / SUCCESS message ...
    # ... for now, only parse the last line which is expected to be a json
    raw_json = response.decode().strip().split("\n")[-1]
    ret = json.loads(raw_json)
    if ret["error"]:
        if ret["code"] == 400:
            raise YunohostValidationError(ret["error"], raw_msg=True)
        else:
            raise YunohostError(f"Failed to {action}: {ret['error']}", raw_msg=True)


def portal_invitation_consume(token, username, fullname, password, external_email=None, accept_tos=False) -> None:

    # Avoid to flood socket API and block webadmin (with invalid token)
    _assert_token_is_valid(token)

    _call_socket_api("user_invitation_consume", {
        "invitation_token": token,
        "username": username,
        "fullname": fullname,
        "password": password,
        "external_email": external_email,
        "accept_tos": accept_tos,
    })


# FIXME : this is probably not a proper global state shared between all the gevent/bottle threads
# Though for now it looks like we have a single thread anyway so it may be OK ?
CHALLENGES: dict[str, tuple[int, int, str]] = dict()


def _generate_antibot_challenge() -> tuple[str, str, str]:

    from secrets import randbelow, choice
    from .utils.misc import random_ascii
    from hashlib import sha256

    token = random_ascii(64)

    CALCULATIONS = {
        "×": lambda a, b: a * b,
        "+": lambda a, b: a + b,
        "-": lambda a, b: a - b,
    }

    x = randbelow(10)
    y = randbelow(10)
    operator = choice(list(CALCULATIONS.keys()))

    # avoid negative results for subtraction
    if y > x and operator == "-":
        x, y = y, x

    answer = CALCULATIONS[operator](x, y)

    # Create a Proof of Work challenge
    # Force bots to bruteforce 10 hashes
    pow_answers = [str(randbelow(100000)) for i in range(10)]
    def createHash(value: str):
        m = sha256()
        m.update(value.encode())
        return m.hexdigest()
    pow_challenges = [createHash(token + pow_answer)
                      for pow_answer in pow_answers]
    pow_challenge = '|'.join(pow_challenges)

    generated_time = int(time.time())
    calculation = f"{x} {operator} {y}"
    CHALLENGES[token] = (generated_time, answer, '|'.join(pow_answers))
    _cleanup_expired_antibot_challenges()

    return token, calculation, pow_challenge


def _cleanup_expired_antibot_challenges() -> None:

    # Also add some sort of limit to prevent an attacker from filling up the RAM by requesting challenges idk
    if len(CHALLENGES) > 10000:
        all_tokens = list(CHALLENGES.keys())
        tokens_to_get_rid_of = all_tokens[:-10000]
        for token in tokens_to_get_rid_of:
            del CHALLENGES[token]

    tokens_to_get_rid_of = []
    for token, infos in CHALLENGES.items():
        if time.time() > infos[0] + ANTIBOT_CHALLENGE_VALIDITY:
            tokens_to_get_rid_of.append(token)
    for token in tokens_to_get_rid_of:
        del CHALLENGES[token]


def _verify_antibot_challenge(token: str, answer: str, pow_answers: str) -> None:

    _cleanup_expired_antibot_challenges()

    generated_time, expected_answer, pow_expected_answers = CHALLENGES.pop(token, (0, None, None))
    if expected_answer is None:
        raise YunohostValidationError("antibot_challenge_doesnt_exist_or_expired")

    if not isinstance(answer, str) or not answer.strip().isdigit() or int(answer.strip()) != expected_answer:
        raise YunohostValidationError("antibot_challenge_wrong_answer")

    if not isinstance(pow_answers, str) or pow_answers != pow_expected_answers:
        raise YunohostValidationError("antibot_challenge_no_proof_of_work")

    if int(time.time()) < generated_time + ANTIBOT_CHALLENGE_MIN_DURATION:
        raise YunohostValidationError("antibot_challenge_too_quick")


def _assert_registration_enabled_for_domain(domain: str) -> None:

    portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"

    if not portal_settings_path.exists():
        raise YunohostValidationError("Self-registration is not enabled for this domain.", raw_msg=True)

    domain_settings: dict[str, Any] = read_json(portal_settings_path)   # type: ignore[assignment]
    if not domain_settings.get("enable_self_registration"):
        raise YunohostValidationError("Self-registration is not enabled for this domain.", raw_msg=True)


def portal_registration_challenge() -> dict[str, str]:

    from bottle import request
    domain = request.get_header("host")
    _assert_registration_enabled_for_domain(domain)

    token, calculation, pow_challenge = _generate_antibot_challenge()
    return {"token": token, "calculation": calculation, "pow": pow_challenge}


def portal_registration_queue(username, fullname, password, external_email=None, notes=None, accept_tos=False, challenge_token="", challenge_answer="", proof_of_work="") -> None:

    try:
        Auth().get_session_cookie()
    except Exception:
        pass
    else:
        raise YunohostValidationError("You cannot request a new account while already logged-in. Please log out first.", raw_msg=True)

    from bottle import request
    domain = request.get_header("host")
    _assert_registration_enabled_for_domain(domain)
    _verify_antibot_challenge(challenge_token, challenge_answer, proof_of_work)

    _call_socket_api("user_registration_queue", {
        "username": username,
        "fullname": fullname,
        "password": password,
        "external_email": external_email,
        "notes": notes,
        "accept_tos": accept_tos,
        "domain": domain,
        "ip": request.remote_addr,
    })


def portal_registration_confirm(request_id) -> None:

    from bottle import request
    domain = request.get_header("host")
    _assert_registration_enabled_for_domain(domain)

    if not isinstance(request_id, str) or not request_id.isalnum() or len(request_id) != 16:
        raise YunohostValidationError("This is not a valid account request id", raw_msg=True)

    _call_socket_api("user_registration_confirm", {
        "request_id": request_id,
    })
