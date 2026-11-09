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

"""
Two-factor authentication (TOTP, RFC 6238) shared by the webadmin and portal
authenticators.

Storage
-------
Per-user data lives in LDAP, on the user entry (attributes allowed by the
`userPermissionYnh` objectClass, see conf/slapd/permission.ldif):

- twoFactorSecret       : base32 TOTP secret
- twoFactorLastCounter  : last accepted TOTP time-step (anti-replay)
- twoFactorRecoveryCode : sha256 hashes of single-use recovery codes

A dedicated ACL (conf/slapd/config.ldif) restricts these attributes to root
and to the user themself. All reads/writes made on behalf of a user therefore
go through an LDAP connection bound *as that user* (we always have their
password at hand when it's needed), which works both from the root webadmin
API and from the unprivileged portal API.

Policy
------
The global setting `security.twofactor.twofactor_policy` is mirrored into
POLICY_FILE (world-readable) because the portal API does not run as root and
cannot read the settings file.

Login protocol
--------------
Moulinette's /login route only lets the authenticator raise an error that ends
up as a 401 with the error message as body. To stay on that route (and thus
remain covered by the existing fail2ban filters), 2FA challenges are returned
as a JSON-encoded error message:

    {"error": "<key>", "message": "<translated text>", ...extra}

and the client sends the extra fields `twofactor_code` (and, during forced
enrollment, `twofactor_setup_token`) alongside `credentials` on the next
/login call.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import struct
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import jwt
from moulinette import m18n

from .error import YunohostError, YunohostValidationError

logger = logging.getLogger("yunohost.utils.twofactor")

POLICY_FILE = Path("/etc/yunohost/twofactor_policy")
POLICIES = ("disabled", "optional", "enforced_admins", "enforced_all")
DEFAULT_POLICY = "optional"

ATTR_SECRET = "twoFactorSecret"
ATTR_COUNTER = "twoFactorLastCounter"
ATTR_RECOVERY = "twoFactorRecoveryCode"
ATTRS = [ATTR_SECRET, ATTR_COUNTER, ATTR_RECOVERY]

TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # accept the previous/next time-step to absorb clock drift

RECOVERY_CODES_COUNT = 10
RECOVERY_CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i

SETUP_TOKEN_VALIDITY = 10 * 60
SETUP_TOKEN_PURPOSE = "twofactor_setup"

ADMIN_GROUP = "cn=admins,ou=groups"


# =============================================================================
# Policy
# =============================================================================


def get_policy() -> str:
    try:
        policy = POLICY_FILE.read_text().strip()
    except FileNotFoundError:
        return DEFAULT_POLICY
    except Exception as e:
        # Fail closed-ish: don't silently disable 2FA if the file is unreadable
        logger.error(f"Unable to read 2FA policy from {POLICY_FILE}: {e}")
        return "enforced_all"

    if policy not in POLICIES:
        logger.error(f"Unknown 2FA policy '{policy}' in {POLICY_FILE}")
        return "enforced_all"
    return policy


def write_policy(policy: str) -> None:
    assert policy in POLICIES
    POLICY_FILE.write_text(policy + "\n")
    POLICY_FILE.chmod(0o644)


def is_enforced(policy: str, is_admin: bool) -> bool:
    return policy == "enforced_all" or (policy == "enforced_admins" and is_admin)


def user_is_admin(username: str) -> bool:
    from .ldap import _get_ldap_interface

    admins = (
        _get_ldap_interface()
        .search(ADMIN_GROUP, attrs=["memberUid"])[0]
        .get("memberUid", [])
    )
    return username in set(admins)


# =============================================================================
# TOTP primitives (RFC 4226 / RFC 6238, SHA1, 6 digits, 30s)
# =============================================================================


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def hotp(secret: str, counter: int) -> str:
    digest = hmac.new(_b32decode(secret), struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def current_counter(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def totp_match(
    secret: str,
    code: str,
    last_counter: int | None = None,
    now: float | None = None,
) -> int | None:
    """
    Return the time-step matching `code`, or None.
    Time-steps <= last_counter are rejected to prevent code replay.
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None

    base = current_counter(now)
    for counter in range(base - TOTP_WINDOW, base + TOTP_WINDOW + 1):
        if last_counter is not None and counter <= last_counter:
            continue
        if hmac.compare_digest(hotp(secret, counter), code):
            return counter
    return None


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


# =============================================================================
# Recovery codes
# =============================================================================


def _normalize_recovery_code(code: str) -> str:
    return "".join(c for c in (code or "").lower() if c.isalnum())


def generate_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_CODES_COUNT):
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(12))
        codes.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")
    return codes


def hash_recovery_code(code: str) -> str:
    # Codes carry ~59 bits of entropy and the hashes are only readable by root
    # and the user themself, so a plain hash is enough here.
    return hashlib.sha256(_normalize_recovery_code(code).encode()).hexdigest()


def _match_recovery_code(code: str, hashes: list[str]) -> str | None:
    if len(_normalize_recovery_code(code)) != 12:
        return None
    candidate = hash_recovery_code(code)
    match = None
    for h in hashes:
        if hmac.compare_digest(h, candidate):
            match = h
    return match


# =============================================================================
# Setup tokens (signed, short-lived, carry the pending secret)
# =============================================================================


def _setup_token_key(signing_key: str) -> str:
    # Derive a dedicated key so that setup tokens and session cookies
    # (signed with the same base secret) can never be confused
    return hmac.new(signing_key.encode(), b"twofactor_setup", "sha256").hexdigest()


def make_setup_token(
    username: str, secret: str, recovery_hashes: list[str], signing_key: str
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "purpose": SETUP_TOKEN_PURPOSE,
            "user": username,
            "secret": secret,
            "recovery": recovery_hashes,
            "iat": now,
            "exp": now + SETUP_TOKEN_VALIDITY,
        },
        _setup_token_key(signing_key),
        algorithm="HS256",
    )


def read_setup_token(token: str, username: str, signing_key: str) -> dict[str, Any]:
    try:
        data = jwt.decode(
            token,
            _setup_token_key(signing_key),
            algorithms=["HS256"],
            options={"require": ["purpose", "user", "secret", "recovery", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise TwoFactorChallenge("twofactor_setup_token_expired")
    except Exception:
        raise TwoFactorChallenge("twofactor_setup_token_invalid")

    if data["purpose"] != SETUP_TOKEN_PURPOSE or data["user"] != username:
        raise TwoFactorChallenge("twofactor_setup_token_invalid")
    return data


def new_setup(username: str, signing_key: str, label: str) -> dict[str, Any]:
    secret = generate_secret()
    recovery_codes = generate_recovery_codes()
    return {
        "secret": secret,
        "uri": provisioning_uri(secret, username, label),
        "recovery_codes": recovery_codes,
        "setup_token": make_setup_token(
            username,
            secret,
            [hash_recovery_code(c) for c in recovery_codes],
            signing_key,
        ),
    }


# =============================================================================
# LDAP storage
# =============================================================================


def _user_rdn(username: str) -> str:
    return f"uid={username},ou=users"


def read_user_data(ldap_interface, username: str) -> dict[str, list[str]]:
    result = ldap_interface.search(_user_rdn(username), attrs=ATTRS)
    if not result:
        raise YunohostError("user_unknown", user=username)
    return result[0]


def is_enrolled(data: dict[str, list[str]]) -> bool:
    return bool(data.get(ATTR_SECRET))


def _last_counter(data: dict[str, list[str]]) -> int | None:
    try:
        return int(data[ATTR_COUNTER][0])
    except (KeyError, IndexError, ValueError):
        return None


def store_enrollment(
    ldap_interface,
    username: str,
    secret: str,
    counter: int,
    recovery_hashes: list[str],
) -> None:
    ldap_interface.update(
        _user_rdn(username),
        {
            ATTR_SECRET: [secret],
            ATTR_COUNTER: [str(counter)],
            ATTR_RECOVERY: set(recovery_hashes),
        },
    )


def clear_enrollment(ldap_interface, username: str) -> None:
    data = read_user_data(ldap_interface, username)
    # Only touch attributes that exist, LDAP refuses to delete missing ones
    to_delete = {attr: [] for attr in ATTRS if data.get(attr)}
    if to_delete:
        ldap_interface.update(_user_rdn(username), to_delete)


def verify_code(ldap_interface, username: str, code: str) -> bool:
    """
    Check a TOTP or recovery code for an enrolled user, and persist the
    side effects (anti-replay counter, consumed recovery code).
    """
    data = read_user_data(ldap_interface, username)
    if not is_enrolled(data):
        return False

    counter = totp_match(data[ATTR_SECRET][0], code, _last_counter(data))
    if counter is not None:
        ldap_interface.update(_user_rdn(username), {ATTR_COUNTER: [str(counter)]})
        return True

    hashes = data.get(ATTR_RECOVERY, [])
    used = _match_recovery_code(code, hashes)
    if used is not None:
        ldap_interface.update(
            _user_rdn(username), {ATTR_RECOVERY: set(hashes) - {used}}
        )
        logger.warning(f"User {username} logged in using a 2FA recovery code")
        return True

    return False


# =============================================================================
# Login-time enforcement
# =============================================================================


class TwoFactorChallenge(YunohostError):
    """
    Raised during /login when a second step is needed. The message is a JSON
    document so that frontends can tell challenges apart from regular errors
    (moulinette only forwards the message string, as a 401).
    """

    http_code = 401

    def __init__(self, key: str, **extra: Any) -> None:
        payload = {"error": key, "message": m18n.n(key), **extra}
        super().__init__(json.dumps(payload), raw_msg=True)
        self.key = key
        self.kwargs = extra


def get_request_param(name: str) -> str | None:
    """Read an extra field sent alongside `credentials` to /login."""
    try:
        from bottle import request

        try:
            body = request.json
        except Exception:
            body = None
        if isinstance(body, dict) and body.get(name):
            return str(body[name])
        value = request.params.get(name)
        return str(value) if value else None
    except Exception:
        # Not in a request context (eg unit tests calling the authenticator)
        return None


def issuer() -> str:
    """Label shown in the user's authenticator app"""
    try:
        from bottle import request

        host = request.get_header("host")
    except Exception:
        host = None
    return f"YunoHost ({host})" if host else "YunoHost"


def check_login(username: str, password: str, is_admin: bool, signing_key: str) -> None:
    """
    To be called by authenticators once the password has been validated.
    Returns if the login may proceed, raises TwoFactorChallenge otherwise.
    """
    from .ldap import LDAPInterface

    policy = get_policy()
    if policy == "disabled":
        return

    ldap_user = LDAPInterface(user=username, password=password)
    data = read_user_data(ldap_user, username)
    code = get_request_param("twofactor_code")

    if is_enrolled(data):
        if not code:
            raise TwoFactorChallenge("twofactor_code_required")
        if not verify_code(ldap_user, username, code):
            raise TwoFactorChallenge("twofactor_code_invalid")
        return

    if not is_enforced(policy, is_admin):
        return

    # Enforced but not enrolled yet: the user must enroll before getting a session
    setup_token = get_request_param("twofactor_setup_token")
    if setup_token and code:
        setup = read_setup_token(setup_token, username, signing_key)
        counter = totp_match(setup["secret"], code)
        if counter is None:
            raise TwoFactorChallenge("twofactor_code_invalid")
        store_enrollment(
            ldap_user, username, setup["secret"], counter, setup["recovery"]
        )
        logger.info(f"User {username} enrolled 2FA during login")
        return

    raise TwoFactorChallenge(
        "twofactor_setup_required", **new_setup(username, signing_key, issuer())
    )


# =============================================================================
# Self-service (portal) helpers
# =============================================================================


def status(data: dict[str, list[str]], is_admin: bool) -> dict[str, Any]:
    policy = get_policy()
    return {
        "policy": policy,
        "enabled": is_enrolled(data),
        "enforced": is_enforced(policy, is_admin),
        "recovery_codes_left": len(data.get(ATTR_RECOVERY, [])),
    }


def self_enable(
    ldap_user, username: str, setup_token: str, code: str, signing_key: str
) -> None:
    if get_policy() == "disabled":
        raise YunohostValidationError("twofactor_disabled_by_admin")
    if is_enrolled(read_user_data(ldap_user, username)):
        raise YunohostValidationError("twofactor_already_enabled")

    try:
        setup = read_setup_token(setup_token, username, signing_key)
    except TwoFactorChallenge as e:
        # Not a login: report it as a regular validation error, not a 401
        raise YunohostValidationError(e.key)
    counter = totp_match(setup["secret"], code)
    if counter is None:
        raise YunohostValidationError("twofactor_code_invalid")
    store_enrollment(ldap_user, username, setup["secret"], counter, setup["recovery"])


def self_disable(ldap_user, username: str, code: str, is_admin: bool) -> None:
    if is_enforced(get_policy(), is_admin):
        raise YunohostValidationError("twofactor_cannot_disable_enforced")
    if not is_enrolled(read_user_data(ldap_user, username)):
        raise YunohostValidationError("twofactor_not_enabled")
    if not verify_code(ldap_user, username, code):
        raise YunohostValidationError("twofactor_code_invalid")
    clear_enrollment(ldap_user, username)


def self_regenerate_recovery_codes(ldap_user, username: str, code: str) -> list[str]:
    if not is_enrolled(read_user_data(ldap_user, username)):
        raise YunohostValidationError("twofactor_not_enabled")
    if not verify_code(ldap_user, username, code):
        raise YunohostValidationError("twofactor_code_invalid")
    codes = generate_recovery_codes()
    ldap_user.update(
        _user_rdn(username), {ATTR_RECOVERY: {hash_recovery_code(c) for c in codes}}
    )
    return codes
