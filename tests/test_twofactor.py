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

import pytest
from yunohost.utils import twofactor
from yunohost.utils.twofactor import (
    TwoFactorChallenge,
    current_counter,
    generate_recovery_codes,
    generate_secret,
    hotp,
    is_enforced,
    make_setup_token,
    read_setup_token,
    totp_match,
)

# RFC 6238 appendix B, SHA1 seed "12345678901234567890" (base32-encoded),
# truncated to 6 digits
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_VECTORS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
]


#
# Pure unit tests (no LDAP needed)
#


@pytest.mark.parametrize("timestamp,code", RFC_VECTORS)
def test_totp_rfc6238_vectors(timestamp, code):
    assert hotp(RFC_SECRET, current_counter(timestamp)) == code
    assert totp_match(RFC_SECRET, code, now=timestamp) == current_counter(timestamp)


def test_totp_accepts_clock_drift_of_one_step():
    secret = generate_secret()
    now = 1_700_000_000
    previous = hotp(secret, current_counter(now) - 1)
    following = hotp(secret, current_counter(now) + 1)
    too_old = hotp(secret, current_counter(now) - 2)

    assert totp_match(secret, previous, now=now) is not None
    assert totp_match(secret, following, now=now) is not None
    assert totp_match(secret, too_old, now=now) is None


def test_totp_rejects_replay():
    secret = generate_secret()
    now = 1_700_000_000
    code = hotp(secret, current_counter(now))

    counter = totp_match(secret, code, now=now)
    assert counter is not None
    assert totp_match(secret, code, last_counter=counter, now=now) is None


@pytest.mark.parametrize("garbage", ["", "12345", "1234567", "abcdef", None])
def test_totp_rejects_malformed_codes(garbage):
    assert totp_match(generate_secret(), garbage) is None


def test_recovery_codes_are_unique_and_normalized():
    codes = generate_recovery_codes()
    assert len(set(codes)) == len(codes) == twofactor.RECOVERY_CODES_COUNT

    hashes = [twofactor.hash_recovery_code(c) for c in codes]
    sloppy = codes[0].upper().replace("-", " ")
    assert twofactor._match_recovery_code(sloppy, hashes) == hashes[0]
    assert twofactor._match_recovery_code("aaaa-aaaa-aaaa", hashes) is None


def test_setup_token_roundtrip_and_tampering():
    token = make_setup_token("alice", "SECRET", ["h1"], "key")
    assert read_setup_token(token, "alice", "key")["secret"] == "SECRET"

    with pytest.raises(TwoFactorChallenge):
        read_setup_token(token, "bob", "key")
    with pytest.raises(TwoFactorChallenge):
        read_setup_token(token, "alice", "another_key")
    with pytest.raises(TwoFactorChallenge):
        read_setup_token(token[:-2] + "xx", "alice", "key")


def test_setup_token_is_not_signed_with_the_raw_session_key():
    import jwt

    token = make_setup_token("alice", "SECRET", [], "key")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, "key", algorithms=["HS256"])


def test_setup_token_expires(monkeypatch):
    # Forge a token issued long enough ago to be expired
    real_time = time.time
    monkeypatch.setattr(
        time, "time", lambda: real_time() - twofactor.SETUP_TOKEN_VALIDITY - 60
    )
    token = make_setup_token("alice", "SECRET", [], "key")
    monkeypatch.setattr(time, "time", real_time)
    with pytest.raises(TwoFactorChallenge) as e:
        read_setup_token(token, "alice", "key")
    assert e.value.key == "twofactor_setup_token_expired"


def test_policy_enforcement_matrix():
    assert not is_enforced("disabled", True)
    assert not is_enforced("optional", True)
    assert is_enforced("enforced_admins", True)
    assert not is_enforced("enforced_admins", False)
    assert is_enforced("enforced_all", False)


def test_policy_file(tmp_path, monkeypatch):
    monkeypatch.setattr(twofactor, "POLICY_FILE", tmp_path / "policy")
    assert twofactor.get_policy() == twofactor.DEFAULT_POLICY

    twofactor.write_policy("enforced_all")
    assert twofactor.get_policy() == "enforced_all"

    # Garbage must not silently disable 2FA
    (tmp_path / "policy").write_text("lolwut")
    assert twofactor.get_policy() == "enforced_all"


#
# Integration tests (need a YunoHost install with slapd)
#


@pytest.fixture
def ldap_env(tmp_path, monkeypatch):
    from yunohost.domain import _get_maindomain
    from yunohost.user import user_create, user_delete, user_list

    for u in user_list()["users"]:
        user_delete(u, purge=True, force=True)

    maindomain = _get_maindomain()
    user_create("alice", maindomain, "Yunohost", admin=True, fullname="Alice White")
    user_create("bob", maindomain, "test123Ynh", fullname="Bob Snow")

    monkeypatch.setattr(twofactor, "POLICY_FILE", tmp_path / "policy")

    # Simulate the extra fields sent alongside `credentials` to /login
    params: dict[str, str] = {}
    monkeypatch.setattr(twofactor, "get_request_param", lambda name: params.get(name))

    yield params

    for u in user_list()["users"]:
        user_delete(u, purge=True, force=True)


def _login_admin():
    from yunohost.authenticators.ldap_admin import Authenticator

    return Authenticator().authenticate_credentials(credentials="alice:Yunohost")


def _challenge(exception) -> dict:
    return json.loads(exception.value.strerror)


def test_login_without_2fa_when_optional(ldap_env):
    twofactor.write_policy("optional")
    assert _login_admin() == {"user": "alice"}


def test_enforced_login_requires_enrollment_then_code(ldap_env):
    from yunohost.user import user_twofactor_status

    twofactor.write_policy("enforced_admins")

    # 1. Password alone is not enough: we get a setup challenge
    with pytest.raises(TwoFactorChallenge) as e:
        _login_admin()
    setup = _challenge(e)
    assert setup["error"] == "twofactor_setup_required"
    assert setup["uri"].startswith("otpauth://totp/")
    assert len(setup["recovery_codes"]) == twofactor.RECOVERY_CODES_COUNT

    # 2. A wrong code doesn't enroll
    ldap_env.update(twofactor_setup_token=setup["setup_token"], twofactor_code="000000")
    with pytest.raises(TwoFactorChallenge) as e:
        _login_admin()
    assert _challenge(e)["error"] == "twofactor_code_invalid"
    assert not user_twofactor_status("alice")["enabled"]

    # 3. The right code enrolls and logs in
    ldap_env["twofactor_code"] = hotp(setup["secret"], current_counter())
    assert _login_admin() == {"user": "alice"}
    assert user_twofactor_status("alice")["enabled"]

    # 4. Same code can't be replayed
    ldap_env.pop("twofactor_setup_token")
    with pytest.raises(TwoFactorChallenge):
        _login_admin()

    # 5. Without a code, the password alone is refused
    ldap_env.clear()
    with pytest.raises(TwoFactorChallenge) as e:
        _login_admin()
    assert _challenge(e)["error"] == "twofactor_code_required"

    # 6. Recovery codes work exactly once
    ldap_env["twofactor_code"] = setup["recovery_codes"][0]
    assert _login_admin() == {"user": "alice"}
    with pytest.raises(TwoFactorChallenge):
        _login_admin()
    assert (
        user_twofactor_status("alice")["recovery_codes_left"]
        == twofactor.RECOVERY_CODES_COUNT - 1
    )


def test_wrong_password_never_reaches_2fa(ldap_env):
    from moulinette.core import MoulinetteError
    from yunohost.authenticators.ldap_admin import Authenticator

    twofactor.write_policy("enforced_all")
    with pytest.raises(MoulinetteError) as e:
        Authenticator().authenticate_credentials(credentials="alice:nope")
    assert not isinstance(e.value, TwoFactorChallenge)


def test_secret_is_not_readable_by_other_users(ldap_env):
    from yunohost.utils.ldap import LDAPInterface, _get_ldap_interface

    twofactor.write_policy("optional")
    twofactor.store_enrollment(
        _get_ldap_interface(), "alice", generate_secret(), 0, ["h"]
    )

    as_bob = LDAPInterface("bob", "test123Ynh")
    entry = as_bob.search("uid=alice,ou=users", attrs=twofactor.ATTRS + ["cn"])[0]
    assert "cn" in entry
    for attr in twofactor.ATTRS:
        assert attr not in entry

    as_alice = LDAPInterface("alice", "Yunohost")
    assert twofactor.is_enrolled(twofactor.read_user_data(as_alice, "alice"))


def test_user_cannot_disable_when_enforced_but_admin_can_reset(ldap_env):
    from yunohost.user import user_twofactor_reset, user_twofactor_status
    from yunohost.utils.error import YunohostValidationError
    from yunohost.utils.ldap import LDAPInterface

    twofactor.write_policy("enforced_all")
    secret = generate_secret()
    as_bob = LDAPInterface("bob", "test123Ynh")
    twofactor.store_enrollment(as_bob, "bob", secret, 0, [])

    with pytest.raises(YunohostValidationError) as e:
        twofactor.self_disable(
            as_bob, "bob", hotp(secret, current_counter()), is_admin=False
        )
    assert e.value.key == "twofactor_cannot_disable_enforced"
    assert user_twofactor_status("bob")["enabled"]

    user_twofactor_reset("bob")
    assert not user_twofactor_status("bob")["enabled"]


def test_user_can_disable_when_optional(ldap_env):
    from yunohost.utils.ldap import LDAPInterface

    twofactor.write_policy("optional")
    secret = generate_secret()
    as_bob = LDAPInterface("bob", "test123Ynh")
    twofactor.store_enrollment(as_bob, "bob", secret, 0, [])

    twofactor.self_disable(as_bob, "bob", hotp(secret, current_counter()), False)
    assert not twofactor.is_enrolled(twofactor.read_user_data(as_bob, "bob"))
