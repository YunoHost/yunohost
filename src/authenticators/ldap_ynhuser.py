# -*- coding: utf-8 -*-

import time
import jwt
import logging
import ldap
import ldap.sasl
import base64
import os
import hashlib
import glob
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.text import random_ascii
from moulinette.utils.filesystem import read_json
from yunohost.utils.error import YunohostError, YunohostAuthenticationError

logger = logging.getLogger("yunohostportal.authenticators.ldap_ynhuser")

SESSION_SECRET = open("/etc/yunohost/.ssowat_cookie_secret").read().strip()
SESSION_FOLDER = "/var/cache/yunohost-portal/sessions"
SESSION_VALIDITY = 3 * 24 * 3600  # 3 days

URI = "ldap://localhost:389"
USERDN = "uid={username},ou=users,dc=yunohost,dc=org"

DOMAIN_USER_ACL_DICT: dict[str, dict] = {}
PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"


def user_is_allowed_on_domain(user: str, domain: str) -> bool:

    assert "/" not in domain

    portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"

    if not portal_settings_path.exists():
        if "." not in domain:
            return False
        else:
            parent_domain = domain.split(".", 1)[-1]
            return user_is_allowed_on_domain(user, domain)

    ctime = portal_settings_path.stat().st_ctime
    if domain not in DOMAIN_USER_ACL_DICT or DOMAIN_USER_ACL_DICT[domain]["ctime"] < time.time():
        users = set()
        for infos in read_json(str(portal_settings_path))["apps"].values():
            users = users.union(infos["users"])
        DOMAIN_USER_ACL_DICT[domain] = {}
        DOMAIN_USER_ACL_DICT[domain]["ctime"] = ctime
        DOMAIN_USER_ACL_DICT[domain]["users"] = users

    return user in DOMAIN_USER_ACL_DICT[domain]["users"]


# We want to save the password in the cookie, but we should do so in an encrypted fashion
# This is needed because the SSO later needs to possibly inject the Basic Auth header
# which includes the user's password
# It's also needed because we need to be able to open LDAP sessions, authenticated as the user,
# which requires the user's password
#
# To do so, we use AES-256-CBC. As it's a block encryption algorithm, it requires an IV,
# which we need to keep around for decryption on SSOwat'side.
#
# SESSION_SECRET is used as the encryption key, which implies it must be exactly 32-char long (256/8)
#
# The result is a string formatted as <password_enc_b64>|<iv_b64>
# For example: ctl8kk5GevYdaA5VZ2S88Q==|yTAzCx0Gd1+MCit4EQl9lA==
def encrypt(data):
    alg = algorithms.AES(SESSION_SECRET.encode())
    iv = os.urandom(int(alg.block_size / 8))

    E = Cipher(alg, modes.CBC(iv), default_backend()).encryptor()
    p = padding.PKCS7(alg.block_size).padder()
    data_padded = p.update(data.encode()) + p.finalize()
    data_enc = E.update(data_padded) + E.finalize()
    data_enc_b64 = base64.b64encode(data_enc).decode()
    iv_b64 = base64.b64encode(iv).decode()
    return data_enc_b64 + "|" + iv_b64


def decrypt(data_enc_and_iv_b64):
    data_enc_b64, iv_b64 = data_enc_and_iv_b64.split("|")
    data_enc = base64.b64decode(data_enc_b64)
    iv = base64.b64decode(iv_b64)

    alg = algorithms.AES(SESSION_SECRET.encode())
    D = Cipher(alg, modes.CBC(iv), default_backend()).decryptor()
    p = padding.PKCS7(alg.block_size).unpadder()
    data_padded = D.update(data_enc)
    data = p.update(data_padded) + p.finalize()
    return data.decode()


def short_hash(data):
    return hashlib.shake_256(data.encode()).hexdigest(20)


class Authenticator(BaseAuthenticator):
    name = "ldap_ynhuser"

    def _authenticate_credentials(self, credentials=None):
        from bottle import request

        try:
            username, password = credentials.split(":", 1)
        except ValueError:
            raise YunohostError("invalid_credentials")

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(URI, retry_max=2, retry_delay=0.5)
            con.simple_bind_s(USERDN.format(username=username), password)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
            # FIXME FIXME FIXME : this should be properly logged and caught by Fail2ban ! !  ! ! ! ! !
            raise YunohostError("invalid_password")
        except ldap.SERVER_DOWN:
            logger.warning(m18n.n("ldap_server_down"))

        # Check that we are indeed logged in with the expected identity
        try:
            # whoami_s return dn:..., then delete these 3 characters
            who = con.whoami_s()[3:]
        except Exception as e:
            logger.warning("Error during ldap authentication process: %s", e)
            raise
        else:
            if who != USERDN.format(username=username):
                raise YunohostError(
                    "Not logged with the appropriate identity ?!",
                    raw_msg=True,
                )
        finally:
            # Free the connection, we don't really need it to keep it open as the point is only to check authentication...
            if con:
                con.unbind_s()

        if not user_is_allowed_on_domain(username, request.get_header("host")):
            raise YunohostAuthenticationError("unable_authenticate")

        return {"user": username, "pwd": encrypt(password)}

    def set_session_cookie(self, infos):
        from bottle import response, request

        assert isinstance(infos, dict)
        assert "user" in infos
        assert "pwd" in infos

        # Create a session id, built as <user_hash> + some random ascii
        # Prefixing with the user hash is meant to provide the ability to invalidate all this user's session
        # (eg because the user gets deleted, or password gets changed)
        # User hashing not really meant for security, just to sort of anonymize/pseudonymize the session file name
        infos["id"] = short_hash(infos['user']) + random_ascii(20)
        infos["host"] = request.get_header("host")

        is_dev = Path("/etc/yunohost/.portal-api-allowed-cors-origins").exists()

        response.set_cookie(
            "yunohost.portal",
            jwt.encode(infos, SESSION_SECRET, algorithm="HS256"),
            secure=True,
            httponly=True,
            path="/",
            # Doesn't this cause issues ? May cause issue if the portal is on different subdomain than the portal API ? Will surely cause issue for development similar to CORS ?
            samesite="strict" if not is_dev else None,
        )

        # Create the session file (expiration mechanism)
        session_file = f'{SESSION_FOLDER}/{infos["id"]}'
        os.system(f'touch "{session_file}"')

    def get_session_cookie(self, decrypt_pwd=False):
        from bottle import request, response

        try:
            token = request.get_cookie("yunohost.portal", default="").encode()
            infos = jwt.decode(
                token,
                SESSION_SECRET,
                algorithms="HS256",
                options={"require": ["id", "host", "user", "pwd"]},
            )
        except Exception:
            raise YunohostAuthenticationError("unable_authenticate")

        if not infos:
            raise YunohostAuthenticationError("unable_authenticate")

        if infos["host"] != request.get_header("host"):
            raise YunohostAuthenticationError("unable_authenticate")

        if not user_is_allowed_on_domain(infos["user"], infos["host"]):
            raise YunohostAuthenticationError("unable_authenticate")

        self.purge_expired_session_files()
        session_file = Path(SESSION_FOLDER) / infos["id"]
        if not session_file.exists():
            response.delete_cookie("yunohost.portal", path="/")
            raise YunohostAuthenticationError("session_expired")

        # Otherwise, we 'touch' the file to extend the validity
        session_file.touch()

        if decrypt_pwd:
            infos["pwd"] = decrypt(infos["pwd"])

        return infos

    def delete_session_cookie(self):
        from bottle import response

        try:
            infos = self.get_session_cookie()
            session_file = Path(SESSION_FOLDER) / infos["id"]
            session_file.unlink()
        except Exception as e:
            logger.debug(f"User logged out, but failed to properly invalidate the session : {e}")

        response.delete_cookie("yunohost.portal", path="/")

    def purge_expired_session_files(self):

        for session_file in Path(SESSION_FOLDER).iterdir():
            if abs(session_file.stat().st_ctime - time.time()) > SESSION_VALIDITY:
                try:
                    session_file.unlink()
                except Exception as e:
                    logger.debug(f"Failed to delete session file {session_file} ? {e}")

    @staticmethod
    def invalidate_all_sessions_for_user(user):

        for file in Path(SESSION_FOLDER).glob(f"{short_hash(user)}*"):
            try:
                file.unlink()
            except Exception as e:
                logger.debug(f"Failed to delete session file {file} ? {e}")
