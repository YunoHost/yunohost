# -*- coding: utf-8 -*-

import jwt
import logging
import ldap
import ldap.sasl
import datetime
import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.text import random_ascii
from yunohost.utils.error import YunohostError, YunohostAuthenticationError

# FIXME : we shall generate this somewhere if it doesnt exists yet
# FIXME : fix permissions
session_secret = open("/etc/yunohost/.ssowat_cookie_secret").read().strip()

logger = logging.getLogger("yunohostportal.authenticators.ldap_ynhuser")

URI = "ldap://localhost:389"
USERDN = "uid={username},ou=users,dc=yunohost,dc=org"

# We want to save the password in the cookie, but we should do so in an encrypted fashion
# This is needed because the SSO later needs to possibly inject the Basic Auth header
# which includes the user's password
# It's also needed because we need to be able to open LDAP sessions, authenticated as the user,
# which requires the user's password
#
# To do so, we use AES-256-CBC. As it's a block encryption algorithm, it requires an IV,
# which we need to keep around for decryption on SSOwat'side.
#
# session_secret is used as the encryption key, which implies it must be exactly 32-char long (256/8)
#
# The result is a string formatted as <password_enc_b64>|<iv_b64>
# For example: ctl8kk5GevYdaA5VZ2S88Q==|yTAzCx0Gd1+MCit4EQl9lA==
def encrypt(data):

    alg = algorithms.AES(session_secret.encode())
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

    alg = algorithms.AES(session_secret.encode())
    D = Cipher(alg, modes.CBC(iv), default_backend()).decryptor()
    p = padding.PKCS7(alg.block_size).unpadder()
    data_padded = D.update(data_enc)
    data = p.update(data_padded) + p.finalize()
    return data.decode()


class Authenticator(BaseAuthenticator):

    name = "ldap_ynhuser"

    def _authenticate_credentials(self, credentials=None):

        try:
            username, password = credentials.split(":", 1)
        except ValueError:
            raise YunohostError("invalid_credentials")

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(
                URI, retry_max=2, retry_delay=0.5
            )
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

        return {"user": username, "pwd": encrypt(password)}

    def set_session_cookie(self, infos):

        from bottle import response

        assert isinstance(infos, dict)

        # This allows to generate a new session id or keep the existing one
        current_infos = self.get_session_cookie(raise_if_no_session_exists=False)
        new_infos = {
            "id": current_infos["id"],
            # See https://pyjwt.readthedocs.io/en/latest/usage.html#registered-claim-names
            # for explanations regarding nbf, exp
            "nbf": int(datetime.datetime.now().timestamp()),
            "exp": int(datetime.datetime.now().timestamp()) + (7 * 24 * 3600)  # One week validity   # FIXME : does it mean the session suddenly expires after a week ? Can we somehow auto-renew it at every usage or something ?
        }
        new_infos.update(infos)

        response.set_cookie(
            "yunohost.portal",
            jwt.encode(new_infos, session_secret, algorithm="HS256"),
            secure=True,
            httponly=True,
            path="/",
            # samesite="strict", # Bottle 0.12 doesn't support samesite, to be added in next versions
            # FIXME : add Expire clause
        )

    def get_session_cookie(self, raise_if_no_session_exists=True, decrypt_pwd=False):

        from bottle import request

        try:
            token = request.get_cookie("yunohost.portal", default="").encode()
            infos = jwt.decode(token, session_secret, algorithms="HS256", options={"require": ["id", "user", "exp", "nbf"]})
        except Exception:
            if not raise_if_no_session_exists:
                return {"id": random_ascii()}
            # FIXME FIXME FIXME : we might also want this to be caught by fail2ban ? Idk ...
            raise YunohostAuthenticationError("unable_authenticate")

        if not infos and raise_if_no_session_exists:
            raise YunohostAuthenticationError("unable_authenticate")

        if "id" not in infos:
            infos["id"] = random_ascii()

        if decrypt_pwd:
            infos["pwd"] = decrypt(infos["pwd"])

        # FIXME : maybe check expiration here ? Or is it already done in jwt.decode ?

        # FIXME: also a valid cookie ain't everything ... i.e. maybe we should validate that the user still exists

        return infos

    def delete_session_cookie(self):

        from bottle import response

        response.set_cookie("yunohost.portal", "", max_age=-1)
        response.delete_cookie("yunohost.portal")
