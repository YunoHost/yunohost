import spwd
import crypt
import random
import string
import subprocess

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import run_commands, check_output
from moulinette.utils.filesystem import append_to_file
from moulinette.authenticators.ldap import Authenticator
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')
SMALL_PWD_LIST = ["yunohost", "olinux"]

class MyMigration(Migration):
    "Migrate password"

    def migrate(self):

        if self._is_root_pwd_listed(SMALL_PWD_LIST):
            new_hash = self._get_admin_hash()
            self._replace_root_hash(new_hash)

    def backward(self):

        pass

    def _get_admin_hash(self):
        """
        Fetch the admin hash from the LDAP db using slapcat
        """
        admin_hash = check_output("slapcat \
            | grep 'dn: cn=admin,dc=yunohost,dc=org' -A20 \
            | grep userPassword -A2 \
            | tr -d '\n ' \
            | tr ':' ' ' \
            | awk '{print $2}' \
            | base64 -d")
        return admin_hash

    def _replace_root_hash(self, new_hash):
        hash_root = spwd.getspnam("root").sp_pwd

        with open('/etc/shadow', 'r') as before_file:
            before = before_file.read()

        with open('/etc/shadow', 'w') as after_file:
            after_file.write(before.replace("root:" + hash_root,
                                            "root:" + new_hash))

    def _is_root_pwd_listed(self, pwd_list):
        hash_root = spwd.getspnam("root").sp_pwd

        for password in pwd_list:
            if hash_root == crypt.crypt(password, hash_root):
                return True
        return False
