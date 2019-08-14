import spwd
import crypt
import random
import string
import subprocess

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import run_commands, check_output
from moulinette.utils.filesystem import append_to_file
from moulinette.authenticators.ldap import Authenticator
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')
SMALL_PWD_LIST = ["yunohost", "olinuxino", "olinux", "raspberry", "admin", "root", "test", "rpi"]


class MyMigration(Migration):

    "Synchronize admin and root passwords"

    def run(self):

        new_hash = self._get_admin_hash()
        self._replace_root_hash(new_hash)

        logger.info(m18n.n("root_password_replaced_by_admin_password"))

    @property
    def mode(self):

        # If the root password is still a "default" value,
        # then this is an emergency and migration shall
        # be applied automatically
        #
        # Otherwise, as playing with root password is touchy,
        # we set this as a manual migration.
        return "auto" if self._is_root_pwd_listed(SMALL_PWD_LIST) else "manual"

    @property
    def disclaimer(self):
        if self._is_root_pwd_listed(SMALL_PWD_LIST):
            return None

        return m18n.n("migration_0006_disclaimer")

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
            | base64 -d \
            | sed 's/{CRYPT}//g'")
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
