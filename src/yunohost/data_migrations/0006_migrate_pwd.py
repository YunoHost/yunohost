import spwd
import crypt
import random
import string
import subprocess

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import run_commands
from moulinette.utils.filesystem import append_to_file
from moulinette.authenticators.ldap import Authenticator

from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')
SMALL_PWD_LIST = ["yunohost", "olinux"]

class MyMigration(Migration):
    "Migrate password"

    def migrate(self):

        new_hash = self._get_admin_hash()
        self._replace_root_hash(new_hash)

    def backward(self):
        pass

    @property
    def mode(self):
        if self._is_root_pwd_listed(SMALL_PWD_LIST):
            return "auto"

        return "manual"

    @property
    def disclaimer(self):
        if self._is_root_pwd_listed(SMALL_PWD_LIST):
            return None

        return m18n.n("migration_0006_root_admin_sync_warning")

    def _get_admin_hash(self):
        """
        Ask for admin hash the ldap db
        Note: to do that like we don't know the admin password we add a second
        password
        """
        logger.debug('Generate a random temporary password')
        tmp_password = ''.join(random.choice(string.ascii_letters +
            string.digits) for i in range(12))

        # Generate a random temporary password (won't be valid after this
        # script ends !) and hash it
        logger.debug('Hash temporary password')
        tmp_hash = subprocess.check_output(["slappasswd", "-h", "{SSHA}","-s",
            tmp_password])

        try:
            logger.debug('Stop slapd and backup its conf')
            run_commands([
                # Stop slapd service...
                'systemctl stop slapd',

                # Backup slapd.conf (to be restored at the end of script)
                'cp /etc/ldap/slapd.conf /root/slapd.conf.bkp'
                ])

            logger.debug('Add password to the conf')
            # Append lines to slapd.conf to manually define root password hash
            append_to_file("/etc/ldap/slapd.conf", 'rootdn "cn=admin,dc=yunohost,dc=org"')
            append_to_file("/etc/ldap/slapd.conf", "\n")
            append_to_file("/etc/ldap/slapd.conf", 'rootpw ' + tmp_hash)

            logger.debug('Start slapd with new password')
            run_commands([
                # Test conf (might not be entirely necessary though :P)
                'slaptest -Q -u -f /etc/ldap/slapd.conf',

                # Regenerate slapd.d directory
                'rm -Rf /etc/ldap/slapd.d',
                'mkdir /etc/ldap/slapd.d',
                'slaptest -f /etc/ldap/slapd.conf -F /etc/ldap/slapd.d/ 2>&1',

                # Set permissions to slapd.d
                'chown -R openldap:openldap /etc/ldap/slapd.d/',

                # Restore slapd.conf
                'mv /root/slapd.conf.bkp /etc/ldap/slapd.conf',

                # Restart slapd service
                'service slapd start'
                ])

            logger.debug('Authenticate on ldap')
            auth = Authenticator('default', 'ldap://localhost:389',
            'dc=yunohost,dc=org', 'cn=admin')
            auth.authenticate( tmp_password)
            logger.debug('Ask for the admin hash')
            admin_hash = auth.search('cn=admin,dc=yunohost,dc=org', 'cn=admin',
                               ['userPassword'])[0]['userPassword'][0]
            admin_hash = admin_hash.replace('{CRYPT}', '')
        finally:
            logger.debug('Remove tmp_password from ldap db')
            # Remove tmp_password from ldap db
            run_commands([

                # Stop slapd service
                'service slapd stop || true',

                'if [ -f /root/slapd.conf.bkp ]; then mv /root/slapd.conf.bkp /etc/ldap/slapd.conf; fi',

                # Regenerate slapd.d directory
                'rm -Rf /etc/ldap/slapd.d',
                'mkdir /etc/ldap/slapd.d',
                'slaptest -f /etc/ldap/slapd.conf -F /etc/ldap/slapd.d/ 2>&1',

                # Set permissions to slapd.d
                'chown -R openldap:openldap /etc/ldap/slapd.d/',

                # Restart slapd service
                'service slapd start'
                ])
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
