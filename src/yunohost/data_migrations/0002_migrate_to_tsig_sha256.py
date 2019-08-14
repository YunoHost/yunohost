import glob
import os
import requests
import base64
import time
import json

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.dyndns import _guess_current_dyndns_domain

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):

    "Migrate Dyndns stuff from MD5 TSIG to SHA512 TSIG"

    def run(self, dyn_host="dyndns.yunohost.org", domain=None, private_key_path=None):

        if domain is None or private_key_path is None:
            try:
                (domain, private_key_path) = _guess_current_dyndns_domain(dyn_host)
                assert "+157" in private_key_path
            except (YunohostError, AssertionError):
                logger.info(m18n.n("migrate_tsig_not_needed"))
                return

        logger.info(m18n.n('migrate_tsig_start', domain=domain))
        public_key_path = private_key_path.rsplit(".private", 1)[0] + ".key"
        public_key_md5 = open(public_key_path).read().strip().split(' ')[-1]

        os.system('cd /etc/yunohost/dyndns && '
                  'dnssec-keygen -a hmac-sha512 -b 512 -r /dev/urandom -n USER %s' % domain)
        os.system('chmod 600 /etc/yunohost/dyndns/*.key /etc/yunohost/dyndns/*.private')

        # +165 means that this file store a hmac-sha512 key
        new_key_path = glob.glob('/etc/yunohost/dyndns/*+165*.key')[0]
        public_key_sha512 = open(new_key_path).read().strip().split(' ', 6)[-1]

        try:
            r = requests.put('https://%s/migrate_key_to_sha512/' % (dyn_host),
                             data={
                               'public_key_md5': base64.b64encode(public_key_md5),
                               'public_key_sha512': base64.b64encode(public_key_sha512),
                             }, timeout=30)
        except requests.ConnectionError:
            raise YunohostError('no_internet_connection')

        if r.status_code != 201:
            try:
                error = json.loads(r.text)['error']
            except Exception:
                # failed to decode json
                error = r.text

                import traceback
                from StringIO import StringIO
                stack = StringIO()
                traceback.print_stack(file=stack)
                logger.error(stack.getvalue())

            # Migration didn't succeed, so we rollback and raise an exception
            os.system("mv /etc/yunohost/dyndns/*+165* /tmp")

            raise YunohostError('migrate_tsig_failed', domain=domain,
                                error_code=str(r.status_code), error=error)

        # remove old certificates
        os.system("mv /etc/yunohost/dyndns/*+157* /tmp")

        # sleep to wait for dyndns cache invalidation
        logger.info(m18n.n('migrate_tsig_wait'))
        time.sleep(60)
        logger.info(m18n.n('migrate_tsig_wait_2'))
        time.sleep(60)
        logger.info(m18n.n('migrate_tsig_wait_3'))
        time.sleep(30)
        logger.info(m18n.n('migrate_tsig_wait_4'))
        time.sleep(30)

        logger.info(m18n.n('migrate_tsig_end'))
        return
