import hashlib
import os
import subprocess
from logging import getLogger

from moulinette import m18n
from yunohost.tools import Migration
from yunohost.domain import domain_list
from yunohost.dyndns import dyndns_update, dyndns_list
from yunohost.service import service_restart
from yunohost.utils.file_utils import cp, chown, chmod, rm
from ..utils.error import YunohostError
from yunohost.utils.mail import get_pending_mails_nb


logger = getLogger("yunohost.migration")


def get_upgradable_domains():
    """ Find domains with a 1024 bits DKIM to upgrade
    """
    # Avoid to  filter by mail_in and mail_out features cause
    # 1024 bits keys could already exists, and features could
    # be reactivated
    mail_domains = domain_list()["domains"]
    for domain in mail_domains:
        domain_key = f"/etc/dkim/{domain}.mail.key"
        # Do not recreate the key if it does not exist
        if not os.path.isfile(domain_key):
            continue

        # Do not recreate keys bigger than 1024 bits (about 16 lines)
        with open(domain_key, 'r') as f:
            # Here we used an aproximative way to check key size
            # In order to avoid loading a crypto lib
            if len(f.readlines()) > 20:
                continue
        yield domain


class MyMigration(Migration):
    """ Replace 1024 bits DKIM keys by 2048 bits
    """
    introduced_in_version = "12.1"
    dependencies: list[str] = []
    upgradable_domains = set(get_upgradable_domains())
    dyndns_domains = set(dyndns_list()["domains"])

    @property
    def manual_domains(self):
        domains = self.upgradable_domains - self.dyndns_domains
        domains = [
            domain for domain in domains
            if not domain.endswith(".local")
        ]
        return domains

    @property
    def mode(self):
        if not self.upgradable_domains:
            return "auto"

        return "manual"

    @property
    def disclaimer(self):
        if self.upgradable_domains:
            domains = "\n - " + "\n - ".join(self.upgradable_domains)
        else:
            domains = "no domains seems concerned"

        return m18n.n("migration_0037_upgrade_dkim_keys_disclaimer", domains=domains)

    def check_assertions(self):
        try:
            pending_mails = get_pending_mails_nb()
        except (ValueError, subprocess.CalledProcessError):
            return
        if pending_mails > 0:
            raise YunohostError(
                "migration_0037_upgrade_dkim_keys_pending_mails",
                pending_mails=pending_mails
            )

    def run(self, *args):
        self.check_assertions()
        # Find 1024 bits keys to upgrade
        # Deal with potential admin customization with
        # domains sharing the same 1048 bits dkim keys
        dkim_keys = {}
        for domain in self.upgradable_domains:
            domain_key = f"/etc/dkim/{domain}.mail.key"

            with open(domain_key, 'rb', buffering=0) as f:
                dkim_key_hash = hashlib.file_digest(f, 'sha256').hexdigest()

            if dkim_key_hash not in dkim_keys:
                dkim_keys[dkim_key_hash] = []

            dkim_keys[dkim_key_hash].append(domain)

        # Generate 2048 bits keys for each 1024 bits dkim keys
        for dkim_key_hash, domains in dkim_keys.items():
            try:
                subprocess.check_call([
                    "opendkim-genkey", "-d", domains[0], "-b", "2048",
                    "--selector=mail", "--directory=/etc/dkim"
                ])
            except subprocess.CalledProcessError:
                logger.error(m18n.n("migration_0037_upgrade_dkim_keys_failed", domains=", ".join(domains)))
                continue

            with open("/etc/dkim/mail.txt", 'r') as f:
                data = f.read()

            for domain in domains:
                cp("/etc/dkim/mail.private", f"/etc/dkim/{domain}.mail.key")
                with open(f"/etc/dkim/{domain}.mail.txt", 'w') as file:
                    file.write(data.replace(domains[0], domain))
            rm("/etc/dkim/mail.private")
            rm("/etc/dkim/mail.txt")

        # Reapply permissions just in case
        chmod("/etc/dkim/", mode=0o700, recursive=True)
        chown("/etc/dkim/", uid="opendkim", gid="root")

        # Restart opendkim
        service_restart("opendkim")

        # If an upgradable domain is a dyndns domain, update dyndns
        if self.upgradable_domains & self.dyndns_domains:
            dyndns_update(force=True)

        # If an upgradable domain is a dyndns domain, update dyndns
        if self.manual_domains:
            domains = "\n - " + "\n - ".join(self.manual_domains)
            logger.warning(m18n.n("migration_0037_upgrade_dkim_keys_manual_action", domains=domains))
