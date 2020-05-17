import os
import subprocess

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.firewall import firewall_reload
from yunohost.service import service_restart
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):

    "Migrate legacy iptables rules from stretch that relied on xtable and should now rely on nftable"

    dependencies = ["migrate_to_buster"]

    def run(self):

        self.do_ipv4 = os.system("iptables -w -L >/dev/null") == 0
        self.do_ipv6 = os.system("ip6tables -w -L >/dev/null") == 0

        if not self.do_ipv4:
            logger.warning(m18n.n('iptables_unavailable'))
        if not self.do_ipv6:
            logger.warning(m18n.n('ip6tables_unavailable'))

        backup_folder = "/home/yunohost.backup/premigration/xtable_to_nftable/"
        if not os.path.exists(backup_folder):
            os.makedirs(backup_folder, 0o750)
        self.backup_rules_ipv4 = os.path.join(backup_folder, "legacy_rules_ipv4")
        self.backup_rules_ipv6 = os.path.join(backup_folder, "legacy_rules_ipv6")

        # Backup existing legacy rules to be able to rollback
        if self.do_ipv4 and not os.path.exists(self.backup_rules_ipv4):
            os.system("iptables-legacy -L >/dev/null")  # For some reason if we don't do this, iptables-legacy-save is empty ?
            subprocess.check_call("iptables-legacy-save > %s" % self.backup_rules_ipv4, shell=True)
            assert subprocess.check_output("cat %s" % self.backup_rules_ipv4, shell=True).strip(), "Uhoh backup of legacy ipv4 rules is empty !?"
        if self.do_ipv6 and not os.path.exists(self.backup_rules_ipv6):
            os.system("ip6tables-legacy -L >/dev/null")  # For some reason if we don't do this, iptables-legacy-save is empty ?
            subprocess.check_call("ip6tables-legacy-save > %s" % self.backup_rules_ipv6, shell=True)
            assert subprocess.check_output("cat %s" % self.backup_rules_ipv6, shell=True).strip(), "Uhoh backup of legacy ipv6 rules is empty !?"

        # We inject the legacy rules (iptables-legacy) into the new iptable (just "iptables")
        try:
            if self.do_ipv4:
                subprocess.check_call("iptables-legacy-save | iptables-restore", shell=True)
            if self.do_ipv6:
                subprocess.check_call("ip6tables-legacy-save | ip6tables-restore", shell=True)
        except Exception as e:
            self.rollback()
            raise YunohostError("migration_0018_failed_to_migrate_iptables_rules", error=e)

        # Reset everything in iptables-legacy
        # Stolen from https://serverfault.com/a/200642
        try:
            if self.do_ipv4:
                subprocess.check_call(
                    "iptables-legacy-save | awk '/^[*]/ { print $1 }"                         # Keep lines like *raw, *filter and *nat
                    "                            /^:[A-Z]+ [^-]/ { print $1 \" ACCEPT\" ; }"  # Turn all policies to accept
                    "                            /COMMIT/ { print $0; }'"                     # Keep the line COMMIT
                    " | iptables-legacy-restore",
                    shell=True)
            if self.do_ipv6:
                subprocess.check_call(
                    "ip6tables-legacy-save | awk '/^[*]/ { print $1 }"                        # Keep lines like *raw, *filter and *nat
                    "                            /^:[A-Z]+ [^-]/ { print $1 \" ACCEPT\" ; }"  # Turn all policies to accept
                    "                            /COMMIT/ { print $0; }'"                     # Keep the line COMMIT
                    " | ip6tables-legacy-restore",
                    shell=True)
        except Exception as e:
            self.rollback()
            raise YunohostError("migration_0018_failed_to_reset_legacy_rules", error=e)

        # You might be wondering "uh but is it really useful to
        # iptables-legacy-save | iptables-restore considering firewall_reload()
        # flush/resets everything anyway ?"
        # But the answer is : firewall_reload() only resets the *filter table.
        # On more complex setups (e.g. internet cube or docker) you will also
        # have rules in the *nat (or maybe *raw?) sections of iptables.
        firewall_reload()
        service_restart("fail2ban")

    def rollback(self):

        if self.do_ipv4:
            subprocess.check_call("iptables-legacy-restore < %s" % self.backup_rules_ipv4, shell=True)
        if self.do_ipv6:
            subprocess.check_call("iptables-legacy-restore < %s" % self.backup_rules_ipv6, shell=True)
