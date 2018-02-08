import glob
import os
import requests
import base64
import time
import json
import errno
import platform

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from yunohost.tools import Migration
from yunohost.service import _run_service_command, service_regen_conf

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    "Upgrade the system to Debian Stretch and Yunohost 3.0"

    mode = "manual"

    def backward(self):

        raise MoulinetteError(m18n.n("migration_0003_backward_impossible"))

    def migrate(self):

        self.logfile = "/tmp/{}.log".format(self.name)

        self.check_assertions()

        logger.warning(m18n.n("migration_0003_start", logfile=self.logfile))

        # Preparing the upgrade
        logger.warning(m18n.n("migration_0003_patching_sources_list"))
        self.patch_apt_sources_list()
        self.apt_update()
        self.hold(["yunohost", "yunohost-admin", "moulinette", "ssowat", "fail2ban"])

        # Main dist-upgrade
        logger.warning(m18n.n("migration_0003_main_upgrade"))
        _run_service_command("stop", "mysql")
        self.apt_dist_upgrade(conf_flags=["old", "def"])
        _run_service_command("start", "mysql")

        # Specific upgrade for fail2ban...
        logger.warning(m18n.n("migration_0003_fail2ban_upgrade"))
        self.unhold(["fail2ban"])
        os.system("mv /etc/fail2ban /etc/fail2ban.old")
        self.apt_dist_upgrade(conf_flags=["new", "miss", "def"])
        _run_service_command("restart", "mysql")

        ## Clean the mess
        os.system("apt autoremove --assume-yes")
        os.system("apt clean --assume-yes")

        # Upgrade yunohost packages
        logger.warning(m18n.n("migration_0003_yunohost_upgrade"))
        self.unhold(["yunohost", "yunohost-admin", "moulinette", "ssowat"])
        self.upgrade_yunohost_packages()
        #service_regen_conf(["fail2ban", "postfix", "mysql", "nslcd"], force=True)

    def check_assertions(self):

        # Be on jessie
        debian_version = platform.dist()[1]
        if not debian_version.startswith('8'):
            raise MoulinetteError(m18n.n("migration_0003_not_jessie"))

        # Have > 1 Go free space on /var/ ?

        # System up to date ?
        # (e.g. with apt list --upgradable 2>&1 | grep -c upgradable)

        pass

    @property
    def disclaimer(self):

        # Backup ?

        # Problematic apps ? E.g. not official or community+working ?

        # Manually modified files ? (c.f. yunohost service regen-conf)

        return "Hurr durr itz dungerus"

    def patch_apt_sources_list(self):

        sources_list = glob.glob("/etc/apt/sources.list.d/*.conf")
        sources_list.append("/etc/apt/sources.list")

        # TODO / FIXME Is this enough ?
        # (Probably not, sometimes there are some jessie/updates or
        # jessie-updates ... but we don't want to touch to jessie-backports
        # maybe ?)
        # TODO/FIXME : to be seen if we really use 'vinaigrette' as final repo name
        for f in sources_list:
            command = "sed -i -e 's@ jessie @ stretch @g' " \
                             "-e 's@repo.yunohost@vinaigrette\.yunohost@g' " \
                             "{}".format(f)
            print(command)
            os.system(command)

    def hold(self, packages):
        for package in packages:
            os.system("apt-mark hold {}".format(package))

    def unhold(self, packages):
        for package in packages:
            os.system("apt-mark unhold {}".format(package))

    def apt_update(self):

        command = "apt-get update"
        logger.debug("Running apt command :\n{}".format(command))
        command += " 2>&1 | tee -a {}".format(self.logfile)

        os.system(command)

    def upgrade_yunohost_packages(self, packages):

        #
        # Here we use a dirty hack to run a command after the current
        # "yunohost tools migrations migrate", because the upgrade of
        # yunohost will also trigger another "yunohost tools migrations migrate"
        # (also the upgrade of the package, if executed from the webadmin, is
        # likely to kill/restart the api which is in turn likely to kill this
        # command before it ends...)
        #

        MOULINETTE_LOCK = "/var/run/moulinette_yunohost.lock"
        packages = ["yunohost", "yunohost-admin", "moulinette", "ssowat"]

        upgrade_command = ""
        upgrade_command += " DEBIAN_FRONTEND=noninteractive"
        upgrade_command += " APT_LISTCHANGES_FRONTEND=none"
        upgrade_command += " apt-get install"
        upgrade_command += " --assume-yes "
        upgrade_command += " ".join(packages)
        upgrade_command += " 2>&1 | tee -a {}".format(self.logfile)

        logger.warning("Activating upgrade of yunohost packages, to be ran right after this command ends.")

        wait_until_end_of_yunohost_command = "(while [ -f {} ]; do sleep 2; done)".format(MOULINETTE_LOCK)

        command = "({} && {}) &".format(wait_until_end_of_yunohost_command,
                                        upgrade_command)

        logger.debug("Running command :\n{}".format(command))

        os.system(command)


    def apt_dist_upgrade(self, conf_flags):

        # Make apt-get happy
        os.system("echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections")

        command = ""
        command += " DEBIAN_FRONTEND=noninteractive"
        command += " APT_LISTCHANGES_FRONTEND=none"
        command += " apt-get"
        command += " --fix-broken --show-upgraded --assume-yes"
        for conf_flag in conf_flags:
            command += ' -o Dpkg::Options::="--force-conf{}"'.format(conf_flag)
        command += " dist-upgrade"

        logger.debug("Running apt command :\n{}".format(command))

        command += " 2>&1 | tee -a {}".format(self.logfile)

        os.system(command)

