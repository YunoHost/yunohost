import glob
import os
import requests
import base64
import time
import json
import errno
import platform
from shutil import copy2

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output
from yunohost.tools import Migration
from yunohost.app import unstable_apps
from yunohost.service import _run_service_command, service_regen_conf, manually_modified_files
from yunohost.utils.filesystem import free_space_in_directory

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
        self.backup_files_to_keep()
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

        # Clean the mess
        os.system("apt autoremove --assume-yes")
        os.system("apt clean --assume-yes")

        # Upgrade yunohost packages
        logger.warning(m18n.n("migration_0003_yunohost_upgrade"))
        self.restore_files_to_keep()
        self.unhold(["yunohost", "yunohost-admin", "moulinette", "ssowat"])
        self.upgrade_yunohost_packages()

    def debian_major_version(self):
        return int(platform.dist()[1][0])

    def check_assertions(self):

        # Be on jessie
        if not self.debian_major_version() == 8:
            raise MoulinetteError(m18n.n("migration_0003_not_jessie"))

        # Have > 1 Go free space on /var/ ?
        if free_space_in_directory("/var/") / (1024**3) < 1.0:
            raise MoulinetteError(m18n.n("migration_0003_not_enough_free_space"))

        # Check system is up to date
        self.apt_update()
        apt_list_upgradable = check_output("apt list --upgradable".split())
        if "upgradable" in apt_list_upgradable:
            raise MoulinetteError(m18n.n("migration_0003_system_not_fully_up_to_date"))

    @property
    def disclaimer(self):

        # Avoid having a super long disclaimer + uncessary check if we ain't
        # on jessie anymore
        if not self.debian_major_version() == 8:
            return None

        # Get list of problematic apps ? I.e. not official or community+working
        problematic_apps = unstable_apps()
        problematic_apps = "".join(["\n    - "+app for app in problematic_apps ])

        # Manually modified files ? (c.f. yunohost service regen-conf)
        modified_files = manually_modified_files()
        modified_files = "".join(["\n    - "+f for f in modified_files ])

        message = m18n.n("migration_0003_general_warning")

        if problematic_apps:
            message += "\n\n" + m18n.n("migration_0003_problematic_apps_warning", problematic_apps=problematic_apps)

        if modified_files:
            message += "\n\n" + m18n.n("migration_0003_modified_files", manually_modified_files=modified_files)

        return message

    def patch_apt_sources_list(self):

        sources_list = glob.glob("/etc/apt/sources.list.d/*.list")
        sources_list.append("/etc/apt/sources.list")

        # TODO/FIXME : to be seen if we really use 'vinaigrette' as final repo name
        # This :
        # - replace single 'jessie' occurence by 'stretch'
        # - comments lines containing "backports"
        # - replace 'jessie/updates' by 'strech/updates'
        # - switch yunohost's repo to vinaigrette
        for f in sources_list:
            command = "sed -i -e 's@ jessie @ stretch @g' " \
                             "-e '/backports/ s@^#*@#@' " \
                             "-e 's@ jessie/updates @ stretch/updates @g' " \
                             "-e 's@repo.yunohost@vinaigrette.yunohost@g' " \
                             "{}".format(f)
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

    def upgrade_yunohost_packages(self):

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

        command = "({} && {} && echo 'Done!') &".format(wait_until_end_of_yunohost_command,
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


    # Those are files that should be kept and restored before the final switch
    # to yunohost 3.x... They end up being modified by the various dist-upgrades
    # (or need to be taken out momentarily), which then blocks the regen-conf
    # as they are flagged as "manually modified"...
    files_to_keep = [
        "/etc/mysql/my.cnf",
        "/etc/nslcd.conf",
        "/etc/postfix/master.cf",
        "/etc/fail2ban/filter.d/yunohost.conf"
    ]

    def backup_files_to_keep(self):

        tmp_dir = os.path.join("/tmp/", self.name)
        os.mkdir(tmp_dir, 0700)

        for f in self.files_to_keep:
            dest_file = f.strip('/').replace("/", "_")
            copy2(f, os.path.join(tmp_dir, dest_file))

    def restore_files_to_keep(self):

        tmp_dir = os.path.join("/tmp/", self.name)

        for f in self.files_to_keep:
            dest_file = f.strip('/').replace("/", "_")
            copy2(os.path.join(tmp_dir, dest_file), f)

