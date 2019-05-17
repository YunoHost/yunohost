import glob
import os
from shutil import copy2

from moulinette import m18n, msettings
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output, call_async_output
from moulinette.utils.filesystem import read_file

from yunohost.tools import Migration
from yunohost.app import unstable_apps
from yunohost.service import _run_service_command
from yunohost.regenconf import (manually_modified_files,
                                manually_modified_files_compared_to_debian_default)
from yunohost.utils.filesystem import free_space_in_directory
from yunohost.utils.packages import get_installed_version
from yunohost.utils.network import get_network_interfaces
from yunohost.firewall import firewall_allow, firewall_disallow

logger = getActionLogger('yunohost.migration')

YUNOHOST_PACKAGES = ["yunohost", "yunohost-admin", "moulinette", "ssowat"]


class MyMigration(Migration):

    "Upgrade the system to Debian Stretch and Yunohost 3.0"

    mode = "manual"

    def backward(self):

        raise YunohostError("migration_0003_backward_impossible")

    def migrate(self):

        self.logfile = "/var/log/yunohost/{}.log".format(self.name)

        self.check_assertions()

        logger.info(m18n.n("migration_0003_start", logfile=self.logfile))

        # Preparing the upgrade
        self.restore_original_nginx_conf_if_needed()

        logger.info(m18n.n("migration_0003_patching_sources_list"))
        self.patch_apt_sources_list()
        self.backup_files_to_keep()
        self.apt_update()
        apps_packages = self.get_apps_equivs_packages()
        self.unhold(["metronome"])
        self.hold(YUNOHOST_PACKAGES + apps_packages + ["fail2ban"])

        # Main dist-upgrade
        logger.info(m18n.n("migration_0003_main_upgrade"))
        _run_service_command("stop", "mysql")
        self.apt_dist_upgrade(conf_flags=["old", "miss", "def"])
        _run_service_command("start", "mysql")
        if self.debian_major_version() == 8:
            raise YunohostError("migration_0003_still_on_jessie_after_main_upgrade", log=self.logfile)

        # Specific upgrade for fail2ban...
        logger.info(m18n.n("migration_0003_fail2ban_upgrade"))
        self.unhold(["fail2ban"])
        # Don't move this if folder already exists. If it does, we probably are
        # running this script a 2nd, 3rd, ... time but /etc/fail2ban will
        # be re-created only for the first dist-upgrade of fail2ban
        if not os.path.exists("/etc/fail2ban.old"):
            os.system("mv /etc/fail2ban /etc/fail2ban.old")
        self.apt_dist_upgrade(conf_flags=["new", "miss", "def"])
        _run_service_command("restart", "fail2ban")

        self.disable_predicable_interface_names()

        # Clean the mess
        os.system("apt autoremove --assume-yes")
        os.system("apt clean --assume-yes")

        # We moved to port 587 for SMTP
        # https://busylog.net/smtp-tls-ssl-25-465-587/
        firewall_allow("Both", 587)
        firewall_disallow("Both", 465)

        # Upgrade yunohost packages
        logger.info(m18n.n("migration_0003_yunohost_upgrade"))
        self.restore_files_to_keep()
        self.unhold(YUNOHOST_PACKAGES + apps_packages)
        self.upgrade_yunohost_packages()

    def debian_major_version(self):
        # The python module "platform" and lsb_release are not reliable because
        # on some setup, they still return Release=8 even after upgrading to
        # stretch ... (Apparently this is related to OVH overriding some stuff
        # with /etc/lsb-release for instance -_-)
        # Instead, we rely on /etc/os-release which should be the raw info from
        # the distribution...
        return int(check_output("grep VERSION_ID /etc/os-release | head -n 1 | tr '\"' ' ' | cut -d ' ' -f2"))

    def yunohost_major_version(self):
        return int(get_installed_version("yunohost").split('.')[0])

    def check_assertions(self):

        # Be on jessie (8.x) and yunohost 2.x
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be >= 9.x but yunohost package
        # would still be in 2.x...
        if not self.debian_major_version() == 8 \
           and not self.yunohost_major_version() == 2:
            raise YunohostError("migration_0003_not_jessie")

        # Have > 1 Go free space on /var/ ?
        if free_space_in_directory("/var/") / (1024**3) < 1.0:
            raise YunohostError("migration_0003_not_enough_free_space")

        # Check system is up to date
        # (but we don't if 'stretch' is already in the sources.list ...
        # which means maybe a previous upgrade crashed and we're re-running it)
        if " stretch " not in read_file("/etc/apt/sources.list"):
            self.apt_update()
            apt_list_upgradable = check_output("apt list --upgradable -a")
            if "upgradable" in apt_list_upgradable:
                raise YunohostError("migration_0003_system_not_fully_up_to_date")

    @property
    def disclaimer(self):

        # Avoid having a super long disclaimer + uncessary check if we ain't
        # on jessie / yunohost 2.x anymore
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be >= 9.x but yunohost package
        # would still be in 2.x...
        if not self.debian_major_version() == 8 \
           and not self.yunohost_major_version() == 2:
            return None

        # Get list of problematic apps ? I.e. not official or community+working
        problematic_apps = unstable_apps()
        problematic_apps = "".join(["\n    - " + app for app in problematic_apps])

        # Manually modified files ? (c.f. yunohost service regen-conf)
        modified_files = manually_modified_files()
        # We also have a specific check for nginx.conf which some people
        # modified and needs to be upgraded...
        if "/etc/nginx/nginx.conf" in manually_modified_files_compared_to_debian_default():
            modified_files.append("/etc/nginx/nginx.conf")
        modified_files = "".join(["\n    - " + f for f in modified_files])

        message = m18n.n("migration_0003_general_warning")

        if problematic_apps:
            message += "\n\n" + m18n.n("migration_0003_problematic_apps_warning", problematic_apps=problematic_apps)

        if modified_files:
            message += "\n\n" + m18n.n("migration_0003_modified_files", manually_modified_files=modified_files)

        return message

    def patch_apt_sources_list(self):

        sources_list = glob.glob("/etc/apt/sources.list.d/*.list")
        sources_list.append("/etc/apt/sources.list")

        # This :
        # - replace single 'jessie' occurence by 'stretch'
        # - comments lines containing "backports"
        # - replace 'jessie/updates' by 'strech/updates' (or same with a -)
        # - switch yunohost's repo to forge
        for f in sources_list:
            command = "sed -i -e 's@ jessie @ stretch @g' " \
                      "-e '/backports/ s@^#*@#@' " \
                      "-e 's@ jessie/updates @ stretch/updates @g' " \
                      "-e 's@ jessie-updates @ stretch-updates @g' " \
                      "-e 's@repo.yunohost@forge.yunohost@g' " \
                      "{}".format(f)
            os.system(command)

    def get_apps_equivs_packages(self):

        command = "dpkg --get-selections" \
                  " | grep -v deinstall" \
                  " | awk '{print $1}'" \
                  " | { grep 'ynh-deps$' || true; }"

        output = check_output(command).strip()

        return output.split('\n') if output else []

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

        upgrade_command = ""
        upgrade_command += " DEBIAN_FRONTEND=noninteractive"
        upgrade_command += " APT_LISTCHANGES_FRONTEND=none"
        upgrade_command += " apt-get install"
        upgrade_command += " --assume-yes "
        upgrade_command += " ".join(YUNOHOST_PACKAGES)
        # We also install php-zip and php7.0-acpu to fix an issue with
        # nextcloud and kanboard that need it when on stretch.
        upgrade_command += " php-zip php7.0-apcu"
        upgrade_command += " 2>&1 | tee -a {}".format(self.logfile)

        wait_until_end_of_yunohost_command = "(while [ -f {} ]; do sleep 2; done)".format(MOULINETTE_LOCK)

        command = "({} && {}; echo 'Migration complete!') &".format(wait_until_end_of_yunohost_command,
                                                                    upgrade_command)

        logger.debug("Running command :\n{}".format(command))

        os.system(command)

    def apt_dist_upgrade(self, conf_flags):

        # Make apt-get happy
        os.system("echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections")
        # Don't send an email to root about the postgresql migration. It should be handled automatically after.
        os.system("echo 'postgresql-common postgresql-common/obsolete-major seen true' | debconf-set-selections")

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

        is_api = msettings.get('interface') == 'api'
        if is_api:
            callbacks = (
                lambda l: logger.info(l.rstrip()),
                lambda l: logger.warning(l.rstrip()),
            )
            call_async_output(command, callbacks, shell=True)
        else:
            # We do this when running from the cli to have the output of the
            # command showing in the terminal, since 'info' channel is only
            # enabled if the user explicitly add --verbose ...
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

        logger.debug("Backuping specific files to keep ...")

        # Create tmp directory if it does not exists
        tmp_dir = os.path.join("/tmp/", self.name)
        if not os.path.exists(tmp_dir):
            os.mkdir(tmp_dir, 0o700)

        for f in self.files_to_keep:
            dest_file = f.strip('/').replace("/", "_")

            # If the file is already there, we might be re-running the migration
            # because it previously crashed. Hence we keep the existing file.
            if os.path.exists(os.path.join(tmp_dir, dest_file)):
                continue

            copy2(f, os.path.join(tmp_dir, dest_file))

    def restore_files_to_keep(self):

        logger.debug("Restoring specific files to keep ...")

        tmp_dir = os.path.join("/tmp/", self.name)

        for f in self.files_to_keep:
            dest_file = f.strip('/').replace("/", "_")
            copy2(os.path.join(tmp_dir, dest_file), f)

    # On some setups, /etc/nginx/nginx.conf got edited. But this file needs
    # to be upgraded because of the way the new module system works for nginx.
    # (in particular, having the line that include the modules at the top)
    #
    # So here, if it got edited, we force the restore of the original conf
    # *before* starting the actual upgrade...
    #
    # An alternative strategy that was attempted was to hold the nginx-common
    # package and have a specific upgrade for it like for fail2ban, but that
    # leads to apt complaining about not being able to upgrade for shitty
    # reasons >.>
    def restore_original_nginx_conf_if_needed(self):
        if "/etc/nginx/nginx.conf" not in manually_modified_files_compared_to_debian_default():
            return

        if not os.path.exists("/etc/nginx/nginx.conf"):
            return

        # If stretch is in the sources.list, we already started migrating on
        # stretch so we don't re-do this
        if " stretch " in read_file("/etc/apt/sources.list"):
            return

        backup_dest = "/home/yunohost.conf/backup/nginx.conf.bkp_before_stretch"

        logger.warning(m18n.n("migration_0003_restoring_origin_nginx_conf",
                              backup_dest=backup_dest))

        os.system("mv /etc/nginx/nginx.conf %s" % backup_dest)

        command = ""
        command += " DEBIAN_FRONTEND=noninteractive"
        command += " APT_LISTCHANGES_FRONTEND=none"
        command += " apt-get"
        command += " --fix-broken --show-upgraded --assume-yes"
        command += ' -o Dpkg::Options::="--force-confmiss"'
        command += " install --reinstall"
        command += " nginx-common"

        logger.debug("Running apt command :\n{}".format(command))

        command += " 2>&1 | tee -a {}".format(self.logfile)

        is_api = msettings.get('interface') == 'api'
        if is_api:
            callbacks = (
                lambda l: logger.info(l.rstrip()),
                lambda l: logger.warning(l.rstrip()),
            )
            call_async_output(command, callbacks, shell=True)
        else:
            # We do this when running from the cli to have the output of the
            # command showing in the terminal, since 'info' channel is only
            # enabled if the user explicitly add --verbose ...
            os.system(command)

    def disable_predicable_interface_names(self):

        # Try to see if currently used interface names are predictable ones or not...
        # If we ain't using "eth0" or "wlan0", assume we are using predictable interface
        # names and therefore they shouldnt be disabled
        network_interfaces = get_network_interfaces().keys()
        if "eth0" not in network_interfaces and "wlan0" not in network_interfaces:
            return

        interfaces_config = read_file("/etc/network/interfaces")
        if "eth0" not in interfaces_config and "wlan0" not in interfaces_config:
            return

        # Disable predictive interface names
        # c.f. https://unix.stackexchange.com/a/338730
        os.system("ln -s /dev/null /etc/systemd/network/99-default.link")
