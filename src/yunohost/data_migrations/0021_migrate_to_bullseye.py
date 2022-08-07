import glob
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output, call_async_output
from moulinette.utils.filesystem import read_file, rm, write_to_file

from yunohost.tools import (
    Migration,
    tools_update,
    tools_upgrade,
    _apt_log_line_is_relevant,
)
from yunohost.app import unstable_apps
from yunohost.regenconf import manually_modified_files, _force_clear_hashes
from yunohost.utils.filesystem import free_space_in_directory
from yunohost.utils.packages import (
    get_ynh_package_version,
    _list_upgradable_apt_packages,
)
from yunohost.service import _get_services, _save_services

logger = getActionLogger("yunohost.migration")

N_CURRENT_DEBIAN = 10
N_CURRENT_YUNOHOST = 4

N_NEXT_DEBAN = 11
N_NEXT_YUNOHOST = 11

VENV_REQUIREMENTS_SUFFIX = ".requirements_backup_for_bullseye_upgrade.txt"


def _get_all_venvs(dir, level=0, maxlevel=3):
    """
        Returns the list of all python virtual env directories recursively

        Arguments:
            dir - the directory to scan in
            maxlevel - the depth of the recursion
            level - do not edit this, used as an iterator
    """
    # Using os functions instead of glob, because glob doesn't support hidden folders, and we need recursion with a fixed depth
    result = []
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isdir(path):
            activatepath = os.path.join(path,"bin", "activate")
            if os.path.isfile(activatepath):
                content = read_file(activatepath)
                if ("VIRTUAL_ENV" in content) and ("PYTHONHOME" in content):
                    result.append(path)
                    continue
            if level < maxlevel:
                result += _get_all_venvs(path, level=level + 1)
    return result


def _backup_pip_freeze_for_python_app_venvs():
    """
        Generate a requirements file for all python virtual env located inside /opt/ and /var/www/
    """

    venvs = _get_all_venvs("/opt/") + _get_all_venvs("/var/www/")
    for venv in venvs:
        # Generate a requirements file from venv
        os.system(f"{venv}/bin/pip freeze > {venv}{VENV_REQUIREMENTS_SUFFIX}")


class MyMigration(Migration):

    "Upgrade the system to Debian Bullseye and Yunohost 11.x"

    mode = "manual"

    def run(self):

        self.check_assertions()

        logger.info(m18n.n("migration_0021_start"))

        #
        # Add new apt .deb signing key
        #

        new_apt_key = "https://forge.yunohost.org/yunohost_bullseye.asc"
        check_output(f"wget -O- {new_apt_key} -q | apt-key add -qq -")

        #
        # Patch sources.list
        #
        logger.info(m18n.n("migration_0021_patching_sources_list"))
        self.patch_apt_sources_list()

        # Force add sury if it's not there yet
        # This is to solve some weird issue with php-common breaking php7.3-common,
        # hence breaking many php7.3-deps
        # hence triggering some dependency conflict (or foobar-ynh-deps uninstall)
        # Adding it there shouldnt be a big deal - Yunohost 11.x does add it
        # through its regen conf anyway.
        if not os.path.exists("/etc/apt/sources.list.d/extra_php_version.list"):
            open("/etc/apt/sources.list.d/extra_php_version.list", "w").write(
                "deb https://packages.sury.org/php/ bullseye main"
            )
            os.system(
                'wget --timeout 900 --quiet "https://packages.sury.org/php/apt.gpg" --output-document=- | gpg --dearmor >"/etc/apt/trusted.gpg.d/extra_php_version.gpg"'
            )

        #
        # Get requirements of the different venvs from python apps
        #

        _backup_pip_freeze_for_python_app_venvs()

        #
        # Run apt update
        #

        tools_update(target="system")

        # Tell libc6 it's okay to restart system stuff during the upgrade
        os.system(
            "echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections"
        )

        # Do not restart nginx during the upgrade of nginx-common and nginx-extras ...
        # c.f. https://manpages.debian.org/bullseye/init-system-helpers/deb-systemd-invoke.1p.en.html
        # and zcat /usr/share/doc/init-system-helpers/README.policy-rc.d.gz
        # and the code inside /usr/bin/deb-systemd-invoke to see how it calls /usr/sbin/policy-rc.d ...
        # and also invoke-rc.d ...
        write_to_file(
            "/usr/sbin/policy-rc.d",
            '#!/bin/bash\n[[ "$1" =~ "nginx" ]] && [[ "$2" == "restart" ]] && exit 101 || exit 0',
        )
        os.system("chmod +x /usr/sbin/policy-rc.d")

        # Don't send an email to root about the postgresql migration. It should be handled automatically after.
        os.system(
            "echo 'postgresql-common postgresql-common/obsolete-major seen true' | debconf-set-selections"
        )

        #
        # Patch yunohost conflicts
        #
        logger.info(m18n.n("migration_0021_patch_yunohost_conflicts"))

        self.patch_yunohost_conflicts()

        #
        # Specific tweaking to get rid of custom my.cnf and use debian's default one
        # (my.cnf is actually a symlink to mariadb.cnf)
        #

        _force_clear_hashes(["/etc/mysql/my.cnf"])
        rm("/etc/mysql/mariadb.cnf", force=True)
        rm("/etc/mysql/my.cnf", force=True)
        ret = self.apt_install(
            "mariadb-common --reinstall -o Dpkg::Options::='--force-confmiss'"
        )
        if ret != 0:
            raise YunohostError("Failed to reinstall mariadb-common ?", raw_msg=True)

        #
        # /usr/share/yunohost/yunohost-config/ssl/yunoCA -> /usr/share/yunohost/ssl
        #
        if os.path.exists("/usr/share/yunohost/yunohost-config/ssl/yunoCA"):
            os.system(
                "mv /usr/share/yunohost/yunohost-config/ssl/yunoCA /usr/share/yunohost/ssl"
            )
            rm("/usr/share/yunohost/yunohost-config", recursive=True, force=True)

        #
        # /home/yunohost.conf -> /var/cache/yunohost/regenconf
        #
        if os.path.exists("/home/yunohost.conf"):
            os.system("mv /home/yunohost.conf /var/cache/yunohost/regenconf")
            rm("/home/yunohost.conf", recursive=True, force=True)

        # Remove legacy postgresql service record added by helpers,
        # will now be dynamically handled by the core in bullseye
        services = _get_services()
        if "postgresql" in services:
            del services["postgresql"]
            _save_services(services)

        #
        # Main upgrade
        #
        logger.info(m18n.n("migration_0021_main_upgrade"))

        apps_packages = self.get_apps_equivs_packages()
        self.hold(apps_packages)
        tools_upgrade(target="system", allow_yunohost_upgrade=False)

        if self.debian_major_version() == N_CURRENT_DEBIAN:
            raise YunohostError("migration_0021_still_on_buster_after_main_upgrade")

        # Force explicit install of php7.4-fpm and other old 'default' dependencies
        # that are now only in Recommends
        #
        # Also, we need to install php7.4 equivalents of other php7.3 dependencies.
        # For example, Nextcloud may depend on php7.3-zip, and after the php pool migration
        # to autoupgrade Nextcloud to 7.4, it will need the php7.4-zip to work.
        # The following list is based on an ad-hoc analysis of php deps found in the
        # app ecosystem, with a known equivalent on php7.4.
        #
        # This is kinda a dirty hack as it doesnt properly update the *-ynh-deps virtual packages
        # with the proper list of dependencies, and the dependencies install this way
        # will get flagged as 'manually installed'.
        #
        # We'll probably want to do something during the Bullseye->Bookworm migration to re-flag
        # these as 'auto' so they get autoremoved if not needed anymore.
        # Also hopefully by then we'll have manifestv2 (maybe) and will be able to use
        # the apt resource mecanism to regenerate the *-ynh-deps virtual packages ;)

        php73packages_suffixes = [
            "apcu",
            "bcmath",
            "bz2",
            "dom",
            "gmp",
            "igbinary",
            "imagick",
            "imap",
            "mbstring",
            "memcached",
            "mysqli",
            "mysqlnd",
            "pgsql",
            "redis",
            "simplexml",
            "soap",
            "sqlite3",
            "ssh2",
            "tidy",
            "xml",
            "xmlrpc",
            "xsl",
            "zip",
        ]

        cmd = (
            "apt show '*-ynh-deps' 2>/dev/null"
            "  | grep Depends"
            f" | grep -o -E \"php7.3-({'|'.join(php73packages_suffixes)})\""
            "  | sort | uniq"
            "  | sed 's/php7.3/php7.4/g'"
            "  || true"
        )

        basephp74packages_to_install = [
            "php7.4-fpm",
            "php7.4-common",
            "php7.4-ldap",
            "php7.4-intl",
            "php7.4-mysql",
            "php7.4-gd",
            "php7.4-curl",
            "php-php-gettext",
        ]

        php74packages_to_install = basephp74packages_to_install + [
            f.strip() for f in check_output(cmd).split("\n") if f.strip()
        ]

        ret = self.apt_install(
            f"{' '.join(php74packages_to_install)} "
            "$(dpkg --list | grep ynh-deps | awk '{print $2}') "
            "-o Dpkg::Options::='--force-confmiss'"
        )
        if ret != 0:
            raise YunohostError(
                "Failed to force the install of php dependencies ?", raw_msg=True
            )

        # Clean the mess
        logger.info(m18n.n("migration_0021_cleaning_up"))
        os.system("apt autoremove --assume-yes")
        os.system("apt clean --assume-yes")

        #
        # Yunohost upgrade
        #
        logger.info(m18n.n("migration_0021_yunohost_upgrade"))

        self.unhold(apps_packages)

        cmd = "LC_ALL=C"
        cmd += " DEBIAN_FRONTEND=noninteractive"
        cmd += " APT_LISTCHANGES_FRONTEND=none"
        cmd += " apt dist-upgrade "
        cmd += " --quiet -o=Dpkg::Use-Pty=0 --fix-broken --dry-run"
        cmd += " | grep -q 'ynh-deps'"

        logger.info("Simulating upgrade...")
        if os.system(cmd) == 0:
            raise YunohostError(
                "The upgrade cannot be completed, because some app dependencies would need to be removed?",
                raw_msg=True,
            )

        postupgradecmds = f"apt-mark auto {' '.join(basephp74packages_to_install)}\n"
        postupgradecmds += "rm -f /usr/sbin/policy-rc.d\n"
        postupgradecmds += "echo 'Restarting nginx...' >&2\n"
        postupgradecmds += "systemctl restart nginx\n"

        tools_upgrade(target="system", postupgradecmds=postupgradecmds)


    def debian_major_version(self):
        # The python module "platform" and lsb_release are not reliable because
        # on some setup, they may still return Release=9 even after upgrading to
        # buster ... (Apparently this is related to OVH overriding some stuff
        # with /etc/lsb-release for instance -_-)
        # Instead, we rely on /etc/os-release which should be the raw info from
        # the distribution...
        return int(
            check_output(
                "grep VERSION_ID /etc/os-release | head -n 1 | tr '\"' ' ' | cut -d ' ' -f2"
            )
        )

    def yunohost_major_version(self):
        return int(get_ynh_package_version("yunohost")["version"].split(".")[0])

    def check_assertions(self):

        # Be on buster (10.x) and yunohost 4.x
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be > 9.x but yunohost package
        # would still be in 3.x...
        if (
            not self.debian_major_version() == N_CURRENT_DEBIAN
            and not self.yunohost_major_version() == N_CURRENT_YUNOHOST
        ):
            raise YunohostError("migration_0021_not_buster")

        # Have > 1 Go free space on /var/ ?
        if free_space_in_directory("/var/") / (1024 ** 3) < 1.0:
            raise YunohostError("migration_0021_not_enough_free_space")

        # Check system is up to date
        # (but we don't if 'bullseye' is already in the sources.list ...
        # which means maybe a previous upgrade crashed and we're re-running it)
        if os.path.exists("/etc/apt/sources.list") and " bullseye " not in read_file("/etc/apt/sources.list"):
            tools_update(target="system")
            upgradable_system_packages = list(_list_upgradable_apt_packages())
            upgradable_system_packages = [package["name"] for package in upgradable_system_packages]
            upgradable_system_packages = set(upgradable_system_packages)
            # Lime2 have hold packages to avoid ethernet instability
            # See https://github.com/YunoHost/arm-images/commit/b4ef8c99554fd1a122a306db7abacc4e2f2942df
            lime2_hold_packages = set([
                "armbian-firmware",
                "armbian-bsp-cli-lime2",
                "linux-dtb-current-sunxi",
                "linux-image-current-sunxi",
                "linux-u-boot-lime2-current",
                "linux-image-next-sunxi"
            ])
            if upgradable_system_packages - lime2_hold_packages:
                raise YunohostError("migration_0021_system_not_fully_up_to_date")

    @property
    def disclaimer(self):

        # Avoid having a super long disclaimer + uncessary check if we ain't
        # on buster / yunohost 4.x anymore
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be >= 10.x but yunohost package
        # would still be in 4.x...
        if (
            not self.debian_major_version() == N_CURRENT_DEBIAN
            and not self.yunohost_major_version() == N_CURRENT_YUNOHOST
        ):
            return None

        # Get list of problematic apps ? I.e. not official or community+working
        problematic_apps = unstable_apps()
        problematic_apps = "".join(["\n    - " + app for app in problematic_apps])

        # Manually modified files ? (c.f. yunohost service regen-conf)
        modified_files = manually_modified_files()
        modified_files = "".join(["\n    - " + f for f in modified_files])

        message = m18n.n("migration_0021_general_warning")

        # FIXME: update this message with updated topic link once we release the migration as stable
        message = (
           "N.B.: **THIS MIGRATION IS STILL IN BETA-STAGE** ! If your server hosts critical services and if you are not too confident with debugging possible issues, we recommend you to wait a little bit more while we gather more feedback and polish things up. If on the other hand you are relatively confident with debugging small issues that may arise, you are encouraged to run this migration ;)! You can read and share feedbacks on this forum thread: https://forum.yunohost.org/t/18531\n\n"
           + message
        )
        # message = (
        #    "N.B.: This migration has been tested by the community over the last few months but has only been declared stable recently. If your server hosts critical services and if you are not too confident with debugging possible issues, we recommend you to wait a little bit more while we gather more feedback and polish things up. If on the other hand you are relatively confident with debugging small issues that may arise, you are encouraged to run this migration ;)! You can read about remaining known issues and feedback from the community here: https://forum.yunohost.org/t/12195\n\n"
        #    + message
        # )

        if problematic_apps:
            message += "\n\n" + m18n.n(
                "migration_0021_problematic_apps_warning",
                problematic_apps=problematic_apps,
            )

        if modified_files:
            message += "\n\n" + m18n.n(
                "migration_0021_modified_files", manually_modified_files=modified_files
            )

        return message

    def patch_apt_sources_list(self):

        sources_list = glob.glob("/etc/apt/sources.list.d/*.list")
        if os.path.exists("/etc/apt/sources.list"):
            sources_list.append("/etc/apt/sources.list")

        # This :
        # - replace single 'buster' occurence by 'bulleye'
        # - comments lines containing "backports"
        # - replace 'buster/updates' by 'bullseye/updates' (or same with -)
        # Special note about the security suite:
        # https://www.debian.org/releases/bullseye/amd64/release-notes/ch-information.en.html#security-archive
        for f in sources_list:
            command = (
                f"sed -i {f} "
                "-e 's@ buster @ bullseye @g' "
                "-e '/backports/ s@^#*@#@' "
                "-e 's@ buster/updates @ bullseye-security @g' "
                "-e 's@ buster-@ bullseye-@g' "
            )
            os.system(command)

    def get_apps_equivs_packages(self):

        command = (
            "dpkg --get-selections"
            " | grep -v deinstall"
            " | awk '{print $1}'"
            " | { grep 'ynh-deps$' || true; }"
        )

        output = check_output(command)

        return output.split("\n") if output else []

    def hold(self, packages):
        for package in packages:
            os.system(f"apt-mark hold {package}")

    def unhold(self, packages):
        for package in packages:
            os.system(f"apt-mark unhold {package}")

    def apt_install(self, cmd):
        def is_relevant(line):
            return "Reading database ..." not in line.rstrip()

        callbacks = (
            lambda l: logger.info("+ " + l.rstrip() + "\r")
            if _apt_log_line_is_relevant(l)
            else logger.debug(l.rstrip() + "\r"),
            lambda l: logger.warning(l.rstrip())
            if _apt_log_line_is_relevant(l)
            else logger.debug(l.rstrip()),
        )

        cmd = (
            "LC_ALL=C DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt install --quiet -o=Dpkg::Use-Pty=0 --fix-broken --assume-yes "
            + cmd
        )

        logger.debug("Running: %s" % cmd)

        return call_async_output(cmd, callbacks, shell=True)

    def patch_yunohost_conflicts(self):
        #
        # This is a super dirty hack to remove the conflicts from yunohost's debian/control file
        # Those conflicts are there to prevent mistakenly upgrading critical packages
        # such as dovecot, postfix, nginx, openssl, etc... usually related to mistakenly
        # using backports etc.
        #
        # The hack consists in savagely removing the conflicts directly in /var/lib/dpkg/status
        #

        # We only patch the conflict if we're on yunohost 4.x
        if self.yunohost_major_version() != N_CURRENT_YUNOHOST:
            return

        conflicts = check_output("dpkg-query -s yunohost | grep '^Conflicts:'").strip()
        if conflicts:
            # We want to keep conflicting with apache/bind9 tho
            new_conflicts = "Conflicts: apache2, bind9"

            command = (
                f"sed -i /var/lib/dpkg/status -e 's@{conflicts}@{new_conflicts}@g'"
            )
            logger.debug(f"Running: {command}")
            os.system(command)
