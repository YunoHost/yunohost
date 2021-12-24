import glob
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output, call_async_output
from moulinette.utils.filesystem import read_file

from yunohost.tools import Migration, tools_update, tools_upgrade
from yunohost.app import unstable_apps
from yunohost.regenconf import manually_modified_files
from yunohost.utils.filesystem import free_space_in_directory
from yunohost.utils.packages import (
    get_ynh_package_version,
    _list_upgradable_apt_packages,
)

logger = getActionLogger("yunohost.migration")


class MyMigration(Migration):

    "Upgrade the system to Debian Buster and Yunohost 4.x"

    mode = "manual"

    def run(self):

        self.check_assertions()

        logger.info(m18n.n("migration_0015_start"))

        #
        # Make sure certificates do not use weak signature hash algorithms (md5, sha1)
        # otherwise nginx will later refuse to start which result in
        # catastrophic situation
        #
        self.validate_and_upgrade_cert_if_necessary()

        #
        # Patch sources.list
        #
        logger.info(m18n.n("migration_0015_patching_sources_list"))
        self.patch_apt_sources_list()
        tools_update(target="system")

        # Tell libc6 it's okay to restart system stuff during the upgrade
        os.system(
            "echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections"
        )

        # Don't send an email to root about the postgresql migration. It should be handled automatically after.
        os.system(
            "echo 'postgresql-common postgresql-common/obsolete-major seen true' | debconf-set-selections"
        )

        #
        # Specific packages upgrades
        #
        logger.info(m18n.n("migration_0015_specific_upgrade"))

        # Update unscd independently, was 0.53-1+yunohost on stretch (custom build of ours) but now it's 0.53-1+b1 on vanilla buster,
        # which for apt appears as a lower version (hence the --allow-downgrades and the hardcoded version number)
        unscd_version = check_output(
            'dpkg -s unscd | grep "^Version: " | cut -d " " -f 2'
        )
        if "yunohost" in unscd_version:
            new_version = check_output(
                "LC_ALL=C apt policy unscd 2>/dev/null | grep -v '\\*\\*\\*' | grep http -B1 | head -n 1 | awk '{print $1}'"
            ).strip()
            if new_version:
                self.apt_install("unscd=%s --allow-downgrades" % new_version)
            else:
                logger.warning("Could not identify which version of unscd to install")

        # Upgrade libpam-modules independently, small issue related to willing to overwrite a file previously provided by Yunohost
        libpammodules_version = check_output(
            'dpkg -s libpam-modules | grep "^Version: " | cut -d " " -f 2'
        )
        if not libpammodules_version.startswith("1.3"):
            self.apt_install('libpam-modules -o Dpkg::Options::="--force-overwrite"')

        #
        # Main upgrade
        #
        logger.info(m18n.n("migration_0015_main_upgrade"))

        apps_packages = self.get_apps_equivs_packages()
        self.hold(apps_packages)
        tools_upgrade(target="system", allow_yunohost_upgrade=False)

        if self.debian_major_version() == 9:
            raise YunohostError("migration_0015_still_on_stretch_after_main_upgrade")

        # Clean the mess
        logger.info(m18n.n("migration_0015_cleaning_up"))
        os.system("apt autoremove --assume-yes")
        os.system("apt clean --assume-yes")

        #
        # Yunohost upgrade
        #
        logger.info(m18n.n("migration_0015_yunohost_upgrade"))
        self.unhold(apps_packages)
        tools_upgrade(target="system")

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

        # Be on stretch (9.x) and yunohost 3.x
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be > 9.x but yunohost package
        # would still be in 3.x...
        if (
            not self.debian_major_version() == 9
            and not self.yunohost_major_version() == 3
        ):
            raise YunohostError("migration_0015_not_stretch")

        # Have > 1 Go free space on /var/ ?
        if free_space_in_directory("/var/") / (1024 ** 3) < 1.0:
            raise YunohostError("migration_0015_not_enough_free_space")

        # Check system is up to date
        # (but we don't if 'stretch' is already in the sources.list ...
        # which means maybe a previous upgrade crashed and we're re-running it)
        if " buster " not in read_file("/etc/apt/sources.list"):
            tools_update(target="system")
            upgradable_system_packages = list(_list_upgradable_apt_packages())
            if upgradable_system_packages:
                raise YunohostError("migration_0015_system_not_fully_up_to_date")

    @property
    def disclaimer(self):

        # Avoid having a super long disclaimer + uncessary check if we ain't
        # on stretch / yunohost 3.x anymore
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be >= 10.x but yunohost package
        # would still be in 3.x...
        if (
            not self.debian_major_version() == 9
            and not self.yunohost_major_version() == 3
        ):
            return None

        # Get list of problematic apps ? I.e. not official or community+working
        problematic_apps = unstable_apps()
        problematic_apps = "".join(["\n    - " + app for app in problematic_apps])

        # Manually modified files ? (c.f. yunohost service regen-conf)
        modified_files = manually_modified_files()
        modified_files = "".join(["\n    - " + f for f in modified_files])

        message = m18n.n("migration_0015_general_warning")

        message = (
            "N.B.: This migration has been tested by the community over the last few months but has only been declared stable recently. If your server hosts critical services and if you are not too confident with debugging possible issues, we recommend you to wait a little bit more while we gather more feedback and polish things up. If on the other hand you are relatively confident with debugging small issues that may arise, you are encouraged to run this migration ;)! You can read about remaining known issues and feedback from the community here: https://forum.yunohost.org/t/12195\n\n"
            + message
        )

        if problematic_apps:
            message += "\n\n" + m18n.n(
                "migration_0015_problematic_apps_warning",
                problematic_apps=problematic_apps,
            )

        if modified_files:
            message += "\n\n" + m18n.n(
                "migration_0015_modified_files", manually_modified_files=modified_files
            )

        return message

    def patch_apt_sources_list(self):

        sources_list = glob.glob("/etc/apt/sources.list.d/*.list")
        sources_list.append("/etc/apt/sources.list")

        # This :
        # - replace single 'stretch' occurence by 'buster'
        # - comments lines containing "backports"
        # - replace 'stretch/updates' by 'strech/updates' (or same with -)
        for f in sources_list:
            command = (
                "sed -i -e 's@ stretch @ buster @g' "
                "-e '/backports/ s@^#*@#@' "
                "-e 's@ stretch/updates @ buster/updates @g' "
                "-e 's@ stretch-@ buster-@g' "
                "{}".format(f)
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
            os.system("apt-mark hold {}".format(package))

    def unhold(self, packages):
        for package in packages:
            os.system("apt-mark unhold {}".format(package))

    def apt_install(self, cmd):
        def is_relevant(line):
            return "Reading database ..." not in line.rstrip()

        callbacks = (
            lambda l: logger.info("+ " + l.rstrip() + "\r")
            if is_relevant(l)
            else logger.debug(l.rstrip() + "\r"),
            lambda l: logger.warning(l.rstrip()),
        )

        cmd = (
            "LC_ALL=C DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt install --quiet -o=Dpkg::Use-Pty=0 --fix-broken --assume-yes "
            + cmd
        )

        logger.debug("Running: %s" % cmd)

        call_async_output(cmd, callbacks, shell=True)

    def validate_and_upgrade_cert_if_necessary(self):

        active_certs = set(
            check_output("grep -roh '/.*crt.pem' /etc/nginx/").split("\n")
        )

        cmd = "LC_ALL=C openssl x509 -in %s -text -noout | grep -i 'Signature Algorithm:' | awk '{print $3}' | uniq"

        default_crt = "/etc/yunohost/certs/yunohost.org/crt.pem"
        default_key = "/etc/yunohost/certs/yunohost.org/key.pem"
        default_signature = (
            check_output(cmd % default_crt) if default_crt in active_certs else None
        )
        if default_signature is not None and (
            default_signature.startswith("md5") or default_signature.startswith("sha1")
        ):
            logger.warning(
                "%s is using a pretty old certificate incompatible with newer versions of nginx ... attempting to regenerate a fresh one"
                % default_crt
            )

            os.system("mv {} {}.old".format(default_crt, default_crt))
            os.system("mv {} {}.old".format(default_key, default_key))
            ret = os.system("/usr/share/yunohost/hooks/conf_regen/02-ssl init")

            if ret != 0 or not os.path.exists(default_crt):
                logger.error("Upgrading the certificate failed ... reverting")
                os.system("mv {}.old {}".format(default_crt, default_crt))
                os.system("mv {}.old {}".format(default_key, default_key))

        signatures = {cert: check_output(cmd % cert) for cert in active_certs}

        def cert_is_weak(cert):
            sig = signatures[cert]
            return sig.startswith("md5") or sig.startswith("sha1")

        weak_certs = [cert for cert in signatures.keys() if cert_is_weak(cert)]
        if weak_certs:
            raise YunohostError(
                "migration_0015_weak_certs", certs=", ".join(weak_certs)
            )
