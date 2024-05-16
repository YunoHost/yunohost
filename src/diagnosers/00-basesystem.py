#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import os
import json
import subprocess
from typing import List

from moulinette.utils import log
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file, read_json, write_to_json
from yunohost.diagnosis import Diagnoser
from yunohost.utils.system import (
    ynh_packages_version,
    system_virt,
    system_arch,
)

logger = log.getActionLogger("yunohost.diagnosis")


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies: List[str] = []

    def run(self):
        virt = system_virt()
        if virt.lower() == "none":
            virt = "bare-metal"

        # Detect arch
        arch = system_arch()
        hardware = dict(
            meta={"test": "hardware"},
            status="INFO",
            data={"virt": virt, "arch": arch},
            summary="diagnosis_basesystem_hardware",
        )

        # Also possibly the board / hardware name
        if os.path.exists("/proc/device-tree/model"):
            model = read_file("/proc/device-tree/model").strip().replace("\x00", "")
            hardware["data"]["model"] = model
            hardware["details"] = ["diagnosis_basesystem_hardware_model"]
        elif os.path.exists("/sys/devices/virtual/dmi/id/sys_vendor"):
            model = read_file("/sys/devices/virtual/dmi/id/sys_vendor").strip()
            if os.path.exists("/sys/devices/virtual/dmi/id/product_name"):
                product_name = read_file(
                    "/sys/devices/virtual/dmi/id/product_name"
                ).strip()
                model = f"{model} {product_name}"
            hardware["data"]["model"] = model
            hardware["details"] = ["diagnosis_basesystem_hardware_model"]

        yield hardware

        # Kernel version
        kernel_version = read_file("/proc/sys/kernel/osrelease").strip()
        yield dict(
            meta={"test": "kernel"},
            data={"kernel_version": kernel_version},
            status="INFO",
            summary="diagnosis_basesystem_kernel",
        )

        # Debian release
        debian_version = read_file("/etc/debian_version").strip()
        yield dict(
            meta={"test": "host"},
            data={"debian_version": debian_version},
            status="INFO",
            summary="diagnosis_basesystem_host",
        )

        # Yunohost packages versions
        # We check if versions are consistent (e.g. all 3.6 and not 3 packages with 3.6 and the other with 3.5)
        # This is a classical issue for upgrades that failed in the middle
        # (or people upgrading half of the package because they did 'apt upgrade' instead of 'dist-upgrade')
        # Here, ynh_core_version is for example "3.5.4.12", so [:3] is "3.5" and we check it's the same for all packages
        ynh_packages = ynh_packages_version()
        ynh_core_version = ynh_packages["yunohost"]["version"]
        consistent_versions = all(
            infos["version"][:3] == ynh_core_version[:3]
            for infos in ynh_packages.values()
        )
        ynh_version_details = [
            (
                "diagnosis_basesystem_ynh_single_version",
                {
                    "package": package,
                    "version": infos["version"],
                    "repo": infos["repo"],
                },
            )
            for package, infos in ynh_packages.items()
        ]

        yield dict(
            meta={"test": "ynh_versions"},
            data={
                "main_version": ynh_core_version,
                "repo": ynh_packages["yunohost"]["repo"],
            },
            status="INFO" if consistent_versions else "ERROR",
            summary=(
                "diagnosis_basesystem_ynh_main_version"
                if consistent_versions
                else "diagnosis_basesystem_ynh_inconsistent_versions"
            ),
            details=ynh_version_details,
        )

        if self.is_vulnerable_to_meltdown():
            yield dict(
                meta={"test": "meltdown"},
                status="ERROR",
                summary="diagnosis_security_vulnerable_to_meltdown",
                details=["diagnosis_security_vulnerable_to_meltdown_details"],
            )

        bad_sury_packages = list(self.bad_sury_packages())
        if bad_sury_packages:
            cmd_to_fix = "apt install --allow-downgrades " + " ".join(
                [f"{package}={version}" for package, version in bad_sury_packages]
            )
            yield dict(
                meta={"test": "packages_from_sury"},
                data={"cmd_to_fix": cmd_to_fix},
                status="WARNING",
                summary="diagnosis_package_installed_from_sury",
                details=["diagnosis_package_installed_from_sury_details"],
            )

        if self.backports_in_sources_list():
            yield dict(
                meta={"test": "backports_in_sources_list"},
                status="WARNING",
                summary="diagnosis_backports_in_sources_list",
            )

        # Using yunohost testing channel
        if (
            os.system(
                "grep -q '^\\s*deb\\s*.*yunohost.org.*\\stesting' /etc/apt/sources.list /etc/apt/sources.list.d/*"
            )
            == 0
        ):
            yield dict(
                meta={"test": "apt_yunohost_channel"},
                status="WARNING",
                summary="diagnosis_using_yunohost_testing",
                details=["diagnosis_using_yunohost_testing_details"],
            )

        # Apt being mapped to 'stable' (instead of 'buster/bullseye/bookworm/trixie/...')
        # will cause the machine to spontaenously upgrade everything as soon as next debian is released ...
        # Note that we grep this from the policy for libc6, because it's hard to know exactly which apt repo
        # is configured (it may not be simply debian.org)
        if (
            os.system(
                "apt policy libc6 2>/dev/null | grep '^\\s*500' | awk '{print $3}' | tr '/' ' ' | awk '{print $1}' | grep -q 'stable'"
            )
            == 0
        ):
            yield dict(
                meta={"test": "apt_debian_codename"},
                status="WARNING",
                summary="diagnosis_using_stable_codename",
                details=["diagnosis_using_stable_codename_details"],
            )

        if self.number_of_recent_auth_failure() > 750:
            yield dict(
                meta={"test": "high_number_auth_failure"},
                status="WARNING",
                summary="diagnosis_high_number_auth_failures",
            )

        rfkill_wifi = self.rfkill_wifi()
        if len(rfkill_wifi) > 0:
            yield dict(
                meta={"test": "rfkill_wifi"},
                status="ERROR",
                summary="diagnosis_rfkill_wifi",
                details=["diagnosis_rfkill_wifi_details"],
                data={"rfkill_wifi_error": rfkill_wifi}
            )

    def bad_sury_packages(self):
        packages_to_check = ["openssl", "libssl1.1", "libssl-dev"]
        for package in packages_to_check:
            cmd = "dpkg --list | grep '^ii' | grep gbp | grep -q -w %s" % package
            # If version currently installed is not from sury, nothing to report
            if os.system(cmd) != 0:
                continue

            cmd = (
                "LC_ALL=C apt policy %s 2>&1 | grep http -B1 | tr -d '*' | grep '+deb' | grep -v 'gbp' | head -n 1 | awk '{print $1}'"
                % package
            )
            version_to_downgrade_to = check_output(cmd)
            yield (package, version_to_downgrade_to)

    def backports_in_sources_list(self):
        cmd = "grep -q -nr '^ *deb .*-backports' /etc/apt/sources.list*"
        return os.system(cmd) == 0

    def number_of_recent_auth_failure(self):
        # Those syslog facilities correspond to auth and authpriv
        # c.f. https://unix.stackexchange.com/a/401398
        # and https://wiki.archlinux.org/title/Systemd/Journal#Facility
        cmd = "journalctl -q SYSLOG_FACILITY=10 SYSLOG_FACILITY=4 --since '1day ago' | grep 'authentication failure' | wc -l"

        n_failures = check_output(cmd)
        try:
            return int(n_failures)
        except Exception:
            logger.warning(
                "Failed to parse number of recent auth failures, expected an int, got '%s'"
                % n_failures
            )
            return -1

    def is_vulnerable_to_meltdown(self):
        # meltdown CVE: https://security-tracker.debian.org/tracker/CVE-2017-5754

        # We use a cache file to avoid re-running the script so many times,
        # which can be expensive (up to around 5 seconds on ARM)
        # and make the admin appear to be slow (c.f. the calls to diagnosis
        # from the webadmin)
        #
        # The cache is in /tmp and shall disappear upon reboot
        # *or* we compare it to dpkg.log modification time
        # such that it's re-ran if there was package upgrades
        # (e.g. from yunohost)
        cache_file = "/tmp/yunohost-meltdown-diagnosis"
        dpkg_log = "/var/log/dpkg.log"
        if os.path.exists(cache_file):
            if not os.path.exists(dpkg_log) or os.path.getmtime(
                cache_file
            ) > os.path.getmtime(dpkg_log):
                logger.debug(
                    "Using cached results for meltdown checker, from %s" % cache_file
                )
                return read_json(cache_file)[0]["VULNERABLE"]

        # script taken from https://github.com/speed47/spectre-meltdown-checker
        # script commit id is store directly in the script
        SCRIPT_PATH = "/usr/lib/python3/dist-packages/yunohost/vendor/spectre-meltdown-checker/spectre-meltdown-checker.sh"

        # '--variant 3' corresponds to Meltdown
        # example output from the script:
        # [{"NAME":"MELTDOWN","CVE":"CVE-2017-5754","VULNERABLE":false,"INFOS":"PTI mitigates the vulnerability"}]
        try:
            logger.debug("Running meltdown vulnerability checker")
            call = subprocess.Popen(
                "bash %s --batch json --variant 3" % SCRIPT_PATH,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # TODO / FIXME : here we are ignoring error messages ...
            # in particular on RPi2 and other hardware, the script complains about
            # "missing some kernel info (see -v), accuracy might be reduced"
            # Dunno what to do about that but we probably don't want to harass
            # users with this warning ...
            output, _ = call.communicate()
            output = output.decode()
            assert call.returncode in (0, 2, 3), "Return code: %s" % call.returncode

            # If there are multiple lines, sounds like there was some messages
            # in stdout that are not json >.> ... Try to get the actual json
            # stuff which should be the last line
            output = output.strip()
            if "\n" in output:
                logger.debug("Original meltdown checker output : %s" % output)
                output = output.split("\n")[-1]

            CVEs = json.loads(output)
            assert len(CVEs) == 1
            assert CVEs[0]["NAME"] == "MELTDOWN"
        except Exception as e:
            import traceback

            traceback.print_exc()
            logger.warning(
                "Something wrong happened when trying to diagnose Meltdown vunerability, exception: %s"
                % e
            )
            raise Exception("Command output for failed meltdown check: '%s'" % output)

        logger.debug(
            "Writing results from meltdown checker to cache file, %s" % cache_file
        )
        write_to_json(cache_file, CVEs)
        return CVEs[0]["VULNERABLE"]

    def rfkill_wifi(self):
        if os.path.isfile("/etc/profile.d/wifi-check.sh"):
            cmd = "bash /etc/profile.d/wifi-check.sh"
            return check_output(cmd)
