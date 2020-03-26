#!/usr/bin/env python

import os

from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file
from yunohost.diagnosis import Diagnoser
from yunohost.utils.packages import ynh_packages_version


class BaseSystemDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600 * 24
    dependencies = []

    def run(self):

        # Detect virt technology (if not bare metal) and arch
        # Also possibly the board name
        virt = check_output("systemd-detect-virt").strip() or "bare-metal"
        arch = check_output("dpkg --print-architecture").strip()
        hardware = dict(meta={"test": "hardware"},
                        status="INFO",
                        data={"virt": virt, "arch": arch},
                        summary=("diagnosis_basesystem_hardware", {"virt": virt, "arch": arch}))
        if os.path.exists("/proc/device-tree/model"):
            model = read_file('/proc/device-tree/model').strip()
            hardware["data"]["board"] = model
            hardware["details"] = [("diagnosis_basesystem_hardware_board", (model,))]

        yield hardware

        # Kernel version
        kernel_version = read_file('/proc/sys/kernel/osrelease').strip()
        yield dict(meta={"test": "kernel"},
                   status="INFO",
                   summary=("diagnosis_basesystem_kernel", {"kernel_version": kernel_version}))

        # Debian release
        debian_version = read_file("/etc/debian_version").strip()
        yield dict(meta={"test": "host"},
                   status="INFO",
                   summary=("diagnosis_basesystem_host", {"debian_version": debian_version}))

        # Yunohost packages versions
        ynh_packages = ynh_packages_version()
        # We check if versions are consistent (e.g. all 3.6 and not 3 packages with 3.6 and the other with 3.5)
        # This is a classical issue for upgrades that failed in the middle
        # (or people upgrading half of the package because they did 'apt upgrade' instead of 'dist-upgrade')
        # Here, ynh_core_version is for example "3.5.4.12", so [:3] is "3.5" and we check it's the same for all packages
        ynh_core_version = ynh_packages["yunohost"]["version"]
        consistent_versions = all(infos["version"][:3] == ynh_core_version[:3] for infos in ynh_packages.values())
        ynh_version_details = [("diagnosis_basesystem_ynh_single_version", (package, infos["version"], infos["repo"]))
                               for package, infos in ynh_packages.items()]

        if consistent_versions:
            yield dict(meta={"test": "ynh_versions"},
                       data={"main_version": ynh_core_version, "repo": ynh_packages["yunohost"]["repo"]},
                       status="INFO",
                       summary=("diagnosis_basesystem_ynh_main_version",
                                {"main_version": ynh_core_version,
                                 "repo": ynh_packages["yunohost"]["repo"]}),
                       details=ynh_version_details)
        else:
            yield dict(meta={"test": "ynh_versions"},
                       data={"main_version": ynh_core_version, "repo": ynh_packages["yunohost"]["repo"]},
                       status="ERROR",
                       summary=("diagnosis_basesystem_ynh_inconsistent_versions", {}),
                       details=ynh_version_details)


def main(args, env, loggers):
    return BaseSystemDiagnoser(args, env, loggers).diagnose()
