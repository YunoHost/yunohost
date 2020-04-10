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
        # Gotta have this "|| true" because it systemd-detect-virt return 'none'
        # with an error code on bare metal ~.~
        virt = check_output("systemd-detect-virt || true", shell=True).strip()
        if virt.lower() == "none":
            virt = "bare-metal"

        # Detect arch
        arch = check_output("dpkg --print-architecture").strip()
        hardware = dict(meta={"test": "hardware"},
                        status="INFO",
                        data={"virt": virt, "arch": arch},
                        summary="diagnosis_basesystem_hardware")

        # Also possibly the board name
        if os.path.exists("/proc/device-tree/model"):
            model = read_file('/proc/device-tree/model').strip()
            hardware["data"]["model"] = model
            hardware["details"] = ["diagnosis_basesystem_hardware_board"]

        yield hardware

        # Kernel version
        kernel_version = read_file('/proc/sys/kernel/osrelease').strip()
        yield dict(meta={"test": "kernel"},
                   data={"kernel_version": kernel_version},
                   status="INFO",
                   summary="diagnosis_basesystem_kernel")

        # Debian release
        debian_version = read_file("/etc/debian_version").strip()
        yield dict(meta={"test": "host"},
                   data={"debian_version": debian_version},
                   status="INFO",
                   summary="diagnosis_basesystem_host")

        # Yunohost packages versions
        # We check if versions are consistent (e.g. all 3.6 and not 3 packages with 3.6 and the other with 3.5)
        # This is a classical issue for upgrades that failed in the middle
        # (or people upgrading half of the package because they did 'apt upgrade' instead of 'dist-upgrade')
        # Here, ynh_core_version is for example "3.5.4.12", so [:3] is "3.5" and we check it's the same for all packages
        ynh_packages = ynh_packages_version()
        ynh_core_version = ynh_packages["yunohost"]["version"]
        consistent_versions = all(infos["version"][:3] == ynh_core_version[:3] for infos in ynh_packages.values())
        ynh_version_details = [("diagnosis_basesystem_ynh_single_version",
                                {"package":package,
                                 "version": infos["version"],
                                 "repo": infos["repo"]}
                               )
                               for package, infos in ynh_packages.items()]

        yield dict(meta={"test": "ynh_versions"},
                   data={"main_version": ynh_core_version, "repo": ynh_packages["yunohost"]["repo"]},
                   status="INFO" if consistent_versions else "ERROR",
                   summary="diagnosis_basesystem_ynh_main_version" if consistent_versions else "diagnosis_basesystem_ynh_inconsistent_versions",
                   details=ynh_version_details)


def main(args, env, loggers):
    return BaseSystemDiagnoser(args, env, loggers).diagnose()
