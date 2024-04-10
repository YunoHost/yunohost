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
import re
import os
import logging

from moulinette.utils.process import check_output
from yunohost.utils.error import YunohostError

logger = logging.getLogger("yunohost.utils.packages")

YUNOHOST_PACKAGES = ["yunohost", "yunohost-admin", "moulinette", "ssowat"]


def debian_version():
    if debian_version.cache is None:
        debian_version.cache = check_output(
            'grep "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2'
        )
    return debian_version.cache


def debian_version_id():
    if debian_version_id.cache is None:
        debian_version_id.cache = check_output(
            'grep "^VERSION_ID=" /etc/os-release 2>/dev/null | cut -d= -f2'
        ).strip('"')
    return debian_version_id.cache


def system_arch():
    if system_arch.cache is None:
        system_arch.cache = check_output("dpkg --print-architecture 2>/dev/null")
    return system_arch.cache


def system_virt():
    """
    Returns the output of systemd-detect-virt (so e.g. 'none' or 'lxc' or ...)
    You can check the man of the command to have a list of possible outputs...
    """
    # Detect virt technology (if not bare metal) and arch
    # Gotta have this "|| true" because it systemd-detect-virt return 'none'
    # with an error code on bare metal ~.~
    if system_virt.cache is None:
        system_virt.cache = check_output("systemd-detect-virt 2>/dev/null || true")
    return system_virt.cache


debian_version.cache = None
debian_version_id.cache = None
system_arch.cache = None
system_virt.cache = None


def free_space_in_directory(dirpath):
    stat = os.statvfs(dirpath)
    return stat.f_frsize * stat.f_bavail


def space_used_by_directory(dirpath, follow_symlinks=True):
    if not follow_symlinks:
        du_output = check_output(["du", "-sb", dirpath], shell=False)
        return int(du_output.split()[0])

    stat = os.statvfs(dirpath)
    return (
        stat.f_frsize * stat.f_blocks
    )  # FIXME : this doesnt do what the function name suggest this does ...


def human_to_binary(size: str) -> int:
    symbols = ("K", "M", "G", "T", "P", "E", "Z", "Y")
    factor = {}
    for i, s in enumerate(symbols):
        factor[s] = 1 << (i + 1) * 10

    suffix = size[-1]
    size = size[:-1]

    if suffix not in symbols:
        raise YunohostError(
            f"Invalid size suffix '{suffix}', expected one of {symbols}"
        )

    try:
        size_ = float(size)
    except Exception:
        raise YunohostError(f"Failed to convert size {size} to float")

    return int(size_ * factor[suffix])


def binary_to_human(n: int) -> str:
    """
    Convert bytes or bits into human readable format with binary prefix
    """
    symbols = ("K", "M", "G", "T", "P", "E", "Z", "Y")
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return "%.1f%s" % (value, s)
    return "%s" % n


def ram_available():
    import psutil

    return (psutil.virtual_memory().available, psutil.swap_memory().free)


def get_ynh_package_version(package):
    # Returns the installed version and release version ('stable' or 'testing'
    # or 'unstable')

    # NB: this is designed for yunohost packages only !
    # Not tested for any arbitrary packages that
    # may handle changelog differently !

    changelog = "/usr/share/doc/%s/changelog.gz" % package
    cmd = "gzip -cd %s 2>/dev/null | grep -v 'BASH_XTRACEFD' | head -n1" % changelog
    if not os.path.exists(changelog):
        return {"version": "?", "repo": "?"}
    out = check_output(cmd).split()
    # Output looks like : "yunohost (1.2.3) testing; urgency=medium"
    return {"version": out[1].strip("()"), "repo": out[2].strip(";")}


def ynh_packages_version(*args, **kwargs):
    # from cli the received arguments are:
    # (Namespace(_callbacks=deque([]), _tid='_global', _to_return={}), []) {}
    # they don't seem to serve any purpose
    """Return the version of each YunoHost package"""
    from collections import OrderedDict

    packages = OrderedDict()
    for package in YUNOHOST_PACKAGES:
        packages[package] = get_ynh_package_version(package)
    return packages


def dpkg_is_broken():
    if check_output("dpkg --audit") != "":
        return True
    # If dpkg is broken, /var/lib/dpkg/updates
    # will contains files like 0001, 0002, ...
    # ref: https://sources.debian.org/src/apt/1.4.9/apt-pkg/deb/debsystem.cc/#L141-L174
    if not os.path.isdir("/var/lib/dpkg/updates/"):
        return False
    return any(re.match("^[0-9]+$", f) for f in os.listdir("/var/lib/dpkg/updates/"))


def dpkg_lock_available():
    return os.system("lsof /var/lib/dpkg/lock >/dev/null") != 0


def _list_upgradable_apt_packages():
    # List upgradable packages
    # LC_ALL=C is here to make sure the results are in english
    upgradable_raw = check_output("LC_ALL=C apt list --upgradable")

    # Dirty parsing of the output
    upgradable_raw = [
        line.strip() for line in upgradable_raw.split("\n") if line.strip()
    ]
    for line in upgradable_raw:
        # Remove stupid warning and verbose messages >.>
        if "apt does not have a stable CLI interface" in line or "Listing..." in line:
            continue

        # line should look like :
        # yunohost/stable 3.5.0.2+201903211853 all [upgradable from: 3.4.2.4+201903080053]
        line = line.split()
        if len(line) != 6:
            logger.warning("Failed to parse this line : %s" % " ".join(line))
            continue

        yield {
            "name": line[0].split("/")[0],
            "new_version": line[1],
            "current_version": line[5].strip("]"),
        }


def _dump_sources_list():
    from glob import glob

    filenames = glob("/etc/apt/sources.list") + glob("/etc/apt/sources.list.d/*")
    for filename in filenames:
        with open(filename, "r") as f:
            for line in f.readlines():
                if line.startswith("#") or not line.strip():
                    continue
                yield filename.replace("/etc/apt/", "") + ":" + line.strip()
