#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
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

from pathlib import Path
from typing import Any
from collections.abc import Generator
import logging
import os
from functools import cache
import re
import subprocess

from moulinette import Moulinette
from .process import check_output

from ..utils.error import YunohostError

logger = logging.getLogger("yunohost.utils.packages")

YUNOHOST_PACKAGES = [
    "yunohost",
    "yunohost-admin",
    "yunohost-portal",
    "moulinette",
    "ssowat",
]


@cache
def debian_version() -> str:
    command = 'grep "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2'
    return check_output(command)


@cache
def debian_version_id() -> str:
    command = 'grep "^VERSION_ID=" /etc/os-release 2>/dev/null | cut -d= -f2'
    return check_output(command).strip('"')


@cache
def system_arch() -> str:
    command = "dpkg --print-architecture 2>/dev/null"
    return check_output(command)


@cache
def system_virt() -> str:
    """
    Returns the output of systemd-detect-virt (so e.g. 'none' or 'lxc' or ...)
    You can check the man of the command to have a list of possible outputs...
    """
    # Detect virt technology (if not bare metal) and arch
    # Gotta have this "|| true" because it systemd-detect-virt return 'none'
    # with an error code on bare metal ~.~
    command = "systemd-detect-virt 2>/dev/null || true"
    return check_output(command)


def free_space_in_directory(dirpath: str | Path) -> int:
    stat = os.statvfs(dirpath)
    return stat.f_frsize * stat.f_bavail


def space_used_by_directory(dirpath: str | Path, follow_symlinks: bool = True) -> int:
    if not follow_symlinks:
        du_output = check_output(["du", "-sb", dirpath], shell=False)
        return int(du_output.split()[0])

    # FIXME : this doesnt do what the function name suggest this does ...
    stat = os.statvfs(dirpath)
    return stat.f_frsize * stat.f_blocks


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
            # Display one decimal, though only if value is lower than 10
            # because it's prettier to say something is "42 KB" rather than "42.1 KB"
            if value < 10:
                return "%.1f%s" % (value, s)
            else:
                return "%.0f%s" % (value, s)
    return "%s" % n


def ram_available() -> tuple[int, int]:
    import psutil

    return (psutil.virtual_memory().available, psutil.swap_memory().free)


def get_ynh_package_version(package: str) -> dict[str, str]:
    # Returns the installed version and release version ('stable' or 'testing'
    # or 'unstable')

    # NB: this is designed for yunohost packages only !
    # Not tested for any arbitrary packages that
    # may handle changelog differently !

    changelog = Path("/usr/share/doc") / package / "changelog.gz"
    if not changelog.exists():
        return {"version": "?", "repo": "?"}

    cmd = f"gzip -cd {str(changelog)} 2>/dev/null | grep -v 'BASH_XTRACEFD' | head -n1"
    out = check_output(cmd).split()
    # Output looks like : "yunohost (1.2.3) testing; urgency=medium"
    return {"version": out[1].strip("()"), "repo": out[2].strip(";")}


def ynh_packages_version(*args: Any, **kwargs: Any) -> dict[str, dict[str, str]]:
    # from cli the received arguments are:
    # (Namespace(_callbacks=deque([]), _tid='_global', _to_return={}), []) {}
    # they don't seem to serve any purpose
    """Return the version of each YunoHost package"""
    from collections import OrderedDict

    packages = OrderedDict()
    for package in YUNOHOST_PACKAGES:
        packages[package] = get_ynh_package_version(package)
    return packages


def dpkg_is_broken() -> bool:
    if check_output("dpkg --audit", cwd="/tmp/") != "":
        return True
    # If dpkg is broken, /var/lib/dpkg/updates
    # will contains files like 0001, 0002, ...
    # ref: https://sources.debian.org/src/apt/1.4.9/apt-pkg/deb/debsystem.cc/#L141-L174
    if not os.path.isdir("/var/lib/dpkg/updates/"):
        return False
    return any(re.match("^[0-9]+$", f) for f in os.listdir("/var/lib/dpkg/updates/"))


def dpkg_lock_available() -> bool:
    return os.system("lsof /var/lib/dpkg/lock >/dev/null") != 0


def _list_upgradable_apt_packages() -> Generator[dict[str, str], None, None]:
    # List upgradable packages
    # LC_ALL=C is here to make sure the results are in english
    upgradable_raw = check_output("LC_ALL=C apt list --upgradable")

    # Dirty parsing of the output
    upgradable = [line.strip() for line in upgradable_raw.split("\n") if line.strip()]
    for line in upgradable:
        # Remove stupid warning and verbose messages >.>
        if "apt does not have a stable CLI interface" in line or "Listing..." in line:
            continue

        # line should look like :
        # yunohost/stable 3.5.0.2+201903211853 all [upgradable from: 3.4.2.4+201903080053]
        lines = line.split()
        if len(lines) != 6:
            logger.warning("Failed to parse this line : %s" % " ".join(lines))
            continue

        yield {
            "name": lines[0].split("/")[0],
            "new_version": lines[1],
            "current_version": lines[5].strip("]"),
        }


# Corresponds to the 'Section' in apt/dpkg infos
PACKAGE_CATEGORIES_REMAP = {
    "admin": "misc utils and libs",
    "shells": "misc utils and libs",
    "interpreters": "misc utils and libs",
    "net": "misc utils and libs",
    # Libs
    "oldlibs": "misc utils and libs",
    "libs": "misc utils and libs",
    "libdevel": "misc utils and libs",
    # Languages
    "python": "python",
    "perl": "perl",
    "javascript": "javascript",
    "php": "php",
    "lua": "lua",
    # Other technologies
    "database": "database",
    "mail": "mail",
    "httpd": "webserver",
}


def _group_packages_per_categories(
    packages: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    cmd = (
        r'grep "^Package:\|^Section:" /var/lib/dpkg/status '
        r'| tr "\n" "\r" '
        '| sed -e "s/Package: //g" -e "s/\rSection://g" '
        r'| tr "\r" "\n"'
    )
    out = subprocess.check_output(cmd, shell=True).decode().strip()

    all_packages_and_categories = {}
    for line in out.split("\n"):
        if " " in line:
            package, category = line.split(" ")
        else:
            package, category = line, "?"
        if "yunohost" in package or package in ["moulinette", "ssowat"]:
            category = "yunohost"
        elif package.startswith("perl-") or "libperl" in package:
            category = "perl"
        elif "libpython" in package:
            category = "python"
        elif "libmariadb" in package:
            category = "database"
        elif (
            category == "kernel"
            or any(
                keyword in package
                for keyword in [
                    "initramfs",
                    "systemd",
                    "udev",
                    "libc6",
                    "base-files",
                    "sudo",
                    "passwd",
                    "openssh",
                ]
            )
            or package in ["netbase", "apt", "dpkg", "aptitude"]
        ):
            category = "kernel, systemd, and other critical packages"
        elif category in PACKAGE_CATEGORIES_REMAP:
            category = PACKAGE_CATEGORIES_REMAP[category]
        else:
            category = "misc utils and libs"
        all_packages_and_categories[package] = category

    packages_grouped_by_categories: dict[str, list[dict[str, str]]] = {}
    for package_infos in packages:
        category = all_packages_and_categories.get(package_infos["name"], "misc")
        if category not in packages_grouped_by_categories:
            packages_grouped_by_categories[category] = []
        packages_grouped_by_categories[category].append(package_infos)

    return dict(sorted(packages_grouped_by_categories.items()))


def _dump_sources_list() -> Generator[str, None, None]:
    apt_dir = Path("/etc/apt")
    files = [apt_dir / "sources.list", *(apt_dir / "sources.list.d").iterdir()]
    for file in files:
        if not file.is_file():
            continue
        for line in file.open("r").readlines():
            if line.startswith("#") or not line.strip():
                continue
            yield f"{file.relative_to(apt_dir)}:{line.strip()}"


def aptitude_with_progress_bar(cmd: str) -> None:
    from .process import call_async_output

    msg_to_verb = {
        "Preparing for removal": "Removing",
        "Preparing to configure": "Installing",
        "Removing": "Removing",
        "Unpacking": "Installing",
        "Configuring": "Installing",
        "Installing": "Installing",
        "Installed": "Installing",
        "Preparing": "Installing",
        "Done": "Done",
        "Failed?": "Failed?",
    }

    disable_progress_bar = False
    if cmd.startswith("update"):
        # the status-fd does stupid stuff for 'aptitude update', percentage is always zero except last iteration
        disable_progress_bar = True

    class LogAptStatusToProgressBar:
        def __init__(self) -> None:
            self.previous_package: str | None = None
            self.download_message_displayed = False

        def __call__(self, data: str) -> None:
            if disable_progress_bar:
                return

            t, package, percent, msg = data.split(":", 3)

            # We only display the stuff related to download once
            if t == "dlstatus":
                if self.download_message_displayed is False:
                    logger.info("Downloading...")
                    self.download_message_displayed = True
                return

            if package == "dpkg-exec":
                return
            if package and self.previous_package and package == self.previous_package:
                return

            try:
                percentfloat = round(float(percent), 1)
            except Exception:
                return

            verb = "Processing"
            for m, v in msg_to_verb.items():
                if msg.startswith(m):
                    verb = v

            self.previous_package = package

            width = 20
            done = "#" * int(width * percentfloat / 100)
            remain = "." * (width - len(done))
            logger.info(f"[{done}{remain}] > {percentfloat}% {verb} {package}\r")

    log_apt_status_to_progress_bar = LogAptStatusToProgressBar()

    def strip_boring_dpkg_reading_database(line: str) -> str:
        return re.sub(
            r"(\(Reading database ... \d*%?|files and directories currently installed.\))",
            "",
            line,
        )

    callbacks = (
        lambda line: logger.debug(
            strip_boring_dpkg_reading_database(line).rstrip() + "\r"
        ),
        # ... aptitude has no stderr ? :|  if _apt_log_line_is_relevant(l.rstrip()) else logger.debug(l.rstrip() + "\r"),
        lambda line: logger.warning(line.rstrip() + "\r"),
        lambda line: log_apt_status_to_progress_bar(line.rstrip()),
    )

    original_cmd = cmd
    cmd = f'LC_ALL=C DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none aptitude {cmd} --quiet=2 -o=Dpkg::Use-Pty=0 -o "APT::Status-Fd=$YNH_STDINFO"'

    # If upgrading yunohost from the API, delay the Yunohost-api restart
    # (this should be the last time we need it before bookworm, because on bookworm, yunohost-admin cookies will be persistent upon api restart)
    if " yunohost " in cmd and Moulinette.interface.type == "api":
        cmd = "YUNOHOST_API_RESTART_WILL_BE_HANDLED_BY_YUNOHOST=yes " + cmd

    logger.debug(f"Running: {cmd}")

    read, write = os.pipe()
    os.write(write, b"y\ny\ny")
    os.close(write)
    ret = call_async_output(cmd, callbacks, shell=True, stdin=read)

    if log_apt_status_to_progress_bar.previous_package is not None and ret == 0:
        log_apt_status_to_progress_bar("done::100:Done")
    elif ret != 0:
        raise YunohostError(
            f"Failed to run command 'aptitude {original_cmd}'", raw_msg=True
        )


def _apt_log_line_is_relevant(line: str) -> bool:
    irrelevants = [
        "service sudo-ldap already provided",
        "Reading database ...",
        "Preparing to unpack",
        "Selecting previously unselected package",
        "Created symlink /etc/systemd",
        "Replacing config file",
        "Creating config file",
        "Installing new version of config file",
        "Installing new config file as you requested",
        ", does not exist on system.",
        "unable to delete old directory",
        "update-alternatives:",
        "Configuration file '/etc",
        "==> Modified (by you or by a script) since installation.",
        "==> Package distributor has shipped an updated version.",
        "==> Keeping old config file as default.",
        "is a disabled or a static unit",
        " update-rc.d: warning: start and stop actions are no longer supported; falling back to defaults",
        "insserv: warning: current stop runlevel",
        "insserv: warning: current start runlevel",
    ]
    return bool(line.rstrip()) and all(i not in line.rstrip() for i in irrelevants)
