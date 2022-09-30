# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2015 YUNOHOST.ORG

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""
import re
import os
import logging

from moulinette.utils.process import check_output
from packaging import version

logger = logging.getLogger("yunohost.utils.packages")

YUNOHOST_PACKAGES = ["yunohost", "yunohost-admin", "moulinette", "ssowat"]


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


def meets_version_specifier(pkg_name, specifier):
    """
    Check if a package installed version meets specifier

    specifier is something like ">> 1.2.3"
    """

    # In practice, this function is only used to check the yunohost version
    # installed.
    # We'll trim any ~foobar in the current installed version because it's not
    # handled correctly by version.parse, but we don't care so much in that
    # context
    assert pkg_name in YUNOHOST_PACKAGES
    pkg_version = get_ynh_package_version(pkg_name)["version"]
    pkg_version = re.split(r"\~|\+|\-", pkg_version)[0]
    pkg_version = version.parse(pkg_version)

    # Extract operator and version specifier
    op, req_version = re.search(r"(<<|<=|=|>=|>>) *([\d\.]+)", specifier).groups()
    req_version = version.parse(req_version)

    # Python2 had a builtin that returns (-1, 0, 1) depending on comparison
    # c.f. https://stackoverflow.com/a/22490617
    def cmp(a, b):
        return (a > b) - (a < b)

    deb_operators = {
        "<<": lambda v1, v2: cmp(v1, v2) in [-1],
        "<=": lambda v1, v2: cmp(v1, v2) in [-1, 0],
        "=": lambda v1, v2: cmp(v1, v2) in [0],
        ">=": lambda v1, v2: cmp(v1, v2) in [0, 1],
        ">>": lambda v1, v2: cmp(v1, v2) in [1],
    }

    return deb_operators[op](pkg_version, req_version)


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
