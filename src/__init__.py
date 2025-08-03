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

import os
import sys
from typing import TYPE_CHECKING, NoReturn, Literal

if TYPE_CHECKING:
    import argparse
    from moulinette.core import MoulinetteLock

from pathlib import Path

import moulinette
from moulinette import m18n
from moulinette.interfaces.cli import colorize, get_locale
from .utils.logging import init_logging


def is_installed() -> bool:
    """Returns whether YunoHost is installed on the system."""
    return os.path.isfile("/etc/yunohost/installed")


def cli(
    debug: bool,
    quiet: bool,
    output_as: str,
    timeout: int | None,
    args: list[str],
    parser: "argparse.ArgumentParser",
) -> NoReturn:
    """Entry point for YunoHost CLI"""
    init_logging(interface="cli", debug=debug, quiet=quiet)

    # Check that YunoHost is installed
    if not is_installed():
        check_command_is_valid_before_postinstall(args)

    ret = moulinette.cli(
        args,
        actionsmap="/usr/share/yunohost/actionsmap.yml",
        locales_dir="/usr/share/yunohost/locales/",
        output_as=output_as,
        timeout=timeout,
        top_parser=parser,
    )
    sys.exit(ret)


def api(debug: bool, host: str, port: int, actionsmap: str | None = None) -> NoReturn:
    """Entry point for YunoHost API server"""
    actionsmap = actionsmap or "/usr/share/yunohost/actionsmap.yml"
    path = Path(actionsmap).resolve()
    if path.exists():
        actionsmap = str(path)

    allowed_cors_origins = []
    allowed_cors_origins_file = "/etc/yunohost/.admin-api-allowed-cors-origins"

    if os.path.exists(allowed_cors_origins_file):
        allowed_cors_origins = open(allowed_cors_origins_file).read().strip().split(",")

    init_logging(interface="api", debug=debug)

    def is_installed_api() -> dict[Literal["installed"], bool]:
        return {"installed": is_installed()}

    # FIXME : someday, maybe find a way to disable route /postinstall if
    # postinstall already done ...

    ret = moulinette.api(
        host=host,
        port=port,
        actionsmap=actionsmap,
        locales_dir="/usr/share/yunohost/locales/",
        routes={("GET", "/installed"): is_installed_api},
        allowed_cors_origins=allowed_cors_origins,
    )
    sys.exit(ret)


def portalapi(debug: bool, host: str, port: int) -> NoReturn:
    """Entry point for YunoHost Portal API server"""
    allowed_cors_origins = []
    allowed_cors_origins_file = "/etc/yunohost/.portal-api-allowed-cors-origins"

    if os.path.exists(allowed_cors_origins_file):
        allowed_cors_origins = open(allowed_cors_origins_file).read().strip().split(",")

    # FIXME : is this the logdir we want ? (yolo to work around permission issue)
    init_logging(interface="portalapi", debug=debug, logdir="/var/log")

    ret = moulinette.api(
        host=host,
        port=port,
        actionsmap="/usr/share/yunohost/actionsmap-portal.yml",
        locales_dir="/usr/share/yunohost/locales/",
        allowed_cors_origins=allowed_cors_origins,
    )
    sys.exit(ret)


def check_command_is_valid_before_postinstall(args: list[str]) -> None:
    """Asserts if the given command is valid before running postinstall, or exits 1"""
    allowed_if_not_postinstalled = [
        "tools postinstall",
        "tools versions",
        "tools shell",
        "backup list",
        "backup restore",
        "log display",
    ]

    if len(args) < 2 or (args[0] + " " + args[1] not in allowed_if_not_postinstalled):
        init_i18n()
        print(colorize(m18n.g("error"), "red") + " " + m18n.n("yunohost_not_installed"))
        sys.exit(1)


def init(
    interface: str = "cli",
    debug: bool = False,
    quiet: bool = False,
    logdir: str = "/var/log/yunohost",
) -> "MoulinetteLock":
    """
    This is a small util function ONLY meant to be used to initialize a Yunohost
    context when ran from tests or from scripts.
    """
    init_logging(interface=interface, debug=debug, quiet=quiet, logdir=logdir)
    init_i18n()
    from moulinette.core import MoulinetteLock

    lock = MoulinetteLock("yunohost", timeout=30)
    lock.acquire()
    return lock


def init_i18n() -> None:
    """
    Initialize the i18n locale dir and locale.
    This should only be called when not willing to go through moulinette.cli
    or moulinette.api but still willing to call m18n.n/g...
    """
    m18n.set_locales_dir("/usr/share/yunohost/locales/")
    m18n.set_locale(get_locale())
