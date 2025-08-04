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
from logging import addLevelName, setLoggerClass, Logger
from logging.config import dictConfig

SUCCESS = 25

# FIXME : this is the stuff from Moulinette .. probably should be merged with the stuff in init_logging
DEFAULT_LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {"format": "%(asctime)-15s %(levelname)-8s %(name)s - %(message)s"},
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "formatter": "simple",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {"moulinette": {"level": "DEBUG", "handlers": ["console"]}},
}


def init_logging(
    interface: str = "cli",
    debug: bool = False,
    quiet: bool = False,
    logdir: str = "/var/log/yunohost",
) -> None:
    """Initialize logging and logger objects"""
    logfile = os.path.join(logdir, "yunohost-%s.log" % interface)

    if not os.path.isdir(logdir):
        os.makedirs(logdir, 0o750)

    base_handlers = ["file"]
    root_handlers = ["file", "cli"] if debug else ["file"]

    # Logging configuration for API
    if interface in ["api", "portalapi"]:
        # We use a WatchedFileHandler instead of regular FileHandler to possibly support log rotation etc
        file_class = "logging.handlers.WatchedFileHandler"

        # This is for when launching yunohost-api in debug mode, we want to display stuff in the console
        if debug:
            base_handlers.append("cli")

    # Logging configuration for CLI (or any other interface than api...)
    else:
        file_class = "logging.FileHandler"

        if not quiet:
            base_handlers.append("cli")

    logging_configuration = {
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "tty-debug": {
                "format": "%(relativeCreated)-4d %(level_with_color)s %(message)s"
            },
            "precise": {
                "format": "%(asctime)-15s %(levelname)-8s %(name)s.%(funcName)s - %(message)s"
            },
        },
        "handlers": {
            "cli": {
                "level": "DEBUG" if debug else "INFO",
                "class": "moulinette.interfaces.cli.TTYHandler",
                "formatter": "tty-debug" if debug else "",
            },
            "file": {
                "class": file_class,
                "formatter": "precise",
                "filename": logfile,
            },
        },
        "loggers": {
            "yunohost": {
                "level": "DEBUG",
                "handlers": base_handlers,
                "propagate": False,
            },
            "moulinette": {
                "level": "DEBUG",
                "handlers": base_handlers,
                "propagate": False,
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": root_handlers,
        },
    }

    if interface == "api":
        from .sse import start_log_broker

        start_log_broker()

    # add custom logging level and class
    addLevelName(SUCCESS, "SUCCESS")
    setLoggerClass(YunohostLogger)

    # load configuration from dict
    dictConfig(DEFAULT_LOGGING)
    dictConfig(logging_configuration)


class YunohostLogger(Logger):
    """
    Custom logger class with 'success' log method
    """

    def success(self, msg, *args, **kwargs):
        """Log 'msg % args' with severity 'SUCCESS'."""
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kwargs)

    # FIXME : wtf is this used for :| ...
    def findCaller(self, *args):
        """Override findCaller method to consider this source file."""

        import os
        from logging import currentframe, _srcfile

        f = currentframe()
        if f is not None:
            f = f.f_back
        rv = "(unknown file)", 0, "(unknown function)", None
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename == _srcfile or filename == __file__:
                f = f.f_back
                continue
            rv = (co.co_filename, f.f_lineno, co.co_name, None)
            break

        return rv
