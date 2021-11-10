#! /usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys

import moulinette
from moulinette import m18n
from moulinette.utils.log import configure_logging
from moulinette.interfaces.cli import colorize, get_locale


def is_installed():
    return os.path.isfile("/etc/yunohost/installed")


def cli(debug, quiet, output_as, timeout, args, parser):

    init_logging(interface="cli", debug=debug, quiet=quiet)

    # Check that YunoHost is installed
    if not is_installed():
        check_command_is_valid_before_postinstall(args)

    ret = moulinette.cli(args, output_as=output_as, timeout=timeout, top_parser=parser)
    sys.exit(ret)


def api(debug, host, port):

    init_logging(interface="api", debug=debug)

    def is_installed_api():
        return {"installed": is_installed()}

    # FIXME : someday, maybe find a way to disable route /postinstall if
    # postinstall already done ...

    ret = moulinette.api(
        host=host,
        port=port,
        routes={("GET", "/installed"): is_installed_api},
    )
    sys.exit(ret)


def check_command_is_valid_before_postinstall(args):

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


def init(interface="cli", debug=False, quiet=False, logdir="/var/log/yunohost"):
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


def init_i18n():
    # This should only be called when not willing to go through moulinette.cli
    # or moulinette.api but still willing to call m18n.n/g...
    m18n.load_namespace("yunohost")
    m18n.set_locale(get_locale())


def init_logging(interface="cli", debug=False, quiet=False, logdir="/var/log/yunohost"):

    logfile = os.path.join(logdir, "yunohost-%s.log" % interface)

    if not os.path.isdir(logdir):
        os.makedirs(logdir, 0o750)

    logging_configuration = {
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "console": {
                "format": "%(relativeCreated)-5d %(levelname)-8s %(name)s %(funcName)s - %(fmessage)s"
            },
            "tty-debug": {"format": "%(relativeCreated)-4d %(fmessage)s"},
            "precise": {
                "format": "%(asctime)-15s %(levelname)-8s %(name)s %(funcName)s - %(fmessage)s"
            },
        },
        "filters": {
            "action": {
                "()": "moulinette.utils.log.ActionFilter",
            },
        },
        "handlers": {
            "cli": {
                "level": "DEBUG" if debug else "INFO",
                "class": "moulinette.interfaces.cli.TTYHandler",
                "formatter": "tty-debug" if debug else "",
            },
            "api": {
                "level": "DEBUG" if debug else "INFO",
                "class": "moulinette.interfaces.api.APIQueueHandler",
            },
            "file": {
                "class": "logging.FileHandler",
                "formatter": "precise",
                "filename": logfile,
                "filters": ["action"],
            },
        },
        "loggers": {
            "yunohost": {
                "level": "DEBUG",
                "handlers": ["file", interface] if not quiet else ["file"],
                "propagate": False,
            },
            "moulinette": {
                "level": "DEBUG",
                "handlers": ["file", interface] if not quiet else ["file"],
                "propagate": False,
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": ["file", interface] if debug else ["file"],
        },
    }

    #  Logging configuration for CLI (or any other interface than api...)     #
    if interface != "api":
        configure_logging(logging_configuration)

    #  Logging configuration for API                                          #
    else:
        # We use a WatchedFileHandler instead of regular FileHandler to possibly support log rotation etc
        logging_configuration["handlers"]["file"][
            "class"
        ] = "logging.handlers.WatchedFileHandler"

        # This is for when launching yunohost-api in debug mode, we want to display stuff in the console
        if debug:
            logging_configuration["loggers"]["yunohost"]["handlers"].append("cli")
            logging_configuration["loggers"]["moulinette"]["handlers"].append("cli")
            logging_configuration["root"]["handlers"].append("cli")

        configure_logging(logging_configuration)
