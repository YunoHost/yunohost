import os
from yunohost.interface import Interface

from moulinette import m18n
from moulinette.interfaces.cli import get_locale
from moulinette.utils.log import configure_logging


def create_cli_interface():
    init_i18n()
    init_logging(interface="cli")

    from yunohost.user import user, group, permission
    from yunohost.log import log

    app = Interface(root=True)

    user.add(group)
    user.add(permission)
    app.add(user)
    app.add(log)

    return app.instance


def create_api_interface():
    init_i18n()
    init_logging(interface="cli")

    from yunohost.user import user, group, permission
    from yunohost.log import log

    app = Interface(root=True)
    # Intermediate router to have distincts categories in swagger
    user_sub = Interface(prefix="/users")
    user_sub.add(user)
    user_sub.add(group)
    user_sub.add(permission)
    app.add(user_sub)
    app.add(log)

    return app.instance


def init_i18n():
    m18n.set_locales_dir("/usr/share/yunohost/locales/")
    m18n.set_locale(get_locale())


def init_logging(interface="cli", debug=False, quiet=False, logdir="/var/log/yunohost"):
    engine = "typer" if interface == "cli" else "fastapi"
    logfile = os.path.join(logdir, f"yunohost-{engine}-{interface}.log")

    if not os.path.isdir(logdir):
        os.makedirs(logdir, 0o750)

    logging_configuration = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "format": "%(relativeCreated)-5d %(levelname)-8s %(name)s %(funcName)s - %(message)s"
            },
            "tty-debug": {"format": "%(relativeCreated)-4d %(message)s"},
            "precise": {
                "format": "%(asctime)-15s %(levelname)-8s %(name)s %(funcName)s - %(message)s"
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
                "()": "rich.logging.RichHandler",
                "show_time": False,
                # "formatter": "tty-debug" if debug else "",
            },
            "api": {
                "level": "DEBUG" if debug else "INFO",
                "class": "moulinette.interfaces.api.APIQueueHandler",
            },
            "file": {
                "class": "logging.FileHandler",
                "formatter": "precise",
                "filename": logfile,
                # "filters": ["action"],
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

    configure_logging(logging_configuration)
