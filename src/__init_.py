import logging
from rich.logging import RichHandler
from yunohost.interface import Interface
from yunohost.user import user, group, permission

from moulinette import m18n
from moulinette.interfaces.cli import get_locale


def create_cli_interface():
    init_i18n()
    init_logging(interface="cli")

    app = Interface(root=True)

    user.add(group)
    user.add(permission)
    app.add(user)

    return app.instance


def create_api_interface():
    init_i18n()
    init_logging(interface="cli")

    app = Interface(root=True)
    # Intermediate router to have distincts categories in swagger
    user_sub = Interface(prefix="/users")
    user_sub.add(user)
    user_sub.add(group)
    user_sub.add(permission)
    app.add(user_sub)

    return app.instance


def init_i18n():
    m18n.set_locales_dir("/usr/share/yunohost/locales/")
    m18n.set_locale(get_locale())


def init_logging(interface="cli", debug=False, quiet=False, logdir="/var/log/yunohost"):
    logging.basicConfig(
        level="NOTSET", format="%(message)s", handlers=[RichHandler(show_time=False)]
    )
