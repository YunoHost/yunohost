import os
import yaml
import errno

from collections import OrderedDict

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.settings')

SETTINGS_PATH = "/etc/yunohost/settings.yaml"

# a settings entry is in the form of:
# name: {type, value, default, description, [possibilities]}
# possibilities is only for enum

# type can be:
# * bool
# * int
# * string
# * enum (in form a python list)

# we don't store the value in default options
DEFAULTS = OrderedDict([
    ("example.bool", {"type": "bool", "default": True, "description": "Example boolean option"}),
    ("example.int", {"type": "int", "default": 42, "description": "Example int option"}),
    ("example.string", {"type": "string", "default": "yolo swag", "description": "Example stringean option"}),
    ("example.enum", {"type": "enum", "default": "a", "choices": ["a", "b", "c"], "description": "Example enum option"}),
])


def settings_get(key):
    settings = _get_settings()

    if key not in settings:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    return settings[key]


def settings_list():
    return _get_settings()


def settings_set(key, value, namespace):
    settings = _get_settings()

    settings.setdefault(namespace, {})[key] = value

    _save_settings(settings)


def settings_remove(key, namespace, fail_silently=False):
    settings = _get_settings()

    if key not in settings.get(namespace, {}):
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    del settings[namespace][key]

    if not settings[namespace]:
        del settings[namespace]

    _save_settings(settings)


def _get_settings():
    settings = {}

    for key, value in DEFAULTS.copy().items():
        settings[key] = value
        settings[key]["value"] = value["default"]

    # if not os.path.exists(SETTINGS_PATH):
    #     return settings

    # try:
    #     with open(SETTINGS_PATH) as settings_fd:
    #         settings.update(yaml.load(settings_fd))
    # except Exception as e:
    #     raise MoulinetteError(errno.EIO, m18n.n('global_settings_cant_open_settings', reason=e),
    #                           exc_info=1)

    return settings


def _save_settings(settings):
    try:
        result = yaml.dump(settings, default_flow_style=False)
    except Exception as e:
        raise MoulinetteError(errno.EINVAL, m18n.n('global_settings_cant_serialize_setings',
                                                   reason=e),
                              exc_info=1)

    try:
        with open(SETTINGS_PATH, "w") as settings_fd:
            settings_fd.write(result)
    except Exception as e:
        raise MoulinetteError(errno.EIO, m18n.n('global_settings_cant_write_settings', reason=e),
                              exc_info=1)
