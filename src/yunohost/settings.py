import os
import json
import errno

from datetime import datetime
from collections import OrderedDict

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.settings')

SETTINGS_PATH = "/etc/yunohost/settings.json"
SETTINGS_PATH_OTHER_LOCATION = "/etc/yunohost/settings-%s.json"

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


def settings_set(key, value):
    settings = _get_settings()

    if key not in settings:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    key_type = settings[key]["type"]

    if key_type == "bool":
        if not isinstance(value, bool):
            raise MoulinetteError(errno.EINVAL, m18n.n(
                'global_settings_bad_type_for_setting', setting=key,
                received_type=type(value).__name__, expected_type=key_type))
    elif key_type == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            raise MoulinetteError(errno.EINVAL, m18n.n(
                'global_settings_bad_type_for_setting', setting=key,
                received_type=type(value).__name__, expected_type=key_type))
    elif key_type == "string":
        if not isinstance(value, basestring):
            raise MoulinetteError(errno.EINVAL, m18n.n(
                'global_settings_bad_type_for_setting', setting=key,
                received_type=type(value).__name__, expected_type=key_type))
    elif key_type == "enum":
        if value not in settings[key]["choices"]:
            raise MoulinetteError(errno.EINVAL, m18n.n(
                'global_settings_bad_choice_for_enum', setting=key,
                received_type=type(value).__name__,
                expected_type=", ".join(settings[key]["choices"])))
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_unknown_type', setting=key,
            unknown_type=key_type))

    settings[key]["value"] = value

    _save_settings(settings)


def settings_default(key):
    settings = _get_settings()

    if key not in settings:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    settings[key]["value"] = settings[key]["default"]
    _save_settings(settings)


def settings_reset(yes=False):
    if not yes:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_reset_not_yes'))

    settings = _get_settings()

    old_settings_backup_path = SETTINGS_PATH_OTHER_LOCATION % datetime.now().strftime("%F_%X")
    _save_settings(settings, location=old_settings_backup_path)

    for value in settings.values():
        value["value"] = value["default"]

    _save_settings(settings)

    return {
        "old_settings_backup_path": old_settings_backup_path,
        "message": m18n.n("global_settings_reset_success", path=old_settings_backup_path)
    }


def _get_settings():
    settings = {}

    for key, value in DEFAULTS.copy().items():
        settings[key] = value
        settings[key]["value"] = value["default"]

    if not os.path.exists(SETTINGS_PATH):
        return settings

    unknown_settings = {}
    unknown_settings_path = SETTINGS_PATH_OTHER_LOCATION % "unknown"

    if os.path.exists(unknown_settings_path):
        try:
            unknown_settings = json.load(open(unknown_settings_path, "r"))
        except Exception as e:
            logger.warning("Error while loading unknown settings %s" % e)

    try:
        with open(SETTINGS_PATH) as settings_fd:
            local_settings = json.load(settings_fd)

            for key, value in local_settings.items():
                if key in settings:
                    settings[key] = value
                else:
                    logger.warning(m18n.n('global_settings_unknown_setting_from_settings_file',
                                          setting_key=key))
                    unknown_settings[key] = value
    except Exception as e:
        raise MoulinetteError(errno.EIO, m18n.n('global_settings_cant_open_settings', reason=e),
                              exc_info=1)

    if unknown_settings:
        try:
            _save_settings(unknown_settings, location=unknown_settings_path)
        except Exception as e:
            logger.warning("Failed to save uknown settings (because %s), abording." % e)

    return settings


def _save_settings(settings, location=SETTINGS_PATH):
    try:
        result = json.dumps(settings, indent=4)
    except Exception as e:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('global_settings_cant_serialize_setings', reason=e),
                              exc_info=1)

    try:
        with open(location, "w") as settings_fd:
            settings_fd.write(result)
    except Exception as e:
        raise MoulinetteError(errno.EIO,
                              m18n.n('global_settings_cant_write_settings', reason=e),
                              exc_info=1)
