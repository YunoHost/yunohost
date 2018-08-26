import os
import json
import errno

from datetime import datetime
from collections import OrderedDict

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.settings')

SETTINGS_PATH = "/etc/yunohost/settings.json"
SETTINGS_PATH_OTHER_LOCATION = "/etc/yunohost/settings-%s.json"

# a settings entry is in the form of:
# namespace.subnamespace.name: {type, value, default, description, [choices]}
# choices is only for enum
# the keyname can have as many subnamespace as needed but should have at least
# one level of namespace

# description is implied from the translated strings
# the key is "global_settings_setting_%s" % key.replace(".", "_")

# type can be:
# * bool
# * int
# * string
# * enum (in form a python list)

# we don't store the value in default options
DEFAULTS = OrderedDict([
    ("example.bool", {"type": "bool", "default": True}),
    ("example.int", {"type": "int", "default": 42}),
    ("example.string", {"type": "string", "default": "yolo swag"}),
    ("example.enum", {"type": "enum", "default": "a", "choices": ["a", "b", "c"]}),
])


def settings_get(key, full=False):
    """
    Get an entry value in the settings

    Keyword argument:
        key -- Settings key

    """
    settings = _get_settings()

    if key not in settings:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    if full:
        return settings[key]

    return settings[key]['value']


def settings_list():
    """
    List all entries of the settings

    """
    return _get_settings()


def settings_set(key, value):
    """
    Set an entry value in the settings

    Keyword argument:
        key -- Settings key
        value -- New value

    """
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


def settings_reset(key):
    """
    Set an entry value to its default one

    Keyword argument:
        key -- Settings key

    """
    settings = _get_settings()

    if key not in settings:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    settings[key]["value"] = settings[key]["default"]
    _save_settings(settings)


def settings_reset_all():
    """
    Reset all settings to their default value

    Keyword argument:
        yes -- Yes I'm sure I want to do that

    """
    settings = _get_settings()

    # For now on, we backup the previous settings in case of but we don't have
    # any mecanism to take advantage of those backups. It could be a nice
    # addition but we'll see if this is a common need.
    # Another solution would be to use etckeeper and integrate those
    # modification inside of it and take advantage of its git history
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
        settings[key]["description"] = m18n.n("global_settings_setting_%s" % key.replace(".", "_"))

    if not os.path.exists(SETTINGS_PATH):
        return settings

    # we have a very strict policy on only allowing settings that we know in
    # the OrderedDict DEFAULTS
    # For various reason, while reading the local settings we might encounter
    # settings that aren't in DEFAULTS, those can come from settings key that
    # we have removed, errors or the user trying to modify
    # /etc/yunohost/settings.json
    # To avoid to simply overwrite them, we store them in
    # /etc/yunohost/settings-unknown.json in case of
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
                    settings[key]["description"] = m18n.n("global_settings_setting_%s" % key.replace(".", "_"))
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
            logger.warning("Failed to save unknown settings (because %s), aborting." % e)

    return settings


def _save_settings(settings, location=SETTINGS_PATH):
    settings_without_description = {}
    for key, value in settings.items():
        settings_without_description[key] = value
        if "description" in value:
            del settings_without_description[key]["description"]

    try:
        result = json.dumps(settings_without_description, indent=4)
    except Exception as e:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('global_settings_cant_serialize_settings', reason=e),
                              exc_info=1)

    try:
        with open(location, "w") as settings_fd:
            settings_fd.write(result)
    except Exception as e:
        raise MoulinetteError(errno.EIO,
                              m18n.n('global_settings_cant_write_settings', reason=e),
                              exc_info=1)
