import os
import json

from datetime import datetime
from collections import OrderedDict

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from yunohost.service import service_regen_conf

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

DEFAULTS = OrderedDict([
    ("example.bool", {"type": "bool", "default": True}),
    ("example.int", {"type": "int", "default": 42}),
    ("example.string", {"type": "string", "default": "yolo swag"}),
    ("example.enum", {"type": "enum", "default": "a", "choices": ["a", "b", "c"]}),

    # Password Validation
    # -1 disabled, 0 alert if listed, 1 8-letter, 2 normal, 3 strong, 4 strongest
    ("security.password.admin.strength", {"type": "int", "default": 1}),
    ("security.password.user.strength", {"type": "int", "default": 1}),
    ("service.ssh.allow_deprecated_dsa_hostkey", {"type": "bool", "default": False}),
    ("security.ssh.compatibility", {"type": "enum", "default": "modern",
        "choices": ["intermediate", "modern"]}),
    ("security.nginx.compatibility", {"type": "enum", "default": "intermediate",
        "choices": ["intermediate", "modern"]}),
    ("security.postfix.compatibility", {"type": "enum", "default": "intermediate",
        "choices": ["intermediate", "modern"]}),
])


def settings_get(key, full=False):
    """
    Get an entry value in the settings

    Keyword argument:
        key -- Settings key

    """
    settings = _get_settings()

    if key not in settings:
        raise YunohostError('global_settings_key_doesnt_exists', settings_key=key)

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
        raise YunohostError('global_settings_key_doesnt_exists', settings_key=key)

    key_type = settings[key]["type"]

    if key_type == "bool":
        if not isinstance(value, bool):
            raise YunohostError('global_settings_bad_type_for_setting', setting=key,
                                received_type=type(value).__name__, expected_type=key_type)
    elif key_type == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            if isinstance(value, str):
                try:
                    value = int(value)
                except:
                    raise YunohostError('global_settings_bad_type_for_setting',
                                        setting=key,
                                        received_type=type(value).__name__,
                                        expected_type=key_type)
            else:
                raise YunohostError('global_settings_bad_type_for_setting', setting=key,
                                    received_type=type(value).__name__, expected_type=key_type)
    elif key_type == "string":
        if not isinstance(value, basestring):
            raise YunohostError('global_settings_bad_type_for_setting', setting=key,
                                received_type=type(value).__name__, expected_type=key_type)
    elif key_type == "enum":
        if value not in settings[key]["choices"]:
            raise YunohostError('global_settings_bad_choice_for_enum', setting=key,
                                choice=str(value),
                                available_choices=", ".join(settings[key]["choices"]))
    else:
        raise YunohostError('global_settings_unknown_type', setting=key,
                            unknown_type=key_type)

    old_value = settings[key].get("value")
    settings[key]["value"] = value
    _save_settings(settings)

    # TODO : whatdo if the old value is the same as
    # the new value...
    try:
        trigger_post_change_hook(key, old_value, value)
    except Exception as e:
        logger.error("Post-change hook for setting %s failed : %s" % (key, e))
        raise


def settings_reset(key):
    """
    Set an entry value to its default one

    Keyword argument:
        key -- Settings key

    """
    settings = _get_settings()

    if key not in settings:
        raise YunohostError('global_settings_key_doesnt_exists', settings_key=key)

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
    old_settings_backup_path = SETTINGS_PATH_OTHER_LOCATION % datetime.utcnow().strftime("%F_%X")
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
        raise YunohostError('global_settings_cant_open_settings', reason=e)

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
        raise YunohostError('global_settings_cant_serialize_settings', reason=e)

    try:
        with open(location, "w") as settings_fd:
            settings_fd.write(result)
    except Exception as e:
        raise YunohostError('global_settings_cant_write_settings', reason=e)


# Meant to be a dict of setting_name -> function to call
post_change_hooks = {}


def post_change_hook(setting_name):
    def decorator(func):
        assert setting_name in DEFAULTS.keys(), "The setting %s does not exists" % setting_name
        assert setting_name not in post_change_hooks, "You can only register one post change hook per setting (in particular for %s)" % setting_name
        post_change_hooks[setting_name] = func
        return func
    return decorator


def trigger_post_change_hook(setting_name, old_value, new_value):
    if setting_name not in post_change_hooks:
        logger.debug("Nothing to do after changing setting %s" % setting_name)
        return

    f = post_change_hooks[setting_name]
    f(setting_name, old_value, new_value)


# ===========================================
#
# Actions to trigger when changing a setting
# You can define such an action with :
#
# @post_change_hook("your.setting.name")
# def some_function_name(setting_name, old_value, new_value):
#     # Do some stuff
#
# ===========================================

@post_change_hook("security.nginx.compatibility")
def reconfigure_nginx(setting_name, old_value, new_value):
    if old_value != new_value:
        service_regen_conf(names=['nginx'])

@post_change_hook("security.ssh.compatibility")
def reconfigure_ssh(setting_name, old_value, new_value):
    if old_value != new_value:
        service_regen_conf(names=['ssh'])

@post_change_hook("security.postfix.compatibility")
def reconfigure_ssh(setting_name, old_value, new_value):
    if old_value != new_value:
        service_regen_conf(names=['postfix'])
