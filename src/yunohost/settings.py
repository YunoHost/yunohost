import os
import yaml
import errno

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.settings')

SETTINGS_PATH = "/etc/yunohost/settings.yaml"

DEFAULT_VALUES = {
}


def settings_get(key, default, namespace):
    return _get_settings().get(namespace, {}).get(key, default)


def settings_list(namespace=None):
    settings = _get_settings()

    if namespace is not None and not settings.get(namespace, {}):
        logger.warning(m18n.n('global_settings_namespace_is_empty', namespace=namespace))
        return {}

    if namespace is not None:
        return settings.get(namespace, {})

    return settings


def settings_exists(key, namespace):
    # is returning a python boolean the moulinette way of doing this?
    # looks weird
    return key in _get_settings().get(namespace, {})


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
    settings = DEFAULT_VALUES.copy()

    if not os.path.exists(SETTINGS_PATH):
        return settings

    try:
        with open(SETTINGS_PATH) as settings_fd:
            settings.update(yaml.load(settings_fd))
    except Exception as e:
        raise MoulinetteError(errno.EIO, m18n.n('global_settings_cant_open_settings', reason=e),
                              exc_info=1)

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
