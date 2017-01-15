import os
import yaml
import errno

from moulinette.core import MoulinetteError


SETTINGS_PATH = "/etc/yunohost/settings.yaml"

DEFAULT_VALUES = {
}


def settings_get(key, default, namespace):
    return _get_settings().get(namespace, {}).get(key, default)


def settings_list(namespace=None):
    if namespace is not None:
        return _get_settings().get(namespace, {})
    else:
        return _get_settings()


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

    if key in settings.get(namespace, {}):
        del settings.get(namespace, {})[key]
    elif not fail_silently:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'global_settings_key_doesnt_exists', settings_key=key))

    _save_settings(settings)

    return "ok"


def _get_settings():
    settings = DEFAULT_VALUES.copy()

    if not os.path.exists(SETTINGS_PATH):
        return settings

    # TODO error handling
    with open(SETTINGS_PATH) as settings_fd:
        settings.update(yaml.load(settings_fd))

    return settings


def _save_settings(settings):
    # TODO error handling
    result = yaml.dump(settings, default_flow_style=False)

    with open(SETTINGS_PATH, "w") as settings_fd:
        settings_fd.write(result)
