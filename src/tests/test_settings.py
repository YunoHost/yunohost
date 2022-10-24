import os
import json
import glob
import pytest

import moulinette
from yunohost.utils.error import YunohostError, YunohostValidationError

from yunohost.settings import (
    settings_get,
    settings_list,
    settings_set,
    settings_reset,
    settings_reset_all,
    SETTINGS_PATH,
)

EXAMPLE_SETTINGS = """
[example]
    [example.example]
        [example.example.boolean]
        type = "boolean"
        yes = "True"
        no = "False"
        default = "True"

        [example.example.number]
        type = "number"
        default = 42

        [example.example.string]
        type = "string"
        default = "yolo swag"

        [example.example.select]
        type = "select"
        choices = ["a", "b", "c"]
        default = "a"
"""


def setup_function(function):
    # Backup settings
    if os.path.exists(SETTINGS_PATH):
        os.system(f"mv {SETTINGS_PATH} {SETTINGS_PATH}.saved")
    # Add example settings to config panel
    os.system(
        "cp /usr/share/yunohost/config_global.toml /usr/share/yunohost/config_global.toml.saved"
    )
    with open("/usr/share/yunohost/config_global.toml", "a") as file:
        file.write(EXAMPLE_SETTINGS)


def teardown_function(function):
    if os.path.exists("/etc/yunohost/settings.yml.saved"):
        os.system(f"mv {SETTINGS_PATH}.saved {SETTINGS_PATH}")
    elif os.path.exists(SETTINGS_PATH):
        os.remove(SETTINGS_PATH)
    os.system(
        "mv /usr/share/yunohost/config_global.toml.saved /usr/share/yunohost/config_global.toml"
    )


old_translate = moulinette.core.Translator.translate


def _monkeypatch_translator(self, key, *args, **kwargs):

    if key.startswith("global_settings_setting_"):
        return f"Dummy translation for {key}"

    return old_translate(self, key, *args, **kwargs)


moulinette.core.Translator.translate = _monkeypatch_translator


def _get_settings():
    return yaml.load(open(SETTINGS_PATH, "r"))


def test_settings_get_bool():
    assert settings_get("example.example.boolean")


# FIXME : Testing this doesn't make sense ? This should be tested in test_config.py ?
# def test_settings_get_full_bool():
#    assert settings_get("example.example.boolean", True) == {'version': '1.0',
#        'i18n': 'global_settings_setting',
#        'panels': [{'services': [],
#        'actions': {'apply': {'en': 'Apply'}},
#        'sections': [{'name': '',
#            'services': [],
#            'optional': True,
#            'options': [{'type': 'boolean',
#            'yes': 'True',
#            'no': 'False',
#            'default': 'True',
#            'id': 'boolean',
#            'name': 'boolean',
#            'optional': True,
#            'current_value': 'True',
#            'ask': 'global_settings_setting_boolean',
#            'choices': []}],
#            'id': 'example'}],
#        'id': 'example',
#        'name': {'en': 'Example'}}]}


def test_settings_get_int():
    assert settings_get("example.example.number") == 42


# def test_settings_get_full_int():
#    assert settings_get("example.int", True) == {
#        "type": "int",
#        "value": 42,
#        "default": 42,
#        "description": "Dummy int setting",
#    }


def test_settings_get_string():
    assert settings_get("example.example.string") == "yolo swag"


# def test_settings_get_full_string():
#    assert settings_get("example.example.string", True) == {
#        "type": "string",
#        "value": "yolo swag",
#        "default": "yolo swag",
#        "description": "Dummy string setting",
#    }


def test_settings_get_select():
    assert settings_get("example.example.select") == "a"


# def test_settings_get_full_select():
#    option = settings_get("example.example.select", full=True).get('panels')[0].get('sections')[0].get('options')[0]
#    assert option.get('choices') == ["a", "b", "c"]


def test_settings_get_doesnt_exists():
    with pytest.raises(YunohostValidationError):
        settings_get("doesnt.exists")


# def test_settings_list():
#    assert settings_list() == _get_settings()


def test_settings_set():
    settings_set("example.example.boolean", False)
    assert settings_get("example.example.boolean") is False

    settings_set("example.example.boolean", "on")
    assert settings_get("example.example.boolean") is True


def test_settings_set_int():
    settings_set("example.example.number", 21)
    assert settings_get("example.example.number") == 21


def test_settings_set_select():
    settings_set("example.example.select", "c")
    assert settings_get("example.example.select") == "c"


def test_settings_set_doesexit():
    with pytest.raises(YunohostValidationError):
        settings_set("doesnt.exist", True)


def test_settings_set_bad_type_bool():
    with pytest.raises(YunohostError):
        settings_set("example.example.boolean", 42)
    with pytest.raises(YunohostError):
        settings_set("example.example.boolean", "pouet")


def test_settings_set_bad_type_int():
    #    with pytest.raises(YunohostError):
    #        settings_set("example.example.number", True)
    with pytest.raises(YunohostError):
        settings_set("example.example.number", "pouet")


# def test_settings_set_bad_type_string():
#    with pytest.raises(YunohostError):
#        settings_set("example.example.string", True)
#    with pytest.raises(YunohostError):
#        settings_set("example.example.string", 42)


def test_settings_set_bad_value_select():
    with pytest.raises(YunohostError):
        settings_set("example.example.select", True)
    with pytest.raises(YunohostError):
        settings_set("example.example.select", "e")
    with pytest.raises(YunohostError):
        settings_set("example.example.select", 42)
    with pytest.raises(YunohostError):
        settings_set("example.example.select", "pouet")


def test_settings_list_modified():
    settings_set("example.example.number", 21)
    assert settings_list()["number"] == 21


def test_reset():
    option = (
        settings_get("example.example.number", full=True)
        .get("panels")[0]
        .get("sections")[0]
        .get("options")[0]
    )
    settings_set("example.example.number", 21)
    assert settings_get("example.example.number") == 21
    settings_reset("example.example.number")
    assert settings_get("example.example.number") == option["default"]


def test_settings_reset_doesexit():
    with pytest.raises(YunohostError):
        settings_reset("doesnt.exist")


def test_reset_all():
    settings_before = settings_list()
    settings_set("example.example.boolean", False)
    settings_set("example.example.number", 21)
    settings_set("example.example.string", "pif paf pouf")
    settings_set("example.example.select", "c")
    assert settings_before != settings_list()
    settings_reset_all()
    if settings_before != settings_list():
        for i in settings_before:
            assert settings_before[i] == settings_list()[i]


# def test_reset_all_backup():
#    settings_before = settings_list()
#    settings_set("example.bool", False)
#    settings_set("example.int", 21)
#    settings_set("example.string", "pif paf pouf")
#    settings_set("example.select", "c")
#    settings_after_modification = settings_list()
#    assert settings_before != settings_after_modification
#    old_settings_backup_path = settings_reset_all()["old_settings_backup_path"]
#
#    for i in settings_after_modification:
#        del settings_after_modification[i]["description"]
#
#    assert settings_after_modification == json.load(open(old_settings_backup_path, "r"))


# def test_unknown_keys():
#    unknown_settings_path = SETTINGS_PATH_OTHER_LOCATION % "unknown"
#    unknown_setting = {
#        "unkown_key": {"value": 42, "default": 31, "type": "int"},
#    }
#    open(SETTINGS_PATH, "w").write(json.dumps(unknown_setting))
#
#    # stimulate a write
#    settings_reset_all()
#
#    assert unknown_setting == json.load(open(unknown_settings_path, "r"))
