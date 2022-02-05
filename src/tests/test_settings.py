import os
import json
import glob
import pytest

from yunohost.utils.error import YunohostError

import yunohost.settings as settings

from yunohost.settings import (
    settings_get,
    settings_list,
    _get_settings,
    settings_set,
    settings_reset,
    settings_reset_all,
    SETTINGS_PATH_OTHER_LOCATION,
    SETTINGS_PATH,
    DEFAULTS,
)

DEFAULTS["example.bool"] = {"type": "bool", "default": True}
DEFAULTS["example.int"] = {"type": "int", "default": 42}
DEFAULTS["example.string"] = {"type": "string", "default": "yolo swag"}
DEFAULTS["example.enum"] = {"type": "enum", "default": "a", "choices": ["a", "b", "c"]}


def setup_function(function):
    os.system("mv /etc/yunohost/settings.json /etc/yunohost/settings.json.saved")


def teardown_function(function):
    os.system("mv /etc/yunohost/settings.json.saved /etc/yunohost/settings.json")
    for filename in glob.glob("/etc/yunohost/settings-*.json"):
        os.remove(filename)


def monkey_get_setting_description(key):
    return "Dummy %s setting" % key.split(".")[-1]


settings._get_setting_description = monkey_get_setting_description


def test_settings_get_bool():
    assert settings_get("example.bool")


def test_settings_get_full_bool():
    assert settings_get("example.bool", True) == {
        "type": "bool",
        "value": True,
        "default": True,
        "description": "Dummy bool setting",
    }


def test_settings_get_int():
    assert settings_get("example.int") == 42


def test_settings_get_full_int():
    assert settings_get("example.int", True) == {
        "type": "int",
        "value": 42,
        "default": 42,
        "description": "Dummy int setting",
    }


def test_settings_get_string():
    assert settings_get("example.string") == "yolo swag"


def test_settings_get_full_string():
    assert settings_get("example.string", True) == {
        "type": "string",
        "value": "yolo swag",
        "default": "yolo swag",
        "description": "Dummy string setting",
    }


def test_settings_get_enum():
    assert settings_get("example.enum") == "a"


def test_settings_get_full_enum():
    assert settings_get("example.enum", True) == {
        "type": "enum",
        "value": "a",
        "default": "a",
        "description": "Dummy enum setting",
        "choices": ["a", "b", "c"],
    }


def test_settings_get_doesnt_exists():
    with pytest.raises(YunohostError):
        settings_get("doesnt.exists")


def test_settings_list():
    assert settings_list() == _get_settings()


def test_settings_set():
    settings_set("example.bool", False)
    assert settings_get("example.bool") is False

    settings_set("example.bool", "on")
    assert settings_get("example.bool") is True


def test_settings_set_int():
    settings_set("example.int", 21)
    assert settings_get("example.int") == 21


def test_settings_set_enum():
    settings_set("example.enum", "c")
    assert settings_get("example.enum") == "c"


def test_settings_set_doesexit():
    with pytest.raises(YunohostError):
        settings_set("doesnt.exist", True)


def test_settings_set_bad_type_bool():
    with pytest.raises(YunohostError):
        settings_set("example.bool", 42)
    with pytest.raises(YunohostError):
        settings_set("example.bool", "pouet")


def test_settings_set_bad_type_int():
    with pytest.raises(YunohostError):
        settings_set("example.int", True)
    with pytest.raises(YunohostError):
        settings_set("example.int", "pouet")


def test_settings_set_bad_type_string():
    with pytest.raises(YunohostError):
        settings_set("example.string", True)
    with pytest.raises(YunohostError):
        settings_set("example.string", 42)


def test_settings_set_bad_value_enum():
    with pytest.raises(YunohostError):
        settings_set("example.enum", True)
    with pytest.raises(YunohostError):
        settings_set("example.enum", "e")
    with pytest.raises(YunohostError):
        settings_set("example.enum", 42)
    with pytest.raises(YunohostError):
        settings_set("example.enum", "pouet")


def test_settings_list_modified():
    settings_set("example.int", 21)
    assert settings_list()["example.int"] == {
        "default": 42,
        "description": "Dummy int setting",
        "type": "int",
        "value": 21,
    }


def test_reset():
    settings_set("example.int", 21)
    assert settings_get("example.int") == 21
    settings_reset("example.int")
    assert settings_get("example.int") == settings_get("example.int", True)["default"]


def test_settings_reset_doesexit():
    with pytest.raises(YunohostError):
        settings_reset("doesnt.exist")


def test_reset_all():
    settings_before = settings_list()
    settings_set("example.bool", False)
    settings_set("example.int", 21)
    settings_set("example.string", "pif paf pouf")
    settings_set("example.enum", "c")
    assert settings_before != settings_list()
    settings_reset_all()
    if settings_before != settings_list():
        for i in settings_before:
            assert settings_before[i] == settings_list()[i]


def test_reset_all_backup():
    settings_before = settings_list()
    settings_set("example.bool", False)
    settings_set("example.int", 21)
    settings_set("example.string", "pif paf pouf")
    settings_set("example.enum", "c")
    settings_after_modification = settings_list()
    assert settings_before != settings_after_modification
    old_settings_backup_path = settings_reset_all()["old_settings_backup_path"]

    for i in settings_after_modification:
        del settings_after_modification[i]["description"]

    assert settings_after_modification == json.load(open(old_settings_backup_path, "r"))


def test_unknown_keys():
    unknown_settings_path = SETTINGS_PATH_OTHER_LOCATION % "unknown"
    unknown_setting = {
        "unkown_key": {"value": 42, "default": 31, "type": "int"},
    }
    open(SETTINGS_PATH, "w").write(json.dumps(unknown_setting))

    # stimulate a write
    settings_reset_all()

    assert unknown_setting == json.load(open(unknown_settings_path, "r"))
