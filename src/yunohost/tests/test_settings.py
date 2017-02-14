import os
import json

from moulinette.core import MoulinetteError

from yunohost.settings import settings_get, settings_list, _get_settings, settings_set, settings_default, settings_reset, SETTINGS_PATH_OTHER_LOCATION, SETTINGS_PATH


def assertEqual(a, b):
    # == can have different behavior than !=
    if not (a == b):
        raise AssertionError("%s != %s" % (a, b))


def assertNotEqual(a, b):
    # == can have different behavior than !=
    if not (a != b):
        raise AssertionError("%s != %s" % (a, b))


def assertRaise(exception_, func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except exception_:
        pass
    else:
        raise AssertionError("%s should have raise %s with arguments %s and %s" % (func.__name__, exception_.__name__, args, kwargs))


def setup_function(function):
    os.system("mv /etc/yunohost/settings.json /etc/yunohost/settings.json.saved")


def teardown_function(function):
    os.system("mv /etc/yunohost/settings.json.saved /etc/yunohost/settings.json")


def test_settings_get_bool():
    assertEqual(settings_get("example.bool"), {"type": "bool", "value": True, "default": True, "description": "Example boolean option"})


def test_settings_get_int():
    assertEqual(settings_get("example.int"), {"type": "int", "value": 42, "default": 42, "description": "Example int option"})


def test_settings_get_string():
    assertEqual(settings_get("example.string"), {"type": "string", "value": "yolo swag", "default": "yolo swag", "description": "Example string option"})


def test_settings_get_enum():
    assertEqual(settings_get("example.enum"), {"type": "enum", "value": "a", "default": "a", "description": "Example enum option", "choices": ["a", "b", "c"]})


def test_settings_get_doesnt_exists():
    assertRaise(MoulinetteError, settings_get, "doesnt.exists")


def test_settings_list():
    assertEqual(settings_list(), _get_settings())


def test_settings_set():
    settings_set("example.bool", False)
    assertEqual(settings_get("example.bool")["value"], False)


def test_settings_set_int():
    settings_set("example.int", 21)
    assertEqual(settings_get("example.int")["value"], 21)


def test_settings_set_enum():
    settings_set("example.enum", "c")
    assertEqual(settings_get("example.enum")["value"], "c")


def test_settings_set_doesexit():
    assertRaise(MoulinetteError, settings_set, "doesnt.exist", True)


def test_settings_set_bad_type_bool():
    assertRaise(MoulinetteError, settings_set, "example.bool", 42)
    assertRaise(MoulinetteError, settings_set, "example.bool", "pouet")


def test_settings_set_bad_type_int():
    assertRaise(MoulinetteError, settings_set, "example.int", True)
    assertRaise(MoulinetteError, settings_set, "example.int", "pouet")


def test_settings_set_bad_type_string():
    assertRaise(MoulinetteError, settings_set, "example.string", True)
    assertRaise(MoulinetteError, settings_set, "example.string", 42)


def test_settings_set_bad_value_enum():
    assertRaise(MoulinetteError, settings_set, "example.enum", True)
    assertRaise(MoulinetteError, settings_set, "example.enum", "e")
    assertRaise(MoulinetteError, settings_set, "example.enum", 42)
    assertRaise(MoulinetteError, settings_set, "example.enum", "pouet")


def test_settings_list_modified():
    settings_set("example.int", 21)
    assertEqual(settings_list()["example.int"]["value"], 21)


def test_default():
    settings_set("example.int", 21)
    assertEqual(settings_get("example.int")["value"], 21)
    settings_default("example.int")
    assertEqual(settings_get("example.int")["value"], settings_get("example.int")["default"])


def test_settings_default_doesexit():
    assertRaise(MoulinetteError, settings_default, "doesnt.exist")


def test_settings_reset_no_yes():
    assertRaise(MoulinetteError, settings_reset)


def test_reset():
    settings_before = settings_list()
    settings_set("example.bool", False)
    settings_set("example.int", 21)
    settings_set("example.string", "pif paf pouf")
    settings_set("example.enum", "c")
    assertNotEqual(settings_before, settings_list())
    settings_reset(yes=True)
    if settings_before != settings_list():
        for i in settings_before:
            assert settings_before[i] == settings_list()[i]


def test_reset_backup():
    settings_before = settings_list()
    settings_set("example.bool", False)
    settings_set("example.int", 21)
    settings_set("example.string", "pif paf pouf")
    settings_set("example.enum", "c")
    settings_after_modification = settings_list()
    assertNotEqual(settings_before, settings_after_modification)
    old_settings_backup_path = settings_reset(yes=True)["old_settings_backup_path"]

    for i in settings_after_modification:
        del settings_after_modification[i]["description"]

    assertEqual(settings_after_modification, json.load(open(old_settings_backup_path, "r")))


def test_unknown_keys():
    unknown_settings_path = SETTINGS_PATH_OTHER_LOCATION % "unknown"
    unknown_setting = {
        "unkown_key": {"value": 42, "default": 31, "type": "int"},
    }
    open(SETTINGS_PATH, "w").write(json.dumps(unknown_setting))

    # stimulate a write
    settings_reset(yes=True)

    assertEqual(unknown_setting, json.load(open(unknown_settings_path, "r")))
