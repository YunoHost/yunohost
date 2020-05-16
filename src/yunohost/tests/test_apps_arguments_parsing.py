import pytest
from collections import OrderedDict
from mock import patch

from moulinette import msignals

from yunohost.app import _parse_args_in_yunohost_format
from yunohost.utils.error import YunohostError


"""
Argument default format:
{
    "name": "the_name",
    "type": "one_of_the_available_type",  // "sting" is not specified
    "ask": {
        "en": "the question in english",
        "fr": "the question in french"
    },
    "help": {
        "en": "some help text in english",
        "fr": "some help text in french"
    },
    "example": "an example value", // optional
    "default", "some stuff", // optional, not available for all types
    "optional": true // optional, will skip if not answered
}

User answers:
{"name": "value", ...}
"""


def test_parse_args_in_yunohost_format_empty():
    assert _parse_args_in_yunohost_format({}, []) == {}


def test_parse_args_in_yunohost_format_string():
    questions = [{
        "name": "some_string",
        "type": "string",
    }]
    answers = {"some_string": "some_value"}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_default_type():
    questions = [{
        "name": "some_string",
    }]
    answers = {"some_string": "some_value"}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_no_input():
    questions = [{
        "name": "some_string",
    }]
    answers = {}

    with pytest.raises(YunohostError):
        _parse_args_in_yunohost_format(answers, questions)


def test_parse_args_in_yunohost_format_string_input():
    questions = [{
        "name": "some_string",
        "ask": "some question",
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


@pytest.mark.skip  # that shit should work x(
def test_parse_args_in_yunohost_format_string_input_no_ask():
    questions = [{
        "name": "some_string",
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_no_input_optional():
    questions = [{
        "name": "some_string",
        "optional": True,
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_optional_with_input():
    questions = [{
        "name": "some_string",
        "ask": "some question",
        "optional": True,
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


@pytest.mark.skip  # this should work without ask
def test_parse_args_in_yunohost_format_string_optional_with_input_without_ask():
    questions = [{
        "name": "some_string",
        "optional": True,
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_no_input_default():
    questions = [{
        "name": "some_string",
        "ask": "some question",
        "default": "some_value",
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_input_test_ask():
    ask_text = "some question"
    questions = [{
        "name": "some_string",
        "ask": ask_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(ask_text, False)


def test_parse_args_in_yunohost_format_string_input_test_ask_with_default():
    ask_text = "some question"
    default_text = "some example"
    questions = [{
        "name": "some_string",
        "ask": ask_text,
        "default": default_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with("%s (default: %s)" % (ask_text, default_text), False)


@pytest.mark.skip  # we should do something with this example
def test_parse_args_in_yunohost_format_string_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = [{
        "name": "some_string",
        "ask": ask_text,
        "example": example_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[0][0]
        assert example_text in prompt.call_args[0][0]


@pytest.mark.skip  # we should do something with this help
def test_parse_args_in_yunohost_format_string_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = [{
        "name": "some_string",
        "ask": ask_text,
        "help": help_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[0][0]
        assert help_text in prompt.call_args[0][0]


def test_parse_args_in_yunohost_format_string_with_choice():
    questions = [{
        "name": "some_string",
        "type": "string",
        "choices": ["fr", "en"]
    }]
    answers = {"some_string": "fr"}
    expected_result = OrderedDict({"some_string": ("fr", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_with_choice_prompt():
    questions = [{
        "name": "some_string",
        "type": "string",
        "choices": ["fr", "en"]
    }]
    answers = {"some_string": "fr"}
    expected_result = OrderedDict({"some_string": ("fr", "string")})
    with patch.object(msignals, "prompt", return_value="fr"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_string_with_choice_bad():
    questions = [{
        "name": "some_string",
        "type": "string",
        "choices": ["fr", "en"]
    }]
    answers = {"some_string": "bad"}

    with pytest.raises(YunohostError):
        assert _parse_args_in_yunohost_format(answers, questions)


def test_parse_args_in_yunohost_format_string_with_choice_ask():
    ask_text = "some question"
    choices = ["fr", "en", "es", "it", "ru"]
    questions = [{
        "name": "some_string",
        "ask": ask_text,
        "choices": choices,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="ru") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[0][0]

        for choice in choices:
            assert choice in prompt.call_args[0][0]


def test_parse_args_in_yunohost_format_string_with_choice_default():
    questions = [{
        "name": "some_string",
        "type": "string",
        "choices": ["fr", "en"],
        "default": "en",
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("en", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_password():
    questions = [{
        "name": "some_password",
        "type": "password",
    }]
    answers = {"some_password": "some_value"}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_password_default_type():
    questions = [{
        "name": "some_password",
        "type": "password",
    }]
    answers = {"some_password": "some_value"}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_password_no_input():
    questions = [{
        "name": "some_password",
        "type": "password",
    }]
    answers = {}

    with pytest.raises(YunohostError):
        _parse_args_in_yunohost_format(answers, questions)


def test_parse_args_in_yunohost_format_password_input():
    questions = [{
        "name": "some_password",
        "type": "password",
        "ask": "some question",
    }]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


@pytest.mark.skip  # that shit should work x(
def test_parse_args_in_yunohost_format_password_input_no_ask():
    questions = [{
        "name": "some_password",
        "type": "password",
    }]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_password_no_input_optional():
    questions = [{
        "name": "some_password",
        "type": "password",
        "optional": True,
    }]
    answers = {}
    expected_result = OrderedDict({"some_password": ("", "password")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result


def test_parse_args_in_yunohost_format_password_optional_with_input():
    questions = [{
        "name": "some_password",
        "ask": "some question",
        "type": "password",
        "optional": True,
    }]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


@pytest.mark.skip  # this should work without ask
def test_parse_args_in_yunohost_format_password_optional_with_input_without_ask():
    questions = [{
        "name": "some_password",
        "type": "password",
        "optional": True,
    }]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(msignals, "prompt", return_value="some_value"):
        assert _parse_args_in_yunohost_format(answers, questions) == expected_result


@pytest.mark.skip  # this should raises
def test_parse_args_in_yunohost_format_password_no_input_default():
    questions = [{
        "name": "some_password",
        "type": "password",
        "ask": "some question",
        "default": "some_value",
    }]
    answers = {}

    # no default for password!
    with pytest.raises(YunohostError):
        _parse_args_in_yunohost_format(answers, questions)


@pytest.mark.skip  # this should raises
def test_parse_args_in_yunohost_format_password_no_input_example():
    questions = [{
        "name": "some_password",
        "type": "password",
        "ask": "some question",
        "example": "some_value",
    }]
    answers = {"some_password": "some_value"}

    # no example for password!
    with pytest.raises(YunohostError):
        _parse_args_in_yunohost_format(answers, questions)


def test_parse_args_in_yunohost_format_password_input_test_ask():
    ask_text = "some question"
    questions = [{
        "name": "some_password",
        "type": "password",
        "ask": ask_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(ask_text, True)


@pytest.mark.skip  # we should do something with this example
def test_parse_args_in_yunohost_format_password_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = [{
        "name": "some_password",
        "type": "password",
        "ask": ask_text,
        "example": example_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[0][0]
        assert example_text in prompt.call_args[0][0]


@pytest.mark.skip  # we should do something with this help
def test_parse_args_in_yunohost_format_password_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = [{
        "name": "some_password",
        "type": "password",
        "ask": ask_text,
        "help": help_text,
    }]
    answers = {}

    with patch.object(msignals, "prompt", return_value="some_value") as prompt:
        _parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[0][0]
        assert help_text in prompt.call_args[0][0]
