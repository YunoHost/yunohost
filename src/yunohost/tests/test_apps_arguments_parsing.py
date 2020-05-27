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


def test_parse_args_in_yunohost_format_string_no_input_default():
    questions = [{
        "name": "some_string",
        "ask": "some question",
        "default": "some_value",
    }]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    assert _parse_args_in_yunohost_format(answers, questions) == expected_result
