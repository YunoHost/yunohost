import sys
import pytest
import os

from mock import patch, MagicMock
from io import StringIO
from collections import OrderedDict

from moulinette import Moulinette

from yunohost import domain, user
from yunohost.utils.config import (
    parse_args_in_yunohost_format,
    PasswordQuestion,
    Question,
)
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


def test_question_empty():
    assert parse_args_in_yunohost_format({}, []) == {}


def test_question_string():
    questions = [
        {
            "name": "some_string",
            "type": "string",
        }
    ]
    answers = {"some_string": "some_value"}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_default_type():
    questions = [
        {
            "name": "some_string",
        }
    ]
    answers = {"some_string": "some_value"}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_no_input():
    questions = [
        {
            "name": "some_string",
        }
    ]
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_string_input():
    questions = [
        {
            "name": "some_string",
            "ask": "some question",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_input_no_ask():
    questions = [
        {
            "name": "some_string",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_no_input_optional():
    questions = [
        {
            "name": "some_string",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("", "string")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_optional_with_input():
    questions = [
        {
            "name": "some_string",
            "ask": "some question",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_optional_with_empty_input():
    questions = [
        {
            "name": "some_string",
            "ask": "some question",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("", "string")})

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_optional_with_input_without_ask():
    questions = [
        {
            "name": "some_string",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_no_input_default():
    questions = [
        {
            "name": "some_string",
            "ask": "some question",
            "default": "some_value",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("some_value", "string")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_input_test_ask():
    ask_text = "some question"
    questions = [
        {
            "name": "some_string",
            "ask": ask_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill="",
            is_multiline=False,
        )


def test_question_string_input_test_ask_with_default():
    ask_text = "some question"
    default_text = "some example"
    questions = [
        {
            "name": "some_string",
            "ask": ask_text,
            "default": default_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill=default_text,
            is_multiline=False,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_string_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = [
        {
            "name": "some_string",
            "ask": ask_text,
            "example": example_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_string_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = [
        {
            "name": "some_string",
            "ask": ask_text,
            "help": help_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_text in prompt.call_args[1]["message"]


def test_question_string_with_choice():
    questions = [{"name": "some_string", "type": "string", "choices": ["fr", "en"]}]
    answers = {"some_string": "fr"}
    expected_result = OrderedDict({"some_string": ("fr", "string")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_with_choice_prompt():
    questions = [{"name": "some_string", "type": "string", "choices": ["fr", "en"]}]
    answers = {"some_string": "fr"}
    expected_result = OrderedDict({"some_string": ("fr", "string")})
    with patch.object(Moulinette, "prompt", return_value="fr"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_string_with_choice_bad():
    questions = [{"name": "some_string", "type": "string", "choices": ["fr", "en"]}]
    answers = {"some_string": "bad"}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions)


def test_question_string_with_choice_ask():
    ask_text = "some question"
    choices = ["fr", "en", "es", "it", "ru"]
    questions = [
        {
            "name": "some_string",
            "ask": ask_text,
            "choices": choices,
        }
    ]
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="ru") as prompt, patch.object(
        os, "isatty", return_value=True
    ):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]

        for choice in choices:
            assert choice in prompt.call_args[1]["message"]


def test_question_string_with_choice_default():
    questions = [
        {
            "name": "some_string",
            "type": "string",
            "choices": ["fr", "en"],
            "default": "en",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_string": ("en", "string")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password():
    questions = [
        {
            "name": "some_password",
            "type": "password",
        }
    ]
    answers = {"some_password": "some_value"}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_no_input():
    questions = [
        {
            "name": "some_password",
            "type": "password",
        }
    ]
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_password_input():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": "some question",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_input_no_ask():
    questions = [
        {
            "name": "some_password",
            "type": "password",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_no_input_optional():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_password": ("", "password")})

    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result

    questions = [
        {"name": "some_password", "type": "password", "optional": True, "default": ""}
    ]

    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_optional_with_input():
    questions = [
        {
            "name": "some_password",
            "ask": "some question",
            "type": "password",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_optional_with_empty_input():
    questions = [
        {
            "name": "some_password",
            "ask": "some question",
            "type": "password",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_password": ("", "password")})

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_optional_with_input_without_ask():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_password": ("some_value", "password")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_password_no_input_default():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": "some question",
            "default": "some_value",
        }
    ]
    answers = {}

    # no default for password!
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


@pytest.mark.skip  # this should raises
def test_question_password_no_input_example():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": "some question",
            "example": "some_value",
        }
    ]
    answers = {"some_password": "some_value"}

    # no example for password!
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_password_input_test_ask():
    ask_text = "some question"
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": ask_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=True,
            confirm=False,
            prefill="",
            is_multiline=False,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_password_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": ask_text,
            "example": example_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_password_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": ask_text,
            "help": help_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_text in prompt.call_args[1]["message"]


def test_question_password_bad_chars():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": "some question",
            "example": "some_value",
        }
    ]

    for i in PasswordQuestion.forbidden_chars:
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            parse_args_in_yunohost_format({"some_password": i * 8}, questions)


def test_question_password_strong_enough():
    questions = [
        {
            "name": "some_password",
            "type": "password",
            "ask": "some question",
            "example": "some_value",
        }
    ]

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        # too short
        parse_args_in_yunohost_format({"some_password": "a"}, questions)

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format({"some_password": "password"}, questions)


def test_question_password_optional_strong_enough():
    questions = [
        {
            "name": "some_password",
            "ask": "some question",
            "type": "password",
            "optional": True,
        }
    ]

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        # too short
        parse_args_in_yunohost_format({"some_password": "a"}, questions)

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format({"some_password": "password"}, questions)


def test_question_path():
    questions = [
        {
            "name": "some_path",
            "type": "path",
        }
    ]
    answers = {"some_path": "some_value"}
    expected_result = OrderedDict({"some_path": ("some_value", "path")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_no_input():
    questions = [
        {
            "name": "some_path",
            "type": "path",
        }
    ]
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_path_input():
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "ask": "some question",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("some_value", "path")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_input_no_ask():
    questions = [
        {
            "name": "some_path",
            "type": "path",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("some_value", "path")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_no_input_optional():
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("", "path")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_optional_with_input():
    questions = [
        {
            "name": "some_path",
            "ask": "some question",
            "type": "path",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("some_value", "path")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_optional_with_empty_input():
    questions = [
        {
            "name": "some_path",
            "ask": "some question",
            "type": "path",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("", "path")})

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_optional_with_input_without_ask():
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("some_value", "path")})

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_no_input_default():
    questions = [
        {
            "name": "some_path",
            "ask": "some question",
            "type": "path",
            "default": "some_value",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_path": ("some_value", "path")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_path_input_test_ask():
    ask_text = "some question"
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "ask": ask_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill="",
            is_multiline=False,
        )


def test_question_path_input_test_ask_with_default():
    ask_text = "some question"
    default_text = "some example"
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "ask": ask_text,
            "default": default_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill=default_text,
            is_multiline=False,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_path_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "ask": ask_text,
            "example": example_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_path_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = [
        {
            "name": "some_path",
            "type": "path",
            "ask": ask_text,
            "help": help_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_text in prompt.call_args[1]["message"]


def test_question_boolean():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
        }
    ]
    answers = {"some_boolean": "y"}
    expected_result = OrderedDict({"some_boolean": (1, "boolean")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_all_yes():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
        }
    ]
    expected_result = OrderedDict({"some_boolean": (1, "boolean")})
    assert (
        parse_args_in_yunohost_format({"some_boolean": "y"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "Y"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "yes"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "Yes"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "YES"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "1"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": 1}, questions) == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": True}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "True"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "TRUE"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "true"}, questions)
        == expected_result
    )


def test_question_boolean_all_no():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
        }
    ]
    expected_result = OrderedDict({"some_boolean": (0, "boolean")})
    assert (
        parse_args_in_yunohost_format({"some_boolean": "n"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "N"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "no"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "No"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "No"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "0"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": 0}, questions) == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": False}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "False"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "FALSE"}, questions)
        == expected_result
    )
    assert (
        parse_args_in_yunohost_format({"some_boolean": "false"}, questions)
        == expected_result
    )


# XXX apparently boolean are always False (0) by default, I'm not sure what to think about that
def test_question_boolean_no_input():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
        }
    ]
    answers = {}

    expected_result = OrderedDict({"some_boolean": (0, "boolean")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_bad_input():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
        }
    ]
    answers = {"some_boolean": "stuff"}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_boolean_input():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
            "ask": "some question",
        }
    ]
    answers = {}

    expected_result = OrderedDict({"some_boolean": (1, "boolean")})
    with patch.object(Moulinette, "prompt", return_value="y"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result

    expected_result = OrderedDict({"some_boolean": (0, "boolean")})
    with patch.object(Moulinette, "prompt", return_value="n"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_input_no_ask():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_boolean": (1, "boolean")})

    with patch.object(Moulinette, "prompt", return_value="y"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_no_input_optional():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_boolean": (0, "boolean")})  # default to false
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_optional_with_input():
    questions = [
        {
            "name": "some_boolean",
            "ask": "some question",
            "type": "boolean",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_boolean": (1, "boolean")})

    with patch.object(Moulinette, "prompt", return_value="y"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_optional_with_empty_input():
    questions = [
        {
            "name": "some_boolean",
            "ask": "some question",
            "type": "boolean",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_boolean": (0, "boolean")})  # default to false

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_optional_with_input_without_ask():
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_boolean": (0, "boolean")})

    with patch.object(Moulinette, "prompt", return_value="n"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_no_input_default():
    questions = [
        {
            "name": "some_boolean",
            "ask": "some question",
            "type": "boolean",
            "default": 0,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_boolean": (0, "boolean")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_boolean_bad_default():
    questions = [
        {
            "name": "some_boolean",
            "ask": "some question",
            "type": "boolean",
            "default": "bad default",
        }
    ]
    answers = {}
    with pytest.raises(YunohostError):
        parse_args_in_yunohost_format(answers, questions)


def test_question_boolean_input_test_ask():
    ask_text = "some question"
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
            "ask": ask_text,
        }
    ]
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=0) as prompt, patch.object(
        os, "isatty", return_value=True
    ):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text + " [yes | no]",
            is_password=False,
            confirm=False,
            prefill="no",
            is_multiline=False,
        )


def test_question_boolean_input_test_ask_with_default():
    ask_text = "some question"
    default_text = 1
    questions = [
        {
            "name": "some_boolean",
            "type": "boolean",
            "ask": ask_text,
            "default": default_text,
        }
    ]
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=1) as prompt, patch.object(
        os, "isatty", return_value=True
    ):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text + " [yes | no]",
            is_password=False,
            confirm=False,
            prefill="yes",
            is_multiline=False,
        )


def test_question_domain_empty():
    questions = [
        {
            "name": "some_domain",
            "type": "domain",
        }
    ]
    main_domain = "my_main_domain.com"
    expected_result = OrderedDict({"some_domain": (main_domain, "domain")})
    answers = {}

    with patch.object(
        domain, "_get_maindomain", return_value="my_main_domain.com"
    ), patch.object(
        domain, "domain_list", return_value={"domains": [main_domain]}
    ), patch.object(
        os, "isatty", return_value=False
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_domain():
    main_domain = "my_main_domain.com"
    domains = [main_domain]
    questions = [
        {
            "name": "some_domain",
            "type": "domain",
        }
    ]

    answers = {"some_domain": main_domain}
    expected_result = OrderedDict({"some_domain": (main_domain, "domain")})

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_domain_two_domains():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = [
        {
            "name": "some_domain",
            "type": "domain",
        }
    ]
    answers = {"some_domain": other_domain}
    expected_result = OrderedDict({"some_domain": (other_domain, "domain")})

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result

    answers = {"some_domain": main_domain}
    expected_result = OrderedDict({"some_domain": (main_domain, "domain")})

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_domain_two_domains_wrong_answer():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = [
        {
            "name": "some_domain",
            "type": "domain",
        }
    ]
    answers = {"some_domain": "doesnt_exist.pouet"}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            parse_args_in_yunohost_format(answers, questions)


def test_question_domain_two_domains_default_no_ask():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = [
        {
            "name": "some_domain",
            "type": "domain",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_domain": (main_domain, "domain")})

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(
        domain, "domain_list", return_value={"domains": domains}
    ), patch.object(
        os, "isatty", return_value=False
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_domain_two_domains_default():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = [{"name": "some_domain", "type": "domain", "ask": "choose a domain"}]
    answers = {}
    expected_result = OrderedDict({"some_domain": (main_domain, "domain")})

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(
        domain, "domain_list", return_value={"domains": domains}
    ), patch.object(
        os, "isatty", return_value=False
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_domain_two_domains_default_input():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = [{"name": "some_domain", "type": "domain", "ask": "choose a domain"}]
    answers = {}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(
        domain, "domain_list", return_value={"domains": domains}
    ), patch.object(
        os, "isatty", return_value=True
    ):
        expected_result = OrderedDict({"some_domain": (main_domain, "domain")})
        with patch.object(Moulinette, "prompt", return_value=main_domain):
            assert parse_args_in_yunohost_format(answers, questions) == expected_result

        expected_result = OrderedDict({"some_domain": (other_domain, "domain")})
        with patch.object(Moulinette, "prompt", return_value=other_domain):
            assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_user_empty():
    users = {
        "some_user": {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "p@ynh.local",
            "fullname": "the first name the last name",
        }
    }

    questions = [
        {
            "name": "some_user",
            "type": "user",
        }
    ]
    answers = {}

    with patch.object(user, "user_list", return_value={"users": users}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            parse_args_in_yunohost_format(answers, questions)


def test_question_user():
    username = "some_user"
    users = {
        username: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "p@ynh.local",
            "fullname": "the first name the last name",
        }
    }

    questions = [
        {
            "name": "some_user",
            "type": "user",
        }
    ]
    answers = {"some_user": username}

    expected_result = OrderedDict({"some_user": (username, "user")})

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        user, "user_info", return_value={}
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_user_two_users():
    username = "some_user"
    other_user = "some_other_user"
    users = {
        username: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "p@ynh.local",
            "fullname": "the first name the last name",
        },
        other_user: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "z@ynh.local",
            "fullname": "john doe",
        },
    }

    questions = [
        {
            "name": "some_user",
            "type": "user",
        }
    ]
    answers = {"some_user": other_user}
    expected_result = OrderedDict({"some_user": (other_user, "user")})

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        user, "user_info", return_value={}
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result

    answers = {"some_user": username}
    expected_result = OrderedDict({"some_user": (username, "user")})

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        user, "user_info", return_value={}
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_user_two_users_wrong_answer():
    username = "my_username.com"
    other_user = "some_other_user"
    users = {
        username: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "p@ynh.local",
            "fullname": "the first name the last name",
        },
        other_user: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "z@ynh.local",
            "fullname": "john doe",
        },
    }

    questions = [
        {
            "name": "some_user",
            "type": "user",
        }
    ]
    answers = {"some_user": "doesnt_exist.pouet"}

    with patch.object(user, "user_list", return_value={"users": users}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            parse_args_in_yunohost_format(answers, questions)


def test_question_user_two_users_no_default():
    username = "my_username.com"
    other_user = "some_other_user.tld"
    users = {
        username: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "p@ynh.local",
            "fullname": "the first name the last name",
        },
        other_user: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "z@ynh.local",
            "fullname": "john doe",
        },
    }

    questions = [{"name": "some_user", "type": "user", "ask": "choose a user"}]
    answers = {}

    with patch.object(user, "user_list", return_value={"users": users}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            parse_args_in_yunohost_format(answers, questions)


def test_question_user_two_users_default_input():
    username = "my_username.com"
    other_user = "some_other_user.tld"
    users = {
        username: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "p@ynh.local",
            "fullname": "the first name the last name",
        },
        other_user: {
            "ssh_allowed": False,
            "username": "some_user",
            "mailbox-quota": "0",
            "mail": "z@ynh.local",
            "fullname": "john doe",
        },
    }

    questions = [{"name": "some_user", "type": "user", "ask": "choose a user"}]
    answers = {}

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        os, "isatty", return_value=True
    ):
        with patch.object(user, "user_info", return_value={}):
            expected_result = OrderedDict({"some_user": (username, "user")})
            with patch.object(Moulinette, "prompt", return_value=username):
                assert (
                    parse_args_in_yunohost_format(answers, questions) == expected_result
                )

            expected_result = OrderedDict({"some_user": (other_user, "user")})
            with patch.object(Moulinette, "prompt", return_value=other_user):
                assert (
                    parse_args_in_yunohost_format(answers, questions) == expected_result
                )


def test_question_number():
    questions = [
        {
            "name": "some_number",
            "type": "number",
        }
    ]
    answers = {"some_number": 1337}
    expected_result = OrderedDict({"some_number": (1337, "number")})
    assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_no_input():
    questions = [
        {
            "name": "some_number",
            "type": "number",
        }
    ]
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_number_bad_input():
    questions = [
        {
            "name": "some_number",
            "type": "number",
        }
    ]
    answers = {"some_number": "stuff"}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)

    answers = {"some_number": 1.5}
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_number_input():
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "ask": "some question",
        }
    ]
    answers = {}

    expected_result = OrderedDict({"some_number": (1337, "number")})
    with patch.object(Moulinette, "prompt", return_value="1337"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result

    with patch.object(Moulinette, "prompt", return_value=1337), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result

    expected_result = OrderedDict({"some_number": (0, "number")})
    with patch.object(Moulinette, "prompt", return_value="0"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_input_no_ask():
    questions = [
        {
            "name": "some_number",
            "type": "number",
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_number": (1337, "number")})

    with patch.object(Moulinette, "prompt", return_value="1337"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_no_input_optional():
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_number": (None, "number")})  # default to 0
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_optional_with_input():
    questions = [
        {
            "name": "some_number",
            "ask": "some question",
            "type": "number",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_number": (1337, "number")})

    with patch.object(Moulinette, "prompt", return_value="1337"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_optional_with_input_without_ask():
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "optional": True,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_number": (0, "number")})

    with patch.object(Moulinette, "prompt", return_value="0"), patch.object(
        os, "isatty", return_value=True
    ):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_no_input_default():
    questions = [
        {
            "name": "some_number",
            "ask": "some question",
            "type": "number",
            "default": 1337,
        }
    ]
    answers = {}
    expected_result = OrderedDict({"some_number": (1337, "number")})
    with patch.object(os, "isatty", return_value=False):
        assert parse_args_in_yunohost_format(answers, questions) == expected_result


def test_question_number_bad_default():
    questions = [
        {
            "name": "some_number",
            "ask": "some question",
            "type": "number",
            "default": "bad default",
        }
    ]
    answers = {}
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        parse_args_in_yunohost_format(answers, questions)


def test_question_number_input_test_ask():
    ask_text = "some question"
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "ask": ask_text,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill="",
            is_multiline=False,
        )


def test_question_number_input_test_ask_with_default():
    ask_text = "some question"
    default_value = 1337
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "ask": ask_text,
            "default": default_value,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill=str(default_value),
            is_multiline=False,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_number_input_test_ask_with_example():
    ask_text = "some question"
    example_value = 1337
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "ask": ask_text,
            "example": example_value,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_value in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_number_input_test_ask_with_help():
    ask_text = "some question"
    help_value = 1337
    questions = [
        {
            "name": "some_number",
            "type": "number",
            "ask": ask_text,
            "help": help_value,
        }
    ]
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        parse_args_in_yunohost_format(answers, questions)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_value in prompt.call_args[1]["message"]


def test_question_display_text():
    questions = [{"name": "some_app", "type": "display_text", "ask": "foobar"}]
    answers = {}

    with patch.object(sys, "stdout", new_callable=StringIO) as stdout, patch.object(
        os, "isatty", return_value=True
    ):
        parse_args_in_yunohost_format(answers, questions)
        assert "foobar" in stdout.getvalue()
