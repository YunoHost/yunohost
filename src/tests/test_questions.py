import sys
import pytest
import os

from mock import patch
from io import StringIO

from moulinette import Moulinette

from yunohost import domain, user
from yunohost.utils.config import (
    ask_questions_and_parse_answers,
    PasswordQuestion,
    DomainQuestion,
    PathQuestion,
    BooleanQuestion,
    FileQuestion,
    evaluate_simple_js_expression,
)
from yunohost.utils.error import YunohostError, YunohostValidationError


"""
Argument default format:
{
    "the_name": {
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
}

User answers:
{"the_name": "value", ...}
"""


def test_question_empty():
    ask_questions_and_parse_answers({}, {}) == []


def test_question_string():

    questions = {
        "some_string": {
            "type": "string",
        }
    }
    answers = {"some_string": "some_value"}

    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_from_query_string():

    questions = {
        "some_string": {
            "type": "string",
        }
    }
    answers = "foo=bar&some_string=some_value&lorem=ipsum"

    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_default_type():
    questions = {"some_string": {}}
    answers = {"some_string": "some_value"}

    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_no_input():
    questions = {"some_string": {}}
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_string_input():
    questions = {
        "some_string": {
            "ask": "some question",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_input_no_ask():
    questions = {"some_string": {}}
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_no_input_optional():
    questions = {"some_string": {"optional": True}}
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == ""


def test_question_string_optional_with_input():
    questions = {
        "some_string": {
            "ask": "some question",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_optional_with_empty_input():
    questions = {
        "some_string": {
            "ask": "some question",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == ""


def test_question_string_optional_with_input_without_ask():
    questions = {
        "some_string": {
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_no_input_default():
    questions = {
        "some_string": {
            "ask": "some question",
            "default": "some_value",
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


def test_question_string_input_test_ask():
    ask_text = "some question"
    questions = {
        "some_string": {
            "ask": ask_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill="",
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


def test_question_string_input_test_ask_with_default():
    ask_text = "some question"
    default_text = "some example"
    questions = {
        "some_string": {
            "ask": ask_text,
            "default": default_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill=default_text,
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_string_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = {
        "some_string": {
            "ask": ask_text,
            "example": example_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_string_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = {
        "some_string": {
            "ask": ask_text,
            "help": help_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_text in prompt.call_args[1]["message"]


def test_question_string_with_choice():
    questions = {"some_string": {"type": "string", "choices": ["fr", "en"]}}
    answers = {"some_string": "fr"}
    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "fr"


def test_question_string_with_choice_prompt():
    questions = {"some_string": {"type": "string", "choices": ["fr", "en"]}}
    answers = {"some_string": "fr"}
    with patch.object(Moulinette, "prompt", return_value="fr"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "fr"


def test_question_string_with_choice_bad():
    questions = {"some_string": {"type": "string", "choices": ["fr", "en"]}}
    answers = {"some_string": "bad"}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_string_with_choice_ask():
    ask_text = "some question"
    choices = ["fr", "en", "es", "it", "ru"]
    questions = {
        "some_string": {
            "ask": ask_text,
            "choices": choices,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="ru") as prompt, patch.object(
        os, "isatty", return_value=True
    ):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]

        for choice in choices:
            assert choice in prompt.call_args[1]["message"]


def test_question_string_with_choice_default():
    questions = {
        "some_string": {
            "type": "string",
            "choices": ["fr", "en"],
            "default": "en",
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "en"


def test_question_password():
    questions = {
        "some_password": {
            "type": "password",
        }
    }
    answers = {"some_password": "some_value"}
    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == "some_value"


def test_question_password_no_input():
    questions = {
        "some_password": {
            "type": "password",
        }
    }
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_password_input():
    questions = {
        "some_password": {
            "type": "password",
            "ask": "some question",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == "some_value"


def test_question_password_input_no_ask():
    questions = {
        "some_password": {
            "type": "password",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == "some_value"


def test_question_password_no_input_optional():
    questions = {
        "some_password": {
            "type": "password",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == ""

    questions = {"some_password": {"type": "password", "optional": True, "default": ""}}

    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == ""


def test_question_password_optional_with_input():
    questions = {
        "some_password": {
            "ask": "some question",
            "type": "password",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == "some_value"


def test_question_password_optional_with_empty_input():
    questions = {
        "some_password": {
            "ask": "some question",
            "type": "password",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == ""


def test_question_password_optional_with_input_without_ask():
    questions = {
        "some_password": {
            "type": "password",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_password"
    assert out.type == "password"
    assert out.value == "some_value"


def test_question_password_no_input_default():
    questions = {
        "some_password": {
            "type": "password",
            "ask": "some question",
            "default": "some_value",
        }
    }
    answers = {}

    # no default for password!
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


@pytest.mark.skip  # this should raises
def test_question_password_no_input_example():
    questions = {
        "some_password": {
            "type": "password",
            "ask": "some question",
            "example": "some_value",
        }
    }
    answers = {"some_password": "some_value"}

    # no example for password!
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_password_input_test_ask():
    ask_text = "some question"
    questions = {
        "some_password": {
            "type": "password",
            "ask": ask_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=True,
            confirm=False,
            prefill="",
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_password_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = {
        "some_password": {
            "type": "password",
            "ask": ask_text,
            "example": example_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_password_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = {
        "some_password": {
            "type": "password",
            "ask": ask_text,
            "help": help_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_text in prompt.call_args[1]["message"]


def test_question_password_bad_chars():
    questions = {
        "some_password": {
            "type": "password",
            "ask": "some question",
            "example": "some_value",
        }
    }

    for i in PasswordQuestion.forbidden_chars:
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            ask_questions_and_parse_answers(questions, {"some_password": i * 8})


def test_question_password_strong_enough():
    questions = {
        "some_password": {
            "type": "password",
            "ask": "some question",
            "example": "some_value",
        }
    }

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        # too short
        ask_questions_and_parse_answers(questions, {"some_password": "a"})

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, {"some_password": "password"})


def test_question_password_optional_strong_enough():
    questions = {
        "some_password": {
            "ask": "some question",
            "type": "password",
            "optional": True,
        }
    }

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        # too short
        ask_questions_and_parse_answers(questions, {"some_password": "a"})

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, {"some_password": "password"})


def test_question_path():
    questions = {
        "some_path": {
            "type": "path",
        }
    }
    answers = {"some_path": "/some_value"}
    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == "/some_value"


def test_question_path_no_input():
    questions = {
        "some_path": {
            "type": "path",
        }
    }
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_path_input():
    questions = {
        "some_path": {
            "type": "path",
            "ask": "some question",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="/some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == "/some_value"


def test_question_path_input_no_ask():
    questions = {
        "some_path": {
            "type": "path",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="/some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == "/some_value"


def test_question_path_no_input_optional():
    questions = {
        "some_path": {
            "type": "path",
            "optional": True,
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == ""


def test_question_path_optional_with_input():
    questions = {
        "some_path": {
            "ask": "some question",
            "type": "path",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="/some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == "/some_value"


def test_question_path_optional_with_empty_input():
    questions = {
        "some_path": {
            "ask": "some question",
            "type": "path",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == ""


def test_question_path_optional_with_input_without_ask():
    questions = {
        "some_path": {
            "type": "path",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="/some_value"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == "/some_value"


def test_question_path_no_input_default():
    questions = {
        "some_path": {
            "ask": "some question",
            "type": "path",
            "default": "some_value",
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_path"
    assert out.type == "path"
    assert out.value == "/some_value"


def test_question_path_input_test_ask():
    ask_text = "some question"
    questions = {
        "some_path": {
            "type": "path",
            "ask": ask_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill="",
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


def test_question_path_input_test_ask_with_default():
    ask_text = "some question"
    default_text = "someexample"
    questions = {
        "some_path": {
            "type": "path",
            "ask": ask_text,
            "default": default_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill=default_text,
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_path_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = {
        "some_path": {
            "type": "path",
            "ask": ask_text,
            "example": example_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_path_input_test_ask_with_help():
    ask_text = "some question"
    help_text = "some_help"
    questions = {
        "some_path": {
            "type": "path",
            "ask": ask_text,
            "help": help_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_text in prompt.call_args[1]["message"]


def test_question_boolean():
    questions = {
        "some_boolean": {
            "type": "boolean",
        }
    }
    answers = {"some_boolean": "y"}
    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_boolean"
    assert out.type == "boolean"
    assert out.value == 1


def test_question_boolean_all_yes():
    questions = {
        "some_boolean": {
            "type": "boolean",
        }
    }

    for value in ["Y", "yes", "Yes", "YES", "1", 1, True, "True", "TRUE", "true"]:
        out = ask_questions_and_parse_answers(questions, {"some_boolean": value})[0]
        assert out.name == "some_boolean"
        assert out.type == "boolean"
        assert out.value == 1


def test_question_boolean_all_no():
    questions = {
        "some_boolean": {
            "type": "boolean",
        }
    }

    for value in ["n", "N", "no", "No", "No", "0", 0, False, "False", "FALSE", "false"]:
        out = ask_questions_and_parse_answers(questions, {"some_boolean": value})[0]
        assert out.name == "some_boolean"
        assert out.type == "boolean"
        assert out.value == 0


# XXX apparently boolean are always False (0) by default, I'm not sure what to think about that
def test_question_boolean_no_input():
    questions = {
        "some_boolean": {
            "type": "boolean",
        }
    }
    answers = {}

    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.value == 0


def test_question_boolean_bad_input():
    questions = {
        "some_boolean": {
            "type": "boolean",
        }
    }
    answers = {"some_boolean": "stuff"}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_boolean_input():
    questions = {
        "some_boolean": {
            "type": "boolean",
            "ask": "some question",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="y"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]
    assert out.value == 1

    with patch.object(Moulinette, "prompt", return_value="n"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]
    assert out.value == 0


def test_question_boolean_input_no_ask():
    questions = {
        "some_boolean": {
            "type": "boolean",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="y"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]
    assert out.value == 1


def test_question_boolean_no_input_optional():
    questions = {
        "some_boolean": {
            "type": "boolean",
            "optional": True,
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]
    assert out.value == 0


def test_question_boolean_optional_with_input():
    questions = {
        "some_boolean": {
            "ask": "some question",
            "type": "boolean",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="y"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]
    assert out.value == 1


def test_question_boolean_optional_with_empty_input():
    questions = {
        "some_boolean": {
            "ask": "some question",
            "type": "boolean",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=""), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.value == 0


def test_question_boolean_optional_with_input_without_ask():
    questions = {
        "some_boolean": {
            "type": "boolean",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="n"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.value == 0


def test_question_boolean_no_input_default():
    questions = {
        "some_boolean": {
            "ask": "some question",
            "type": "boolean",
            "default": 0,
        }
    }
    answers = {}

    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.value == 0


def test_question_boolean_bad_default():
    questions = {
        "some_boolean": {
            "ask": "some question",
            "type": "boolean",
            "default": "bad default",
        }
    }
    answers = {}
    with pytest.raises(YunohostError):
        ask_questions_and_parse_answers(questions, answers)


def test_question_boolean_input_test_ask():
    ask_text = "some question"
    questions = {
        "some_boolean": {
            "type": "boolean",
            "ask": ask_text,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=0) as prompt, patch.object(
        os, "isatty", return_value=True
    ):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text + " [yes | no]",
            is_password=False,
            confirm=False,
            prefill="no",
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


def test_question_boolean_input_test_ask_with_default():
    ask_text = "some question"
    default_text = 1
    questions = {
        "some_boolean": {
            "type": "boolean",
            "ask": ask_text,
            "default": default_text,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value=1) as prompt, patch.object(
        os, "isatty", return_value=True
    ):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text + " [yes | no]",
            is_password=False,
            confirm=False,
            prefill="yes",
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


def test_question_domain_empty():
    questions = {
        "some_domain": {
            "type": "domain",
        }
    }
    main_domain = "my_main_domain.com"
    answers = {}

    with patch.object(
        domain, "_get_maindomain", return_value="my_main_domain.com"
    ), patch.object(
        domain, "domain_list", return_value={"domains": [main_domain]}
    ), patch.object(
        os, "isatty", return_value=False
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_domain"
    assert out.type == "domain"
    assert out.value == main_domain


def test_question_domain():
    main_domain = "my_main_domain.com"
    domains = [main_domain]
    questions = {
        "some_domain": {
            "type": "domain",
        }
    }

    answers = {"some_domain": main_domain}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_domain"
    assert out.type == "domain"
    assert out.value == main_domain


def test_question_domain_two_domains():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = {
        "some_domain": {
            "type": "domain",
        }
    }
    answers = {"some_domain": other_domain}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_domain"
    assert out.type == "domain"
    assert out.value == other_domain

    answers = {"some_domain": main_domain}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_domain"
    assert out.type == "domain"
    assert out.value == main_domain


def test_question_domain_two_domains_wrong_answer():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = {
        "some_domain": {
            "type": "domain",
        }
    }
    answers = {"some_domain": "doesnt_exist.pouet"}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(domain, "domain_list", return_value={"domains": domains}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            ask_questions_and_parse_answers(questions, answers)


def test_question_domain_two_domains_default_no_ask():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = {
        "some_domain": {
            "type": "domain",
        }
    }
    answers = {}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(
        domain, "domain_list", return_value={"domains": domains}
    ), patch.object(
        os, "isatty", return_value=False
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_domain"
    assert out.type == "domain"
    assert out.value == main_domain


def test_question_domain_two_domains_default():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = {"some_domain": {"type": "domain", "ask": "choose a domain"}}
    answers = {}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(
        domain, "domain_list", return_value={"domains": domains}
    ), patch.object(
        os, "isatty", return_value=False
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_domain"
    assert out.type == "domain"
    assert out.value == main_domain


def test_question_domain_two_domains_default_input():
    main_domain = "my_main_domain.com"
    other_domain = "some_other_domain.tld"
    domains = [main_domain, other_domain]

    questions = {"some_domain": {"type": "domain", "ask": "choose a domain"}}
    answers = {}

    with patch.object(
        domain, "_get_maindomain", return_value=main_domain
    ), patch.object(
        domain, "domain_list", return_value={"domains": domains}
    ), patch.object(
        os, "isatty", return_value=True
    ):
        with patch.object(Moulinette, "prompt", return_value=main_domain):
            out = ask_questions_and_parse_answers(questions, answers)[0]

        assert out.name == "some_domain"
        assert out.type == "domain"
        assert out.value == main_domain

        with patch.object(Moulinette, "prompt", return_value=other_domain):
            out = ask_questions_and_parse_answers(questions, answers)[0]

        assert out.name == "some_domain"
        assert out.type == "domain"
        assert out.value == other_domain


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

    questions = {
        "some_user": {
            "type": "user",
        }
    }
    answers = {}

    with patch.object(user, "user_list", return_value={"users": users}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            ask_questions_and_parse_answers(questions, answers)


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

    questions = {
        "some_user": {
            "type": "user",
        }
    }
    answers = {"some_user": username}

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        user, "user_info", return_value={}
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_user"
    assert out.type == "user"
    assert out.value == username


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

    questions = {
        "some_user": {
            "type": "user",
        }
    }
    answers = {"some_user": other_user}

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        user, "user_info", return_value={}
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_user"
    assert out.type == "user"
    assert out.value == other_user

    answers = {"some_user": username}

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        user, "user_info", return_value={}
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_user"
    assert out.type == "user"
    assert out.value == username


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

    questions = {
        "some_user": {
            "type": "user",
        }
    }
    answers = {"some_user": "doesnt_exist.pouet"}

    with patch.object(user, "user_list", return_value={"users": users}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            ask_questions_and_parse_answers(questions, answers)


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

    questions = {"some_user": {"type": "user", "ask": "choose a user"}}
    answers = {}

    with patch.object(user, "user_list", return_value={"users": users}):
        with pytest.raises(YunohostError), patch.object(
            os, "isatty", return_value=False
        ):
            ask_questions_and_parse_answers(questions, answers)


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

    questions = {"some_user": {"type": "user", "ask": "choose a user"}}
    answers = {}

    with patch.object(user, "user_list", return_value={"users": users}), patch.object(
        os, "isatty", return_value=True
    ):
        with patch.object(user, "user_info", return_value={}):

            with patch.object(Moulinette, "prompt", return_value=username):
                out = ask_questions_and_parse_answers(questions, answers)[0]

            assert out.name == "some_user"
            assert out.type == "user"
            assert out.value == username

            with patch.object(Moulinette, "prompt", return_value=other_user):
                out = ask_questions_and_parse_answers(questions, answers)[0]

            assert out.name == "some_user"
            assert out.type == "user"
            assert out.value == other_user


def test_question_number():
    questions = {
        "some_number": {
            "type": "number",
        }
    }
    answers = {"some_number": 1337}
    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 1337


def test_question_number_no_input():
    questions = {
        "some_number": {
            "type": "number",
        }
    }
    answers = {}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_number_bad_input():
    questions = {
        "some_number": {
            "type": "number",
        }
    }
    answers = {"some_number": "stuff"}

    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)

    answers = {"some_number": 1.5}
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_number_input():
    questions = {
        "some_number": {
            "type": "number",
            "ask": "some question",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="1337"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 1337

    with patch.object(Moulinette, "prompt", return_value=1337), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 1337

    with patch.object(Moulinette, "prompt", return_value="0"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 0


def test_question_number_input_no_ask():
    questions = {
        "some_number": {
            "type": "number",
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="1337"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 1337


def test_question_number_no_input_optional():
    questions = {
        "some_number": {
            "type": "number",
            "optional": True,
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value is None


def test_question_number_optional_with_input():
    questions = {
        "some_number": {
            "ask": "some question",
            "type": "number",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="1337"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 1337


def test_question_number_optional_with_input_without_ask():
    questions = {
        "some_number": {
            "type": "number",
            "optional": True,
        }
    }
    answers = {}

    with patch.object(Moulinette, "prompt", return_value="0"), patch.object(
        os, "isatty", return_value=True
    ):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 0


def test_question_number_no_input_default():
    questions = {
        "some_number": {
            "ask": "some question",
            "type": "number",
            "default": 1337,
        }
    }
    answers = {}
    with patch.object(os, "isatty", return_value=False):
        out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_number"
    assert out.type == "number"
    assert out.value == 1337


def test_question_number_bad_default():
    questions = {
        "some_number": {
            "ask": "some question",
            "type": "number",
            "default": "bad default",
        }
    }
    answers = {}
    with pytest.raises(YunohostError), patch.object(os, "isatty", return_value=False):
        ask_questions_and_parse_answers(questions, answers)


def test_question_number_input_test_ask():
    ask_text = "some question"
    questions = {
        "some_number": {
            "type": "number",
            "ask": ask_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill="",
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


def test_question_number_input_test_ask_with_default():
    ask_text = "some question"
    default_value = 1337
    questions = {
        "some_number": {
            "type": "number",
            "ask": ask_text,
            "default": default_value,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        prompt.assert_called_with(
            message=ask_text,
            is_password=False,
            confirm=False,
            prefill=str(default_value),
            is_multiline=False,
            autocomplete=[],
            help=None,
        )


@pytest.mark.skip  # we should do something with this example
def test_question_number_input_test_ask_with_example():
    ask_text = "some question"
    example_value = 1337
    questions = {
        "some_number": {
            "type": "number",
            "ask": ask_text,
            "example": example_value,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_value in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this help
def test_question_number_input_test_ask_with_help():
    ask_text = "some question"
    help_value = 1337
    questions = {
        "some_number": {
            "type": "number",
            "ask": ask_text,
            "help": help_value,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert help_value in prompt.call_args[1]["message"]


def test_question_display_text():
    questions = {"some_app": {"type": "display_text", "ask": "foobar"}}
    answers = {}

    with patch.object(sys, "stdout", new_callable=StringIO) as stdout, patch.object(
        os, "isatty", return_value=True
    ):
        ask_questions_and_parse_answers(questions, answers)
        assert "foobar" in stdout.getvalue()


def test_question_file_from_cli():

    FileQuestion.clean_upload_dirs()

    filename = "/tmp/ynh_test_question_file"
    os.system(f"rm -f {filename}")
    os.system(f"echo helloworld > {filename}")

    questions = {
        "some_file": {
            "type": "file",
        }
    }
    answers = {"some_file": filename}

    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_file"
    assert out.type == "file"

    # The file is supposed to be copied somewhere else
    assert out.value != filename
    assert out.value.startswith("/tmp/")
    assert os.path.exists(out.value)
    assert "helloworld" in open(out.value).read().strip()

    FileQuestion.clean_upload_dirs()

    assert not os.path.exists(out.value)


def test_question_file_from_api():

    FileQuestion.clean_upload_dirs()

    from base64 import b64encode

    b64content = b64encode(b"helloworld")
    questions = {
        "some_file": {
            "type": "file",
        }
    }
    answers = {"some_file": b64content}

    interface_type_bkp = Moulinette.interface.type
    try:
        Moulinette.interface.type = "api"
        out = ask_questions_and_parse_answers(questions, answers)[0]
    finally:
        Moulinette.interface.type = interface_type_bkp

    assert out.name == "some_file"
    assert out.type == "file"

    assert out.value.startswith("/tmp/")
    assert os.path.exists(out.value)
    assert "helloworld" in open(out.value).read().strip()

    FileQuestion.clean_upload_dirs()

    assert not os.path.exists(out.value)


def test_normalize_boolean_nominal():

    assert BooleanQuestion.normalize("yes") == 1
    assert BooleanQuestion.normalize("Yes") == 1
    assert BooleanQuestion.normalize(" yes  ") == 1
    assert BooleanQuestion.normalize("y") == 1
    assert BooleanQuestion.normalize("true") == 1
    assert BooleanQuestion.normalize("True") == 1
    assert BooleanQuestion.normalize("on") == 1
    assert BooleanQuestion.normalize("1") == 1
    assert BooleanQuestion.normalize(1) == 1

    assert BooleanQuestion.normalize("no") == 0
    assert BooleanQuestion.normalize("No") == 0
    assert BooleanQuestion.normalize(" no  ") == 0
    assert BooleanQuestion.normalize("n") == 0
    assert BooleanQuestion.normalize("false") == 0
    assert BooleanQuestion.normalize("False") == 0
    assert BooleanQuestion.normalize("off") == 0
    assert BooleanQuestion.normalize("0") == 0
    assert BooleanQuestion.normalize(0) == 0

    assert BooleanQuestion.normalize("") is None
    assert BooleanQuestion.normalize("   ") is None
    assert BooleanQuestion.normalize(" none   ") is None
    assert BooleanQuestion.normalize("None") is None
    assert BooleanQuestion.normalize("noNe") is None
    assert BooleanQuestion.normalize(None) is None


def test_normalize_boolean_humanize():

    assert BooleanQuestion.humanize("yes") == "yes"
    assert BooleanQuestion.humanize("true") == "yes"
    assert BooleanQuestion.humanize("on") == "yes"

    assert BooleanQuestion.humanize("no") == "no"
    assert BooleanQuestion.humanize("false") == "no"
    assert BooleanQuestion.humanize("off") == "no"


def test_normalize_boolean_invalid():

    with pytest.raises(YunohostValidationError):
        BooleanQuestion.normalize("yesno")
    with pytest.raises(YunohostValidationError):
        BooleanQuestion.normalize("foobar")
    with pytest.raises(YunohostValidationError):
        BooleanQuestion.normalize("enabled")


def test_normalize_boolean_special_yesno():

    customyesno = {"yes": "enabled", "no": "disabled"}

    assert BooleanQuestion.normalize("yes", customyesno) == "enabled"
    assert BooleanQuestion.normalize("true", customyesno) == "enabled"
    assert BooleanQuestion.normalize("enabled", customyesno) == "enabled"
    assert BooleanQuestion.humanize("yes", customyesno) == "yes"
    assert BooleanQuestion.humanize("true", customyesno) == "yes"
    assert BooleanQuestion.humanize("enabled", customyesno) == "yes"

    assert BooleanQuestion.normalize("no", customyesno) == "disabled"
    assert BooleanQuestion.normalize("false", customyesno) == "disabled"
    assert BooleanQuestion.normalize("disabled", customyesno) == "disabled"
    assert BooleanQuestion.humanize("no", customyesno) == "no"
    assert BooleanQuestion.humanize("false", customyesno) == "no"
    assert BooleanQuestion.humanize("disabled", customyesno) == "no"


def test_normalize_domain():

    assert DomainQuestion.normalize("https://yolo.swag/") == "yolo.swag"
    assert DomainQuestion.normalize("http://yolo.swag") == "yolo.swag"
    assert DomainQuestion.normalize("yolo.swag/") == "yolo.swag"


def test_normalize_path():

    assert PathQuestion.normalize("") == "/"
    assert PathQuestion.normalize("") == "/"
    assert PathQuestion.normalize("macnuggets") == "/macnuggets"
    assert PathQuestion.normalize("/macnuggets") == "/macnuggets"
    assert PathQuestion.normalize("   /macnuggets      ") == "/macnuggets"
    assert PathQuestion.normalize("/macnuggets") == "/macnuggets"
    assert PathQuestion.normalize("mac/nuggets") == "/mac/nuggets"
    assert PathQuestion.normalize("/macnuggets/") == "/macnuggets"
    assert PathQuestion.normalize("macnuggets/") == "/macnuggets"
    assert PathQuestion.normalize("////macnuggets///") == "/macnuggets"


def test_simple_evaluate():
    context = {
        "a1": 1,
        "b2": 2,
        "c10": 10,
        "foo": "bar",
        "comp": "1>2",
        "empty": "",
        "lorem": "Lorem ipsum dolor et si qua met!",
        "warning": "Warning! This sentence will fail!",
        "quote": "Je s'apelle Groot",
        "and_": "&&",
        "object": {"a": "Security risk"},
    }
    supported = {
        "42": 42,
        "9.5": 9.5,
        "'bopbidibopbopbop'": "bopbidibopbopbop",
        "true": True,
        "false": False,
        "null": None,
        # Math
        "1 * (2 + 3 * (4 - 3))": 5,
        "1 * (2 + 3 * (4 - 3)) > 10 - 2 || 3 * 2 > 9 - 2 * 3": True,
        "(9 - 2) * 3 - 10": 11,
        "12 - 2 * -2 + (3 - 4) * 3.1": 12.9,
        "9 / 12 + 12 * 3 - 5": 31.75,
        "9 / 12 + 12 * (3 - 5)": -23.25,
        "12 > 13.1": False,
        "12 < 14": True,
        "12 <= 14": True,
        "12 >= 14": False,
        "12 == 14": False,
        "12 % 5 > 3": False,
        "12 != 14": True,
        "9 - 1 > 10 && 3 * 5 > 10": False,
        "9 - 1 > 10 || 3 * 5 > 10": True,
        "a1 > 0 || a1 < -12": True,
        "a1 > 0 && a1 < -12": False,
        "a1 + 1 > 0 && -a1 > -12": True,
        "-(a1 + 1) < 0 || -(a1 + 2) > -12": True,
        "-a1 * 2": -2,
        "(9 - 2) * 3 - c10": 11,
        "(9 - b2) * 3 - c10": 11,
        "c10 > b2": True,
        # String
        "foo == 'bar'": True,
        "foo != 'bar'": False,
        'foo == "bar" && 1 > 0': True,
        "!!foo": True,
        "!foo": False,
        "foo": "bar",
        '!(foo > "baa") || 1 > 2': False,
        '!(foo > "baa") || 1 < 2': True,
        'empty == ""': True,
        '1 == "1"': True,
        '1.0 == "1"': True,
        '1 == "aaa"': False,
        "'I am ' + b2 + ' years'": "I am 2 years",
        "quote == 'Je s\\'apelle Groot'": True,
        "lorem == 'Lorem ipsum dolor et si qua met!'": True,
        "and_ == '&&'": True,
        "warning == 'Warning! This sentence will fail!'": True,
        # Match
        "match(lorem, '^Lorem [ia]psumE?')": bool,
        "match(foo, '^Lorem [ia]psumE?')": None,
        "match(lorem, '^Lorem [ia]psumE?') && 1 == 1": bool,
        # No code
        "": False,
        " ": False,
    }
    trigger_errors = {
        "object.a": YunohostError,  # Keep unsupported, for security reasons
        "a1 ** b2": YunohostError,  # Keep unsupported, for security reasons
        "().__class__.__bases__[0].__subclasses__()": YunohostError,  # Very dangerous code
        "a1 > 11 ? 1 : 0": SyntaxError,
        "c10 > b2 == false": YunohostError,  # JS and Python doesn't do the same thing for this situation
        "c10 > b2 == true": YunohostError,
    }

    for expression, result in supported.items():
        if result == bool:
            assert bool(evaluate_simple_js_expression(expression, context)), expression
        else:
            assert (
                evaluate_simple_js_expression(expression, context) == result
            ), expression

    for expression, error in trigger_errors.items():
        with pytest.raises(error):
            evaluate_simple_js_expression(expression, context)
