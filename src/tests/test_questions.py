import inspect
import sys
import pytest
import os

from contextlib import contextmanager
from mock import patch
from io import StringIO
from typing import Any, Literal, Sequence, TypedDict, Union

from _pytest.mark.structures import ParameterSet


from moulinette import Moulinette
from yunohost import domain, user
from yunohost.utils.config import (
    ARGUMENTS_TYPE_PARSERS,
    ask_questions_and_parse_answers,
    DisplayTextQuestion,
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


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╮╭─┐╶┬╴╭─╴╷ ╷╶┬╴╭╮╷╭─╮                             │
# │  ├─╯├─┤ │ │  ├─┤ │ ││││╶╮                             │
# │  ╵  ╵ ╵ ╵ ╰─╴╵ ╵╶┴╴╵╰╯╰─╯                             │
# ╰───────────────────────────────────────────────────────╯


@contextmanager
def patch_isatty(isatty):
    with patch.object(os, "isatty", return_value=isatty):
        yield


@contextmanager
def patch_interface(interface: Literal["api", "cli"] = "api"):
    with patch.object(Moulinette.interface, "type", interface), patch_isatty(
        interface == "cli"
    ):
        yield


@contextmanager
def patch_prompt(return_value):
    with patch_interface("cli"), patch.object(
        Moulinette, "prompt", return_value=return_value
    ) as prompt:
        yield prompt


@pytest.fixture
def patch_no_tty():
    with patch_isatty(False):
        yield


@pytest.fixture
def patch_with_tty():
    with patch_isatty(True):
        yield


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╴╭─╴┌─╴╭╮╷╭─┐┌─╮╶┬╴╭─╮╭─╴                          │
# │  ╰─╮│  ├─╴│││├─┤├┬╯ │ │ │╰─╮                          │
# │  ╶─╯╰─╴╰─╴╵╰╯╵ ╵╵ ╰╶┴╴╰─╯╶─╯                          │
# ╰───────────────────────────────────────────────────────╯


MinScenario = tuple[Any, Union[Literal["FAIL"], Any]]
PartialScenario = tuple[Any, Union[Literal["FAIL"], Any], dict[str, Any]]
FullScenario = tuple[Any, Union[Literal["FAIL"], Any], dict[str, Any], dict[str, Any]]

Scenario = Union[
    MinScenario,
    PartialScenario,
    FullScenario,
    "InnerScenario",
]


class InnerScenario(TypedDict, total=False):
    scenarios: Sequence[Scenario]
    raw_options: Sequence[dict[str, Any]]
    data: Sequence[dict[str, Any]]


# ╭───────────────────────────────────────────────────────╮
# │ Scenario generators/helpers                           │
# ╰───────────────────────────────────────────────────────╯


def get_hydrated_scenarios(raw_options, scenarios, data=[{}]):
    """
    Normalize and hydrate a mixed list of scenarios to proper tuple/pytest.param flattened list values.

    Example::
        scenarios = [
            {
                "raw_options": [{}, {"optional": True}],
                "scenarios": [
                    ("", "value", {"default": "value"}),
                    *unchanged("value", "other"),
                ]
            },
            *all_fails(-1, 0, 1, raw_options={"optional": True}),
            *xfail(scenarios=[(True, "True"), (False, "False)], reason="..."),
        ]
        # Is exactly the same as
        scenarios = [
            ("", "value", {"default": "value"}),
            ("", "value", {"optional": True, "default": "value"}),
            ("value", "value", {}),
            ("value", "value", {"optional": True}),
            ("other", "other", {}),
            ("other", "other", {"optional": True}),
            (-1, FAIL, {"optional": True}),
            (0, FAIL, {"optional": True}),
            (1, FAIL, {"optional": True}),
            pytest.param(True, "True", {}, marks=pytest.mark.xfail(reason="...")),
            pytest.param(False, "False", {}, marks=pytest.mark.xfail(reason="...")),
        ]
    """
    hydrated_scenarios = []
    for raw_option in raw_options:
        for mocked_data in data:
            for scenario in scenarios:
                if isinstance(scenario, dict):
                    merged_raw_options = [
                        {**raw_option, **raw_opt}
                        for raw_opt in scenario.get("raw_options", [{}])
                    ]
                    hydrated_scenarios += get_hydrated_scenarios(
                        merged_raw_options,
                        scenario["scenarios"],
                        scenario.get("data", [mocked_data]),
                    )
                elif isinstance(scenario, ParameterSet):
                    intake, output, custom_raw_option = (
                        scenario.values
                        if len(scenario.values) == 3
                        else (*scenario.values, {})
                    )
                    merged_raw_option = {**raw_option, **custom_raw_option}
                    hydrated_scenarios.append(
                        pytest.param(
                            intake,
                            output,
                            merged_raw_option,
                            mocked_data,
                            marks=scenario.marks,
                        )
                    )
                elif isinstance(scenario, tuple):
                    intake, output, custom_raw_option = (
                        scenario if len(scenario) == 3 else (*scenario, {})
                    )
                    merged_raw_option = {**raw_option, **custom_raw_option}
                    hydrated_scenarios.append(
                        (intake, output, merged_raw_option, mocked_data)
                    )
                else:
                    raise Exception(
                        "Test scenario should be tuple(intake, output, raw_option), pytest.param(intake, output, raw_option) or dict(raw_options, scenarios, data)"
                    )

    return hydrated_scenarios


def generate_test_name(intake, output, raw_option, data):
    values_as_str = []
    for value in (intake, output):
        if isinstance(value, str) and value != FAIL:
            values_as_str.append(f"'{value}'")
        elif inspect.isclass(value) and issubclass(value, Exception):
            values_as_str.append(value.__name__)
        else:
            values_as_str.append(value)
    name = f"{values_as_str[0]} -> {values_as_str[1]}"

    keys = [
        "=".join(
            [
                key,
                str(raw_option[key])
                if not isinstance(raw_option[key], str)
                else f"'{raw_option[key]}'",
            ]
        )
        for key in raw_option.keys()
        if key not in ("id", "type")
    ]
    if keys:
        name += " (" + ",".join(keys) + ")"
    return name


def pytest_generate_tests(metafunc):
    """
    Pytest test factory that, for each `BaseTest` subclasses, parametrize its
    methods if it requires it by checking the method's parameters.
    For those and based on their `cls.scenarios`, a series of `pytest.param` are
    automaticly injected as test values.
    """
    if metafunc.cls and issubclass(metafunc.cls, BaseTest):
        argnames = []
        argvalues = []
        ids = []
        fn_params = inspect.signature(metafunc.function).parameters

        for params in [
            ["intake", "expected_output", "raw_option", "data"],
            ["intake", "expected_normalized", "raw_option", "data"],
            ["intake", "expected_humanized", "raw_option", "data"],
        ]:
            if all(param in fn_params for param in params):
                argnames += params
                if params[1] == "expected_output":
                    # Hydrate scenarios with generic raw_option data
                    argvalues += get_hydrated_scenarios(
                        [metafunc.cls.raw_option], metafunc.cls.scenarios
                    )
                    ids += [
                        generate_test_name(*args.values)
                        if isinstance(args, ParameterSet)
                        else generate_test_name(*args)
                        for args in argvalues
                    ]
                elif params[1] == "expected_normalized":
                    argvalues += metafunc.cls.normalized
                    ids += [
                        f"{metafunc.cls.raw_option['type']}-normalize-{scenario[0]}"
                        for scenario in metafunc.cls.normalized
                    ]
                elif params[1] == "expected_humanized":
                    argvalues += metafunc.cls.humanized
                    ids += [
                        f"{metafunc.cls.raw_option['type']}-normalize-{scenario[0]}"
                        for scenario in metafunc.cls.humanized
                    ]

                metafunc.parametrize(argnames, argvalues, ids=ids)


# ╭───────────────────────────────────────────────────────╮
# │ Scenario helpers                                      │
# ╰───────────────────────────────────────────────────────╯

FAIL = YunohostValidationError


def nones(
    *nones, output, raw_option: dict[str, Any] = {}, fail_if_required: bool = True
) -> list[PartialScenario]:
    """
    Returns common scenarios for ~None values.
    - required and required + as default -> `FAIL`
    - optional and optional + as default -> `expected_output=None`
    """
    return [
        (none, FAIL if fail_if_required else output, base_raw_option | raw_option)  # type: ignore
        for none in nones
        for base_raw_option in ({}, {"default": none})
    ] + [
        (none, output, base_raw_option | raw_option)
        for none in nones
        for base_raw_option in ({"optional": True}, {"optional": True, "default": none})
    ]


def unchanged(*args, raw_option: dict[str, Any] = {}) -> list[PartialScenario]:
    """
    Returns a series of params for which output is expected to be the same as its intake

    Example::
        # expect `"value"` to output as `"value"`, etc.
        unchanged("value", "yes", "none")

    """
    return [(arg, arg, raw_option.copy()) for arg in args]


def all_as(*args, output, raw_option: dict[str, Any] = {}) -> list[PartialScenario]:
    """
    Returns a series of params for which output is expected to be the same single value

    Example::
        # expect all values to output as `True`
        all_as("y", "yes", 1, True, output=True)
    """
    return [(arg, output, raw_option.copy()) for arg in args]


def all_fails(
    *args, raw_option: dict[str, Any] = {}, error=FAIL
) -> list[PartialScenario]:
    """
    Returns a series of params for which output is expected to be failing with validation error
    """
    return [(arg, error, raw_option.copy()) for arg in args]


def xpass(*, scenarios: list[Scenario], reason="unknown") -> list[Scenario]:
    """
    Return a pytest param for which test should have fail but currently passes.
    """
    return [
        pytest.param(
            *scenario,
            marks=pytest.mark.xfail(
                reason=f"Currently valid but probably shouldn't. details: {reason}."
            ),
        )
        for scenario in scenarios
    ]


def xfail(*, scenarios: list[Scenario], reason="unknown") -> list[Scenario]:
    """
    Return a pytest param for which test should have passed but currently fails.
    """
    return [
        pytest.param(
            *scenario,
            marks=pytest.mark.xfail(
                reason=f"Currently invalid but should probably pass. details: {reason}."
            ),
        )
        for scenario in scenarios
    ]


# ╭───────────────────────────────────────────────────────╮
# │  ╶┬╴┌─╴╭─╴╶┬╴╭─╴                                      │
# │   │ ├─╴╰─╮ │ ╰─╮                                      │
# │   ╵ ╰─╴╶─╯ ╵ ╶─╯                                      │
# ╰───────────────────────────────────────────────────────╯


def _fill_or_prompt_one_option(raw_option, intake):
    raw_option = raw_option.copy()
    id_ = raw_option.pop("id")
    options = {id_: raw_option}
    answers = {id_: intake} if intake is not None else {}

    option = ask_questions_and_parse_answers(options, answers)[0]

    return (option, option.value)


def _test_value_is_expected_output(value, expected_output):
    """
    Properly compares bools and None
    """
    if isinstance(expected_output, bool) or expected_output is None:
        assert value is expected_output
    else:
        assert value == expected_output


def _test_intake(raw_option, intake, expected_output):
    option, value = _fill_or_prompt_one_option(raw_option, intake)

    _test_value_is_expected_output(value, expected_output)


def _test_intake_may_fail(raw_option, intake, expected_output):
    if inspect.isclass(expected_output) and issubclass(expected_output, Exception):
        with pytest.raises(expected_output):
            _fill_or_prompt_one_option(raw_option, intake)
    else:
        _test_intake(raw_option, intake, expected_output)


class BaseTest:
    raw_option: dict[str, Any] = {}
    prefill: dict[Literal["raw_option", "prefill", "intake"], Any]
    scenarios: list[Scenario]

    # fmt: off
    # scenarios = [
    #     *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
    #     *all_fails("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
    #     *nones(None, "", output=""),
    # ]
    # fmt: on
    # TODO
    # - pattern (also on Date for example to see if it override the default pattern)
    # - example
    # - visible
    # - redact
    # - regex
    # - hooks

    @classmethod
    def get_raw_option(cls, raw_option={}, **kwargs):
        base_raw_option = cls.raw_option.copy()
        base_raw_option.update(**raw_option)
        base_raw_option.update(**kwargs)
        return base_raw_option

    @classmethod
    def _test_basic_attrs(self):
        raw_option = self.get_raw_option(optional=True)
        id_ = raw_option["id"]
        option, value = _fill_or_prompt_one_option(raw_option, None)

        is_special_readonly_option = isinstance(option, DisplayTextQuestion)

        assert isinstance(option, ARGUMENTS_TYPE_PARSERS[raw_option["type"]])
        assert option.type == raw_option["type"]
        assert option.name == id_
        assert option.ask == {"en": id_}
        assert option.readonly is (True if is_special_readonly_option else False)
        assert option.visible is None
        # assert option.bind is None

        if is_special_readonly_option:
            assert value is None

        return (raw_option, option, value)

    @pytest.mark.usefixtures("patch_no_tty")
    def test_basic_attrs(self):
        """
        Test basic options factories and BaseOption default attributes values.
        """
        # Intermediate method since pytest doesn't like tests that returns something.
        # This allow a test class to call `_test_basic_attrs` then do additional checks
        self._test_basic_attrs()

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        """
        Test that assert that moulinette prompt is called with:
        - `message` with translated string and possible choices list
        -  help` with translated string
        - `prefill` is the expected string value from a custom default
        - `is_password` is true for `password`s only
        - `is_multiline` is true for `text`s only
        - `autocomplete` is option choices

        Ran only once with `cls.prefill` data
        """
        if prefill_data is None:
            prefill_data = self.prefill

        base_raw_option = prefill_data["raw_option"]
        prefill = prefill_data["prefill"]

        with patch_prompt("") as prompt:
            raw_option = self.get_raw_option(
                raw_option=base_raw_option,
                ask={"en": "Can i haz question?"},
                help={"en": "Here's help!"},
            )
            option, value = _fill_or_prompt_one_option(raw_option, None)

            expected_message = option.ask["en"]

            if option.choices:
                choices = (
                    option.choices
                    if isinstance(option.choices, list)
                    else option.choices.keys()
                )
                expected_message += f" [{' | '.join(choices)}]"
            if option.type == "boolean":
                expected_message += " [yes | no]"

            prompt.assert_called_with(
                message=expected_message,
                is_password=option.type == "password",
                confirm=False,  # FIXME no confirm?
                prefill=prefill,
                is_multiline=option.type == "text",
                autocomplete=option.choices or [],
                help=option.help["en"],
            )

    def test_scenarios(self, intake, expected_output, raw_option, data):
        with patch_interface("api"):
            _test_intake_may_fail(
                raw_option,
                intake,
                expected_output,
            )


# ╭───────────────────────────────────────────────────────╮
# │ STRING                                                │
# ╰───────────────────────────────────────────────────────╯


class TestString(BaseTest):
    raw_option = {"type": "string", "id": "string_id"}
    prefill = {
        "raw_option": {"default": " custom default"},
        "prefill": " custom default",
    }
    # fmt: off
    scenarios = [
        *nones(None, "", output=""),
        # basic typed values
        *unchanged(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),  # FIXME should output as str?
        *unchanged("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", raw_option={"optional": True}),
        *xpass(scenarios=[
            ([], []),
        ], reason="Should fail"),
        # test strip
        ("value", "value"),
        ("value\n", "value"),
        ("  \n value\n", "value"),
        ("  \\n value\\n", "\\n value\\n"),
        ("  \tvalue\t", "value"),
        (r" ##value \n \tvalue\n  ", r"##value \n \tvalue\n"),
        *xpass(scenarios=[
            ("value\nvalue", "value\nvalue"),
            (" ##value \n \tvalue\n  ", "##value \n \tvalue"),
        ], reason=r"should fail or without `\n`?"),
        # readonly
        *xfail(scenarios=[
            ("overwrite", "expected value", {"readonly": True, "default": "expected value"}),
        ], reason="Should not be overwritten"),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ TEXT                                                  │
# ╰───────────────────────────────────────────────────────╯


class TestText(BaseTest):
    raw_option = {"type": "text", "id": "text_id"}
    prefill = {
        "raw_option": {"default": "some value\nanother line "},
        "prefill": "some value\nanother line ",
    }
    # fmt: off
    scenarios = [
        *nones(None, "", output=""),
        # basic typed values
        *unchanged(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),  # FIXME should fail or output as str?
        *unchanged("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", raw_option={"optional": True}),
        *xpass(scenarios=[
            ([], [])
        ], reason="Should fail"),
        ("value", "value"),
        ("value\n value", "value\n value"),
        # test no strip
        *xpass(scenarios=[
            ("value\n", "value"),
            ("  \n value\n", "value"),
            ("  \\n value\\n", "\\n value\\n"),
            ("  \tvalue\t", "value"),
            (" ##value \n \tvalue\n  ", "##value \n \tvalue"),
            (r" ##value \n \tvalue\n  ", r"##value \n \tvalue\n"),
        ], reason="Should not be stripped"),
        # readonly
        *xfail(scenarios=[
            ("overwrite", "expected value", {"readonly": True, "default": "expected value"}),
        ], reason="Should not be overwritten"),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ PASSWORD                                              │
# ╰───────────────────────────────────────────────────────╯


class TestPassword(BaseTest):
    raw_option = {"type": "password", "id": "password_id"}
    prefill = {
        "raw_option": {"default": None, "optional": True},
        "prefill": "",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, -1, 1337, 13.37, raw_option={"optional": True}, error=TypeError),  # FIXME those fails with TypeError
        *all_fails([], ["one"], {}, raw_option={"optional": True}, error=AttributeError),  # FIXME those fails with AttributeError
        *all_fails("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
        *nones(None, "", output=""),
        *xpass(scenarios=[
            (" value \n moarc0mpl1cat3d\n  ", "value \n moarc0mpl1cat3d"),
            (" some_ value", "some_ value"),
        ], reason="Should output exactly the same"),
        ("s3cr3t!!", "s3cr3t!!"),
        ("secret", FAIL),
        *[("supersecret" + char, FAIL) for char in PasswordQuestion.forbidden_chars],  # FIXME maybe add ` \n` to the list?
        # readonly
        *xpass(scenarios=[
            ("s3cr3t!!", "s3cr3t!!", {"readonly": True}),
        ], reason="Should fail since readonly is forbidden"),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ BOOLEAN                                               │
# ╰───────────────────────────────────────────────────────╯


class TestBoolean(BaseTest):
    raw_option = {"type": "boolean", "id": "boolean_id"}
    prefill = {
        "raw_option": {"default": True},
        "prefill": "yes",
    }
    # fmt: off
    truthy_values = (True, 1, "1", "True", "true", "Yes", "yes", "y", "on")
    falsy_values = (False, 0, "0", "False", "false", "No", "no", "n", "off")
    scenarios = [
        *all_as(None, "", output=0),
        *all_fails("none", "None"),  # FIXME should output as `0` (default) like other none values when required?
        *all_as(None, "", output=0, raw_option={"optional": True}),  # FIXME should output as `None`?
        *all_as("none", "None", output=None, raw_option={"optional": True}),
        # FIXME even if default is explicity `None|""`, it ends up with class_default `0`
        *all_as(None, "", output=0, raw_option={"default": None}),  # FIXME this should fail, default is `None`
        *all_as(None, "", output=0, raw_option={"optional": True, "default": None}),  # FIXME even if default is explicity None, it ends up with class_default
        *all_as(None, "", output=0, raw_option={"default": ""}),  # FIXME this should fail, default is `""`
        *all_as(None, "", output=0, raw_option={"optional": True, "default": ""}),  # FIXME even if default is explicity None, it ends up with class_default
        # With "none" behavior is ok
        *all_fails(None, "", raw_option={"default": "none"}),
        *all_as(None, "", output=None, raw_option={"optional": True, "default": "none"}),
        # Unhandled types should fail
        *all_fails(1337, "1337", "string", [], "[]", ",", "one,two"),
        *all_fails(1337, "1337", "string", [], "[]", ",", "one,two", {"optional": True}),
        # Required
        *all_as(*truthy_values, output=1),
        *all_as(*falsy_values, output=0),
        # Optional
        *all_as(*truthy_values, output=1, raw_option={"optional": True}),
        *all_as(*falsy_values, output=0, raw_option={"optional": True}),
        # test values as default, as required option without intake
        *[(None, 1, {"default": true for true in truthy_values})],
        *[(None, 0, {"default": false for false in falsy_values})],
        # custom boolean output
        ("", "disallow", {"yes": "allow", "no": "disallow"}),  # required -> default to False -> `"disallow"`
        ("n", "disallow", {"yes": "allow", "no": "disallow"}),
        ("y", "allow", {"yes": "allow", "no": "disallow"}),
        ("", False, {"yes": True, "no": False}),  # required -> default to False -> `False`
        ("n", False, {"yes": True, "no": False}),
        ("y", True, {"yes": True, "no": False}),
        ("", -1, {"yes": 1, "no": -1}),  # required -> default to False -> `-1`
        ("n", -1, {"yes": 1, "no": -1}),
        ("y", 1, {"yes": 1, "no": -1}),
        {
            "raw_options": [
                {"yes": "no", "no": "yes", "optional": True},
                {"yes": False, "no": True, "optional": True},
                {"yes": "0", "no": "1", "optional": True},
            ],
            # "no" for "yes" and "yes" for "no" should fail
            "scenarios": all_fails("", "y", "n", error=AssertionError),
        },
        # readonly
        *xfail(scenarios=[
            (1, 0, {"readonly": True, "default": 0}),
        ], reason="Should not be overwritten"),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ PATH                                                  │
# ╰───────────────────────────────────────────────────────╯


class TestWebPath(BaseTest):
    raw_option = {"type": "path", "id": "path_id"}
    prefill = {
        "raw_option": {"default": "some_path"},
        "prefill": "some_path",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),

        *nones(None, "", output=""),
        # custom valid
        ("/", "/"),
        ("/one/two", "/one/two"),
        *[
            (v, "/" + v)
            for v in ("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value")
        ],
        ("value\n", "/value"),
        ("//value", "/value"),
        ("///value///", "/value"),
        *xpass(scenarios=[
            ("value\nvalue", "/value\nvalue"),
            ("value value", "/value value"),
            ("value//value", "/value//value"),
        ], reason="Should fail"),
        *xpass(scenarios=[
            ("./here", "/./here"),
            ("../here", "/../here"),
            ("/somewhere/../here", "/somewhere/../here"),
        ], reason="Should fail or flattened"),

        *xpass(scenarios=[
            ("/one?withquery=ah", "/one?withquery=ah"),
        ], reason="Should fail or query string removed"),
        *xpass(scenarios=[
            ("https://example.com/folder", "/https://example.com/folder")
        ], reason="Should fail or scheme+domain removed"),
        # readonly
        *xfail(scenarios=[
            ("/overwrite", "/value", {"readonly": True, "default": "/value"}),
        ], reason="Should not be overwritten"),
        # FIXME should path have forbidden_chars?
    ]
    # fmt: on


def test_question_empty():
    ask_questions_and_parse_answers({}, {}) == []


def test_question_string_default_type():
    questions = {"some_string": {}}
    answers = {"some_string": "some_value"}

    out = ask_questions_and_parse_answers(questions, answers)[0]

    assert out.name == "some_string"
    assert out.type == "string"
    assert out.value == "some_value"


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
