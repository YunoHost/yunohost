#
# Copyright (c) 2023 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import ast
import datetime
import operator as op
import os
import re
import shutil
import tempfile
import urllib.parse
from enum import Enum
from typing import (
    Annotated,
    Any,
    Callable,
    List,
    Literal,
    Mapping,
    Type,
    Union,
    cast,
)

from pydantic import (
    BaseModel,
    Extra,
    ValidationError,
    create_model,
    root_validator,
    validator,
)
from pydantic.color import Color
from pydantic.fields import Field
from pydantic.networks import EmailStr, HttpUrl

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import read_file, write_to_file
from moulinette.utils.log import getActionLogger
from yunohost.log import OperationLogger
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.i18n import _value_for_locale

logger = getActionLogger("yunohost.form")


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╴╷ ╷╭─┐╷                                           │
# │  ├─╴│╭╯├─┤│                                           │
# │  ╰─╴╰╯ ╵ ╵╰─╴                                         │
# ╰───────────────────────────────────────────────────────╯


# Those js-like evaluate functions are used to eval safely visible attributes
# The goal is to evaluate in the same way than js simple-evaluate
# https://github.com/shepherdwind/simple-evaluate
def evaluate_simple_ast(node, context=None):
    if context is None:
        context = {}

    operators = {
        ast.Not: op.not_,
        ast.Mult: op.mul,
        ast.Div: op.truediv,  # number
        ast.Mod: op.mod,  # number
        ast.Add: op.add,  # str
        ast.Sub: op.sub,  # number
        ast.USub: op.neg,  # Negative number
        ast.Gt: op.gt,
        ast.Lt: op.lt,
        ast.GtE: op.ge,
        ast.LtE: op.le,
        ast.Eq: op.eq,
        ast.NotEq: op.ne,
    }
    context["true"] = True
    context["false"] = False
    context["null"] = None

    # Variable
    if isinstance(node, ast.Name):  # Variable
        return context[node.id]

    # Python <=3.7 String
    elif isinstance(node, ast.Str):
        return node.s

    # Python <=3.7 Number
    elif isinstance(node, ast.Num):
        return node.n

    # Boolean, None and Python 3.8 for Number, Boolean, String and None
    elif isinstance(node, (ast.Constant, ast.NameConstant)):
        return node.value

    # + - * / %
    elif (
        isinstance(node, ast.BinOp) and type(node.op) in operators
    ):  # <left> <operator> <right>
        left = evaluate_simple_ast(node.left, context)
        right = evaluate_simple_ast(node.right, context)
        if type(node.op) == ast.Add:
            if isinstance(left, str) or isinstance(right, str):  # support 'I am ' + 42
                left = str(left)
                right = str(right)
        elif type(left) != type(right):  # support "111" - "1" -> 110
            left = float(left)
            right = float(right)

        return operators[type(node.op)](left, right)

    # Comparison
    # JS and Python don't give the same result for multi operators
    # like True == 10 > 2.
    elif (
        isinstance(node, ast.Compare) and len(node.comparators) == 1
    ):  # <left> <ops> <comparators>
        left = evaluate_simple_ast(node.left, context)
        right = evaluate_simple_ast(node.comparators[0], context)
        operator = node.ops[0]
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            try:
                left = float(left)
                right = float(right)
            except ValueError:
                return type(operator) == ast.NotEq
        try:
            return operators[type(operator)](left, right)
        except TypeError:  # support "e" > 1 -> False like in JS
            return False

    # and / or
    elif isinstance(node, ast.BoolOp):  # <op> <values>
        for value in node.values:
            value = evaluate_simple_ast(value, context)
            if isinstance(node.op, ast.And) and not value:
                return False
            elif isinstance(node.op, ast.Or) and value:
                return True
        return isinstance(node.op, ast.And)

    # not / USub (it's negation number -\d)
    elif isinstance(node, ast.UnaryOp):  # <operator> <operand> e.g., -1
        return operators[type(node.op)](evaluate_simple_ast(node.operand, context))

    # match function call
    elif isinstance(node, ast.Call) and node.func.__dict__.get("id") == "match":
        return re.match(
            evaluate_simple_ast(node.args[1], context), context[node.args[0].id]
        )

    # Unauthorized opcode
    else:
        opcode = str(type(node))
        raise YunohostError(
            f"Unauthorize opcode '{opcode}' in visible attribute", raw_msg=True
        )


def js_to_python(expr):
    in_string = None
    py_expr = ""
    i = 0
    escaped = False
    for char in expr:
        if char in r"\"'":
            # Start a string
            if not in_string:
                in_string = char

            # Finish a string
            elif in_string == char and not escaped:
                in_string = None

        # If we are not in a string, replace operators
        elif not in_string:
            if char == "!" and expr[i + 1] != "=":
                char = "not "
            elif char in "|&" and py_expr[-1:] == char:
                py_expr = py_expr[:-1]
                char = " and " if char == "&" else " or "

        # Determine if next loop will be in escaped mode
        escaped = char == "\\" and not escaped
        py_expr += char
        i += 1
    return py_expr


def evaluate_simple_js_expression(expr, context={}):
    if not expr.strip():
        return False
    node = ast.parse(js_to_python(expr), mode="eval").body
    return evaluate_simple_ast(node, context)


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╮┌─╮╶┬╴╶┬╴╭─╮╭╮╷╭─╴                                │
# │  │ │├─╯ │  │ │ ││││╰─╮                                │
# │  ╰─╯╵   ╵ ╶┴╴╰─╯╵╰╯╶─╯                                │
# ╰───────────────────────────────────────────────────────╯


class OptionType(str, Enum):
    # display
    display_text = "display_text"
    markdown = "markdown"
    alert = "alert"
    # action
    button = "button"
    # text
    string = "string"
    text = "text"
    password = "password"
    color = "color"
    # numeric
    number = "number"
    range = "range"
    # boolean
    boolean = "boolean"
    # time
    date = "date"
    time = "time"
    # location
    email = "email"
    path = "path"
    url = "url"
    # file
    file = "file"
    # choice
    select = "select"
    tags = "tags"
    # entity
    domain = "domain"
    app = "app"
    user = "user"
    group = "group"


FORBIDDEN_READONLY_TYPES = {
    OptionType.password,
    OptionType.app,
    OptionType.domain,
    OptionType.user,
    OptionType.group,
}


Context = dict[str, Any]
Translation = Union[dict[str, str], str]
JSExpression = str
Values = dict[str, Any]


class Pattern(BaseModel):
    regexp: str
    error: Translation = "error_pattern"  # FIXME add generic i18n key


class BaseOption(BaseModel):
    type: OptionType
    id: str
    ask: Union[Translation, None]
    readonly: bool = False
    visible: Union[JSExpression, bool] = True
    bind: Union[str, None] = None

    class Config:
        arbitrary_types_allowed = True
        use_enum_values = True
        validate_assignment = True

        @staticmethod
        def schema_extra(schema: dict[str, Any], model: Type["BaseOption"]) -> None:
            # FIXME Do proper doctstring for Options
            del schema["description"]
            schema["additionalProperties"] = False

    @validator("ask", always=True)
    def parse_or_set_default_ask(
        cls, value: Union[Translation, None], values: Values
    ) -> Translation:
        if value is None:
            return {"en": values["id"]}
        if isinstance(value, str):
            return {"en": value}
        return value

    @validator("readonly", pre=True)
    def can_be_readonly(cls, value: bool, values: Values) -> bool:
        forbidden_types = ("password", "app", "domain", "user", "file")
        if value is True and values["type"] in forbidden_types:
            raise ValueError(
                m18n.n(
                    "config_forbidden_readonly_type",
                    type=values["type"],
                    id=values["id"],
                )
            )
        return value

    def is_visible(self, context: Context) -> bool:
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    def _get_prompt_message(self, value: None) -> str:
        return _value_for_locale(self.ask)


# ╭───────────────────────────────────────────────────────╮
# │ DISPLAY OPTIONS                                       │
# ╰───────────────────────────────────────────────────────╯


class BaseReadonlyOption(BaseOption):
    readonly: Literal[True] = True


class DisplayTextOption(BaseReadonlyOption):
    type: Literal[OptionType.display_text] = OptionType.display_text


class MarkdownOption(BaseReadonlyOption):
    type: Literal[OptionType.markdown] = OptionType.markdown


class State(str, Enum):
    success = "success"
    info = "info"
    warning = "warning"
    danger = "danger"


class AlertOption(BaseReadonlyOption):
    type: Literal[OptionType.alert] = OptionType.alert
    style: State = State.info
    icon: Union[str, None] = None

    def _get_prompt_message(self, value: None) -> str:
        colors = {
            State.success: "green",
            State.info: "cyan",
            State.warning: "yellow",
            State.danger: "red",
        }
        message = m18n.g(self.style) if self.style != State.danger else m18n.n("danger")
        return f"{colorize(message, colors[self.style])} {_value_for_locale(self.ask)}"


class ButtonOption(BaseReadonlyOption):
    type: Literal[OptionType.button] = OptionType.button
    help: Union[Translation, None] = None
    style: State = State.success
    icon: Union[str, None] = None
    enabled: Union[JSExpression, bool] = True

    def is_enabled(self, context: Context) -> bool:
        if isinstance(self.enabled, bool):
            return self.enabled

        return evaluate_simple_js_expression(self.enabled, context=context)


# ╭───────────────────────────────────────────────────────╮
# │ INPUT OPTIONS                                         │
# ╰───────────────────────────────────────────────────────╯


class BaseInputOption(BaseOption):
    help: Union[Translation, None] = None
    example: Union[str, None] = None
    placeholder: Union[str, None] = None
    redact: bool = False
    optional: bool = False  # FIXME keep required as default?
    default: Any = None

    @validator("default", pre=True)
    def check_empty_default(value: Any) -> Any:
        if value == "":
            return None
        return value

    @staticmethod
    def humanize(value, option={}):
        return str(value)

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, str):
            value = value.strip()
        return value

    def _get_prompt_message(self, value: Any) -> str:
        message = super()._get_prompt_message(value)

        if self.readonly:
            message = colorize(message, "purple")
            return f"{message} {self.humanize(value, self)}"

        return message

    def _value_pre_validator(self):
        if self.value in [None, ""] and not self.optional:
            raise YunohostValidationError("app_argument_required", name=self.id)

        # we have an answer, do some post checks
        if self.value not in [None, ""]:
            if self.pattern and not re.match(self.pattern["regexp"], str(self.value)):
                raise YunohostValidationError(
                    self.pattern["error"],
                    name=self.id,
                    value=self.value,
                )

    def _value_post_validator(self):
        if not self.redact:
            return self.value

        # Tell the operation_logger to redact all password-type / secret args
        # Also redact the % escaped version of the password that might appear in
        # the 'args' section of metadata (relevant for password with non-alphanumeric char)
        data_to_redact = []
        if self.value and isinstance(self.value, str):
            data_to_redact.append(self.value)
        if self.current_value and isinstance(self.current_value, str):
            data_to_redact.append(self.current_value)
        data_to_redact += [
            urllib.parse.quote(data)
            for data in data_to_redact
            if urllib.parse.quote(data) != data
        ]

        for operation_logger in OperationLogger._instances:
            operation_logger.data_to_redact.extend(data_to_redact)

        return self.value


# ─ STRINGS ───────────────────────────────────────────────


class BaseStringOption(BaseInputOption):
    default: Union[str, None]
    pattern: Union[Pattern, None] = None


class StringOption(BaseStringOption):
    type: Literal[OptionType.string] = OptionType.string


class TextOption(BaseStringOption):
    type: Literal[OptionType.text] = OptionType.text


FORBIDDEN_PASSWORD_CHARS = r"{}"


class PasswordOption(BaseInputOption):
    type: Literal[OptionType.password] = OptionType.password
    example: Literal[None] = None
    default: Literal[None] = None
    redact: Literal[True] = True
    _forbidden_chars: str = FORBIDDEN_PASSWORD_CHARS

    def _value_pre_validator(self):
        super()._value_pre_validator()

        if self.value not in [None, ""]:
            if any(char in self.value for char in self._forbidden_chars):
                raise YunohostValidationError(
                    "pattern_password_app", forbidden_chars=self._forbidden_chars
                )

            # If it's an optional argument the value should be empty or strong enough
            from yunohost.utils.password import assert_password_is_strong_enough

            assert_password_is_strong_enough("user", self.value)


class ColorOption(BaseInputOption):
    type: Literal[OptionType.color] = OptionType.color
    default: Union[str, None]
    # pattern = {
    #     "regexp": r"^#[ABCDEFabcdef\d]{3,6}$",
    #     "error": "config_validate_color",  # i18n: config_validate_color
    # }


# ─ NUMERIC ───────────────────────────────────────────────


class NumberOption(BaseInputOption):
    # `number` and `range` are exactly the same, but `range` does render as a slider in web-admin
    type: Literal[OptionType.number, OptionType.range] = OptionType.number
    default: Union[int, None]
    min: Union[int, None] = None
    max: Union[int, None] = None
    step: Union[int, None] = None

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, int):
            return value

        if isinstance(value, str):
            value = value.strip()

        if isinstance(value, str) and value.isdigit():
            return int(value)

        if value in [None, ""]:
            return None

        option = option.dict() if isinstance(option, BaseOption) else option
        raise YunohostValidationError(
            "app_argument_invalid",
            name=option.get("id"),
            error=m18n.n("invalid_number"),
        )

    def _value_pre_validator(self):
        super()._value_pre_validator()
        if self.value in [None, ""]:
            return

        if self.min is not None and int(self.value) < self.min:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.id,
                error=m18n.n("invalid_number_min", min=self.min),
            )

        if self.max is not None and int(self.value) > self.max:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.id,
                error=m18n.n("invalid_number_max", max=self.max),
            )


# ─ BOOLEAN ───────────────────────────────────────────────


class BooleanOption(BaseInputOption):
    type: Literal[OptionType.boolean] = OptionType.boolean
    yes: Any = 1
    no: Any = 0
    default: Union[bool, int, str, None] = 0
    _yes_answers: set[str] = {"1", "yes", "y", "true", "t", "on"}
    _no_answers: set[str] = {"0", "no", "n", "false", "f", "off"}

    @staticmethod
    def humanize(value, option={}):
        option = option.dict() if isinstance(option, BaseOption) else option

        yes = option.get("yes", 1)
        no = option.get("no", 0)

        value = BooleanOption.normalize(value, option)

        if value == yes:
            return "yes"
        if value == no:
            return "no"
        if value is None:
            return ""

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("id"),
            value=value,
            choices="yes/no",
        )

    @staticmethod
    def normalize(value, option={}):
        option = option.dict() if isinstance(option, BaseOption) else option

        if isinstance(value, str):
            value = value.strip()

        technical_yes = option.get("yes", 1)
        technical_no = option.get("no", 0)

        no_answers = BooleanOption._no_answers
        yes_answers = BooleanOption._yes_answers

        assert (
            str(technical_yes).lower() not in no_answers
        ), f"'yes' value can't be in {no_answers}"
        assert (
            str(technical_no).lower() not in yes_answers
        ), f"'no' value can't be in {yes_answers}"

        no_answers.add(str(technical_no).lower())
        yes_answers.add(str(technical_yes).lower())

        strvalue = str(value).lower()

        if strvalue in yes_answers:
            return technical_yes
        if strvalue in no_answers:
            return technical_no

        if strvalue in ["none", ""]:
            return None

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("id"),
            value=strvalue,
            choices="yes/no",
        )

    def get(self, key, default=None):
        return getattr(self, key, default)

    def _get_prompt_message(self, value: Union[bool, None]) -> str:
        message = super()._get_prompt_message(value)

        if not self.readonly:
            message += " [yes | no]"

        return message


# ─ TIME ──────────────────────────────────────────────────


class DateOption(BaseInputOption):
    type: Literal[OptionType.date] = OptionType.date
    default: Union[str, None]
    # pattern = {
    #     "regexp": r"^\d{4}-\d\d-\d\d$",
    #     "error": "config_validate_date",  # i18n: config_validate_date
    # }

    def _value_pre_validator(self):
        super()._value_pre_validator()

        if self.value not in [None, ""]:
            try:
                datetime.strptime(self.value, "%Y-%m-%d")
            except ValueError:
                raise YunohostValidationError("config_validate_date")


class TimeOption(BaseInputOption):
    type: Literal[OptionType.time] = OptionType.time
    default: Union[str, int, None]
    # pattern = {
    #     "regexp": r"^(?:\d|[01]\d|2[0-3]):[0-5]\d$",
    #     "error": "config_validate_time",  # i18n: config_validate_time
    # }


# ─ LOCATIONS ─────────────────────────────────────────────


class EmailOption(BaseInputOption):
    type: Literal[OptionType.email] = OptionType.email
    default: Union[EmailStr, None]
    # pattern = {
    #     "regexp": r"^.+@.+",
    #     "error": "config_validate_email",  # i18n: config_validate_email
    # }


class WebPathOption(BaseInputOption):
    type: Literal[OptionType.path] = OptionType.path
    default: Union[str, None]

    @staticmethod
    def normalize(value, option={}):
        option = option.dict() if isinstance(option, BaseOption) else option

        if not isinstance(value, str):
            raise YunohostValidationError(
                "app_argument_invalid",
                name=option.get("id"),
                error="Argument for path should be a string.",
            )

        if not value.strip():
            if option.get("optional"):
                return ""
            # Hmpf here we could just have a "else" case
            # but we also want WebPathOption.normalize("") to return "/"
            # (i.e. if no option is provided, hence .get("optional") is None
            elif option.get("optional") is False:
                raise YunohostValidationError(
                    "app_argument_invalid",
                    name=option.get("id"),
                    error="Option is mandatory",
                )

        return "/" + value.strip().strip(" /")


class URLOption(BaseStringOption):
    type: Literal[OptionType.url] = OptionType.url
    default: Union[str, None]
    # pattern = {
    #     "regexp": r"^https?://.*$",
    #     "error": "config_validate_url",  # i18n: config_validate_url
    # }


# ─ FILE ──────────────────────────────────────────────────


class FileOption(BaseInputOption):
    type: Literal[OptionType.file] = OptionType.file
    # `FilePath` for CLI (path must exists and must be a file)
    # `bytes` for API (a base64 encoded file actually)
    accept: Union[str, None] = ""  # currently only used by the web-admin
    default: Union[str, None]
    _upload_dirs: set[str] = set()

    @classmethod
    def clean_upload_dirs(cls):
        # Delete files uploaded from API
        for upload_dir in cls._upload_dirs:
            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir)

    def _value_pre_validator(self):
        if self.value is None:
            self.value = self.current_value

        super()._value_pre_validator()

        # Validation should have already failed if required
        if self.value in [None, ""]:
            return self.value

        if Moulinette.interface.type != "api":
            if not os.path.exists(str(self.value)) or not os.path.isfile(
                str(self.value)
            ):
                raise YunohostValidationError(
                    "app_argument_invalid",
                    name=self.id,
                    error=m18n.n("file_does_not_exist", path=str(self.value)),
                )

    def _value_post_validator(self):
        from base64 import b64decode

        if not self.value:
            return ""

        upload_dir = tempfile.mkdtemp(prefix="ynh_filequestion_")
        _, file_path = tempfile.mkstemp(dir=upload_dir)

        FileOption._upload_dirs.add(upload_dir)

        logger.debug(f"Saving file {self.id} for file question into {file_path}")

        def is_file_path(s):
            return isinstance(s, str) and s.startswith("/") and os.path.exists(s)

        if Moulinette.interface.type != "api" or is_file_path(self.value):
            content = read_file(str(self.value), file_mode="rb")
        else:
            content = b64decode(self.value)

        write_to_file(file_path, content, file_mode="wb")

        self.value = file_path

        return self.value


# ─ CHOICES ───────────────────────────────────────────────


ChoosableOptions = Literal[
    OptionType.string,
    OptionType.color,
    OptionType.number,
    OptionType.date,
    OptionType.time,
    OptionType.email,
    OptionType.path,
    OptionType.url,
]


class BaseChoicesOption(BaseInputOption):
    # FIXME probably forbid choices to be None?
    choices: Union[dict[str, Any], list[Any], None]

    def _get_prompt_message(self, value: Any) -> str:
        message = super()._get_prompt_message(value)

        if self.readonly:
            if isinstance(self.choices, dict) and value is not None:
                value = self.choices[value]

            return f"{colorize(message, 'purple')} {value}"

        if self.choices:
            # Prevent displaying a shitload of choices
            # (e.g. 100+ available users when choosing an app admin...)
            choices = (
                list(self.choices.keys())
                if isinstance(self.choices, dict)
                else self.choices
            )
            splitted_choices = choices[:20]
            remaining_choices = len(choices[20:])

            if remaining_choices > 0:
                splitted_choices += [
                    m18n.n("other_available_options", n=remaining_choices)
                ]

            choices_to_display = " | ".join(str(choice) for choice in splitted_choices)

            return f"{message} [{choices_to_display}]"

        return message

    def _value_pre_validator(self):
        super()._value_pre_validator()

        # we have an answer, do some post checks
        if self.value not in [None, ""]:
            if self.choices and self.value not in self.choices:
                raise YunohostValidationError(
                    "app_argument_choice_invalid",
                    name=self.id,
                    value=self.value,
                    choices=", ".join(str(choice) for choice in self.choices),
                )


class SelectOption(BaseChoicesOption):
    type: Literal[OptionType.select] = OptionType.select
    choices: Union[dict[str, Any], list[Any]]
    default: Union[str, None]


class TagsOption(BaseChoicesOption):
    type: Literal[OptionType.tags] = OptionType.tags
    choices: Union[list[str], None] = None
    pattern: Union[Pattern, None] = None
    default: Union[str, list[str], None]

    @staticmethod
    def humanize(value, option={}):
        if isinstance(value, list):
            return ",".join(str(v) for v in value)
        return value

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, list):
            return ",".join(str(v) for v in value)
        if isinstance(value, str):
            value = value.strip()
        return value

    def _value_pre_validator(self):
        values = self.value
        if isinstance(values, str):
            values = values.split(",")
        elif values is None:
            values = []

        if not isinstance(values, list):
            if self.choices:
                raise YunohostValidationError(
                    "app_argument_choice_invalid",
                    name=self.id,
                    value=self.value,
                    choices=", ".join(str(choice) for choice in self.choices),
                )
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.id,
                error=f"'{str(self.value)}' is not a list",
            )

        for value in values:
            self.value = value
            super()._value_pre_validator()
        self.value = values

    def _value_post_validator(self):
        if isinstance(self.value, list):
            self.value = ",".join(self.value)
        return super()._value_post_validator()


# ─ ENTITIES ──────────────────────────────────────────────


class DomainOption(BaseChoicesOption):
    type: Literal[OptionType.domain] = OptionType.domain
    choices: Union[dict[str, str], None]

    @root_validator()
    def inject_domains_choices_and_default(cls, values: Values) -> Values:
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.domain import domain_list

        data = domain_list()
        values["choices"] = {
            domain: domain + " ★" if domain == data["main"] else domain
            for domain in data["domains"]
        }

        if values["default"] is None:
            values["default"] = data["main"]

        return values

    @staticmethod
    def normalize(value, option={}):
        if value.startswith("https://"):
            value = value[len("https://") :]
        elif value.startswith("http://"):
            value = value[len("http://") :]

        # Remove trailing slashes
        value = value.rstrip("/").lower()

        return value


class AppOption(BaseChoicesOption):
    type: Literal[OptionType.app] = OptionType.app
    choices: Union[dict[str, str], None]
    filter: Union[str, None] = None

    @root_validator()
    def inject_apps_choices(cls, values: Values) -> Values:
        from yunohost.app import app_list

        apps = app_list(full=True)["apps"]

        if values.get("filter", None):
            apps = [
                app
                for app in apps
                if evaluate_simple_js_expression(values["filter"], context=app)
            ]
        values["choices"] = {"_none": "---"}
        values["choices"].update(
            {
                app["id"]: f"{app['label']} ({app.get('domain_path', app['id'])})"
                for app in apps
            }
        )

        return values


class UserOption(BaseChoicesOption):
    type: Literal[OptionType.user] = OptionType.user
    choices: Union[dict[str, str], None]

    @root_validator()
    def inject_users_choices_and_default(cls, values: dict[str, Any]) -> dict[str, Any]:
        from yunohost.domain import _get_maindomain
        from yunohost.user import user_info, user_list

        values["choices"] = {
            username: f"{infos['fullname']} ({infos['mail']})"
            for username, infos in user_list()["users"].items()
        }

        # FIXME keep this to test if any user, do not raise error if no admin?
        if not values["choices"]:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=values["id"],
                error="You should create a YunoHost user first.",
            )

        if values["default"] is None:
            # FIXME: this code is obsolete with the new admins group
            # Should be replaced by something like "any first user we find in the admin group"
            root_mail = "root@%s" % _get_maindomain()
            for user in values["choices"].keys():
                if root_mail in user_info(user).get("mail-aliases", []):
                    values["default"] = user
                    break

        return values


class GroupOption(BaseChoicesOption):
    type: Literal[OptionType.group] = OptionType.group
    choices: Union[dict[str, str], None]

    @root_validator()
    def inject_groups_choices_and_default(cls, values: Values) -> Values:
        from yunohost.user import user_group_list

        groups = user_group_list(short=True, include_primary_groups=False)["groups"]

        def _human_readable_group(groupname):
            # i18n: visitors
            # i18n: all_users
            # i18n: admins
            return (
                m18n.n(groupname)
                if groupname in ["visitors", "all_users", "admins"]
                else groupname
            )

        values["choices"] = {
            groupname: _human_readable_group(groupname) for groupname in groups
        }

        if values["default"] is None:
            values["default"] = "all_users"

        return values


OPTIONS = {
    OptionType.display_text: DisplayTextOption,
    OptionType.markdown: MarkdownOption,
    OptionType.alert: AlertOption,
    OptionType.button: ButtonOption,
    OptionType.string: StringOption,
    OptionType.text: TextOption,
    OptionType.password: PasswordOption,
    OptionType.color: ColorOption,
    OptionType.number: NumberOption,
    OptionType.range: NumberOption,
    OptionType.boolean: BooleanOption,
    OptionType.date: DateOption,
    OptionType.time: TimeOption,
    OptionType.email: EmailOption,
    OptionType.path: WebPathOption,
    OptionType.url: URLOption,
    OptionType.file: FileOption,
    OptionType.select: SelectOption,
    OptionType.tags: TagsOption,
    OptionType.domain: DomainOption,
    OptionType.app: AppOption,
    OptionType.user: UserOption,
    OptionType.group: GroupOption,
}

AnyOption = Union[
    DisplayTextOption,
    MarkdownOption,
    AlertOption,
    ButtonOption,
    StringOption,
    TextOption,
    PasswordOption,
    ColorOption,
    NumberOption,
    BooleanOption,
    DateOption,
    TimeOption,
    EmailOption,
    WebPathOption,
    URLOption,
    FileOption,
    SelectOption,
    TagsOption,
    DomainOption,
    AppOption,
    UserOption,
    GroupOption,
]


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╴╭─╮┌─╮╭╮╮                                         │
# │  ├─╴│ │├┬╯│││                                         │
# │  ╵  ╰─╯╵ ╰╵╵╵                                         │
# ╰───────────────────────────────────────────────────────╯


class OptionsModel(BaseModel):
    # Pydantic will match option types to their models class based on the "type" attribute
    options: list[Annotated[AnyOption, Field(discriminator="type")]]

    @staticmethod
    def options_dict_to_list(options: dict[str, Any], defaults: dict[str, Any] = {}):
        return [
            option
            | {
                "id": id_,
                "type": option.get("type", "string"),
            }
            for id_, option in options.items()
        ]

    def __init__(self, **kwargs) -> None:
        super().__init__(options=self.options_dict_to_list(kwargs))


class FormModel(BaseModel):
    """
    Base form on which dynamic forms are built upon Options.
    """

    class Config:
        validate_assignment = True
        extra = Extra.ignore

    def __getitem__(self, name: str):
        # FIXME
        # if a FormModel's required field is not instancied with a value, it is
        # not available as an attr and therefor triggers an `AttributeError`
        # Also since `BaseReadonlyOption`s do not end up in form,
        # `form[AlertOption.id]` would also triggers an error
        # For convinience in those 2 cases, we return `None`
        if not hasattr(self, name):
            # Return None to trigger a validation error instead for required fields
            return None

        return getattr(self, name)

    def __setitem__(self, name: str, value: Any):
        setattr(self, name, value)

    def get(self, attr: str, default: Any = None) -> Any:
        try:
            return getattr(self, attr)
        except AttributeError:
            return default


def build_form(options: list[AnyOption], name: str = "DynamicForm") -> Type[FormModel]:
    """
    Returns a dynamic pydantic model class that can be used as a form.
    Parsing/validation occurs at instanciation and assignements.
    To avoid validation at instanciation, use `my_form.construct(**values)`
    """
    options_as_fields: Any = {}
    validators: dict[str, Any] = {}

    for option in options:
        if not isinstance(option, BaseInputOption):
            continue  # filter out non input options

        options_as_fields[option.id] = option._as_dynamic_model_field()

        for step in ("pre", "post"):
            validators[f"{option.id}_{step}_validator"] = validator(
                option.id, allow_reuse=True, pre=step == "pre"
            )(getattr(option, f"_value_{step}_validator"))

    return cast(
        Type[FormModel],
        create_model(
            name,
            __base__=FormModel,
            __validators__=validators,
            **options_as_fields,
        ),
    )


def hydrate_option_type(raw_option: dict[str, Any]) -> dict[str, Any]:
    type_ = raw_option.get(
        "type", OptionType.select if "choices" in raw_option else OptionType.string
    )
    # LEGACY (`choices` in option `string` used to be valid)
    if "choices" in raw_option and type_ == OptionType.string:
        logger.warning(
            f"Packagers: option {raw_option['id']} has 'choices' but has type 'string', use 'select' instead to remove this warning."
        )
        type_ = OptionType.select

    raw_option["type"] = type_

    return raw_option


# ╭───────────────────────────────────────────────────────╮
# │  ╷ ╷╶┬╴╶┬╴╷  ╭─╴                                      │
# │  │ │ │  │ │  ╰─╮                                      │
# │  ╰─╯ ╵ ╶┴╴╰─╴╶─╯                                      │
# ╰───────────────────────────────────────────────────────╯


Hooks = dict[str, Callable[[BaseInputOption], Any]]


def prompt_or_validate_form(
    options: list[AnyOption],
    form: FormModel,
    prefilled_answers: dict[str, Any] = {},
    context: Context = {},
    hooks: Hooks = {},
) -> FormModel:
    answers = {**prefilled_answers}
    values = {}

    for option in options:
        interactive = Moulinette.interface.type == "cli" and os.isatty(1)

        if isinstance(option, ButtonOption):
            if option.is_visible(context) and option.is_enabled(context):
                continue
            else:
                raise YunohostValidationError(
                    "config_action_disabled",
                    action=option.id,
                    help=_value_for_locale(option.help),
                )

        if not option.is_visible(context):
            if isinstance(option, BaseInputOption):
                # FIXME There could be several use case if the question is not displayed:
                # - we doesn't want to give a specific value
                # - we want to keep the previous value
                # - we want the default value
                context[option.id] = form[option.id] = None

            continue

        # if we try to get a `BaseReadonlyOption` value, which doesn't exists in the form,
        # we get `None`
        value = form[option.id]

        if isinstance(option, BaseReadonlyOption) or option.readonly:
            if isinstance(option, BaseInputOption):
                # FIXME normalized needed, form[option.id] should already be normalized
                # only update the context with the value
                context[option.id] = form[option.id]

                # FIXME here we could error out
                if option.id in prefilled_answers:
                    logger.warning(
                        f"'{option.id}' is readonly, value '{prefilled_answers[option.id]}' is then ignored."
                    )

            if interactive:
                Moulinette.display(option._get_prompt_message(value))

            continue

        for i in range(5):
            if option.id in prefilled_answers:
                value = prefilled_answers[option.id]
            elif interactive:
                value = option.humanize(value, option)
                choices = (
                    option.choices if isinstance(option, BaseChoicesOption) else []
                )
                value = Moulinette.prompt(
                    message=option._get_prompt_message(value),
                    is_password=isinstance(option, PasswordOption),
                    confirm=False,
                    prefill=value,
                    is_multiline=isinstance(option, TextOption),
                    autocomplete=choices,
                    help=_value_for_locale(option.help),
                )

            # Apply default value if none
            if value is None or value == "" and option.default is not None:
                value = option.default

            try:
                # Normalize and validate
                values[option.id] = form[option.id] = option.normalize(value, option)
            except (ValidationError, YunohostValidationError) as e:
                # If in interactive cli, re-ask the current question
                if i < 4 and interactive:
                    logger.error(str(e))
                    value = None
                    continue

                if isinstance(e, ValidationError):
                    error = "\n".join([err["msg"] for err in e.errors()])
                    raise YunohostValidationError(error, raw_msg=True)

                # Otherwise raise the ValidationError
                raise e

            break

        # Search for post actions in hooks
        post_hook = f"post_ask__{option.id}"
        if post_hook in hooks:
            values.update(hooks[post_hook](option))
            # FIXME reapply new values to form to validate it

        answers.update(values)
        context.update(values)

    return form


def ask_questions_and_parse_answers(
    raw_options: dict[str, Any],
    prefilled_answers: Union[str, Mapping[str, Any]] = {},
    current_values: Mapping[str, Any] = {},
    hooks: Hooks = {},
) -> tuple[list[AnyOption], FormModel]:
    """Parse arguments store in either manifest.json or actions.json or from a
    config panel against the user answers when they are present.

    Keyword arguments:
        raw_questions     -- the arguments description store in yunohost
                             format from actions.json/toml, manifest.json/toml
                             or config_panel.json/toml
        prefilled_answers -- a url "query-string" such as "domain=yolo.test&path=/foobar&admin=sam"
                             or a dict such as {"domain": "yolo.test", "path": "/foobar", "admin": "sam"}
    """

    if isinstance(prefilled_answers, str):
        # FIXME FIXME : this is not uniform with config_set() which uses parse.qs (no l)
        # parse_qsl parse single values
        # whereas parse.qs return list of values (which is useful for tags, etc)
        # For now, let's not migrate this piece of code to parse_qs
        # Because Aleks believes some bits of the app CI rely on overriding values (e.g. foo=foo&...&foo=bar)
        answers = dict(
            urllib.parse.parse_qsl(prefilled_answers or "", keep_blank_values=True)
        )
    elif isinstance(prefilled_answers, Mapping):
        answers = {**prefilled_answers}
    else:
        answers = {}

    context = {**current_values, **answers}

    # Validate/parse the options attributes
    try:
        model = OptionsModel(**raw_options)
    except ValidationError as e:
        error = "\n".join([err["msg"] for err in e.errors()])
        # FIXME use YunohostError instead since it is not really a user mistake?
        raise YunohostValidationError(error, raw_msg=True)

    # Build the form from those questions and instantiate it without
    # parsing/validation (construct) since it may contains required questions.
    form = build_form(model.options).construct()
    form = prompt_or_validate_form(
        model.options, form, prefilled_answers=answers, context=context, hooks=hooks
    )
    return (model.options, form)


def hydrate_questions_with_choices(raw_questions: List) -> List:
    out = []

    for raw_question in raw_questions:
        raw_question = hydrate_option_type(raw_question)
        question = OPTIONS[raw_question["type"]](**raw_question)
        if isinstance(question, BaseChoicesOption) and question.choices:
            raw_question["choices"] = question.choices
            raw_question["default"] = question.default
        out.append(raw_question)

    return out
