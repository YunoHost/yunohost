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
import operator as op
import os
import re
import shutil
import tempfile
import urllib.parse
from enum import Enum
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Union

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import read_file, write_to_file
from moulinette.utils.log import getActionLogger
from yunohost.log import OperationLogger
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.i18n import _value_for_locale

logger = getActionLogger("yunohost.form")

Context = dict[str, Any]

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


class BaseOption:
    def __init__(
        self,
        question: Dict[str, Any],
    ):
        self.id = question["id"]
        self.type = question.get("type", OptionType.string)
        self.visible = question.get("visible", True)

        self.readonly = question.get("readonly", False)
        if self.readonly and self.type in FORBIDDEN_READONLY_TYPES:
            # FIXME i18n
            raise YunohostError(
                "config_forbidden_readonly_type",
                type=self.type,
                id=self.id,
            )

        self.ask = question.get("ask", self.id)
        if not isinstance(self.ask, dict):
            self.ask = {"en": self.ask}

    def is_visible(self, context: Context) -> bool:
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    def _get_prompt_message(self) -> str:
        return _value_for_locale(self.ask)


# ╭───────────────────────────────────────────────────────╮
# │ DISPLAY OPTIONS                                       │
# ╰───────────────────────────────────────────────────────╯


class BaseReadonlyOption(BaseOption):
    def __init__(self, question):
        super().__init__(question)
        self.readonly = True


class DisplayTextOption(BaseReadonlyOption):
    type: Literal[OptionType.display_text] = OptionType.display_text


class MarkdownOption(BaseReadonlyOption):
    type: Literal[OptionType.markdown] = OptionType.markdown


class AlertOption(BaseReadonlyOption):
    type: Literal[OptionType.alert] = OptionType.alert

    def __init__(self, question):
        super().__init__(question)
        self.style = question.get("style", "info")

    def _get_prompt_message(self) -> str:
        text = _value_for_locale(self.ask)

        if self.style in ["success", "info", "warning", "danger"]:
            color = {
                "success": "green",
                "info": "cyan",
                "warning": "yellow",
                "danger": "red",
            }
            prompt = m18n.g(self.style) if self.style != "danger" else m18n.n("danger")
            return colorize(prompt, color[self.style]) + f" {text}"
        else:
            return text


class ButtonOption(BaseReadonlyOption):
    type: Literal[OptionType.button] = OptionType.button
    enabled = True

    def __init__(self, question):
        super().__init__(question)
        self.help = question.get("help")
        self.style = question.get("style", "success")
        self.enabled = question.get("enabled", True)

    def is_enabled(self, context: Context) -> bool:
        if isinstance(self.enabled, bool):
            return self.enabled

        return evaluate_simple_js_expression(self.enabled, context=context)


# ╭───────────────────────────────────────────────────────╮
# │ INPUT OPTIONS                                         │
# ╰───────────────────────────────────────────────────────╯


class BaseInputOption(BaseOption):
    hide_user_input_in_prompt = False
    pattern: Optional[Dict] = None

    def __init__(self, question: Dict[str, Any]):
        super().__init__(question)
        self.default = question.get("default", None)
        self.optional = question.get("optional", False)
        self.pattern = question.get("pattern", self.pattern)
        self.help = question.get("help")
        self.redact = question.get("redact", False)
        # .current_value is the currently stored value
        self.current_value = question.get("current_value")
        # .value is the "proposed" value which we got from the user
        self.value = question.get("value")
        # Use to return several values in case answer is in mutipart
        self.values: Dict[str, Any] = {}

        # Empty value is parsed as empty string
        if self.default == "":
            self.default = None

    @staticmethod
    def humanize(value, option={}):
        return str(value)

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, str):
            value = value.strip()
        return value

    def _get_prompt_message(self) -> str:
        message = super()._get_prompt_message()

        if self.readonly:
            message = colorize(message, "purple")
            return f"{message} {self.humanize(self.current_value)}"

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
    default_value = ""


class StringOption(BaseStringOption):
    type: Literal[OptionType.string] = OptionType.string


class TextOption(BaseStringOption):
    type: Literal[OptionType.text] = OptionType.text


class PasswordOption(BaseInputOption):
    type: Literal[OptionType.password] = OptionType.password
    hide_user_input_in_prompt = True
    default_value = ""
    forbidden_chars = "{}"

    def __init__(self, question):
        super().__init__(question)
        self.redact = True
        if self.default is not None:
            raise YunohostValidationError(
                "app_argument_password_no_default", name=self.id
            )

    def _value_pre_validator(self):
        super()._value_pre_validator()

        if self.value not in [None, ""]:
            if any(char in self.value for char in self.forbidden_chars):
                raise YunohostValidationError(
                    "pattern_password_app", forbidden_chars=self.forbidden_chars
                )

            # If it's an optional argument the value should be empty or strong enough
            from yunohost.utils.password import assert_password_is_strong_enough

            assert_password_is_strong_enough("user", self.value)


class ColorOption(BaseStringOption):
    type: Literal[OptionType.color] = OptionType.color
    pattern = {
        "regexp": r"^#[ABCDEFabcdef\d]{3,6}$",
        "error": "config_validate_color",  # i18n: config_validate_color
    }


# ─ NUMERIC ───────────────────────────────────────────────


class NumberOption(BaseInputOption):
    type: Literal[OptionType.number, OptionType.range] = OptionType.number
    default_value = None

    def __init__(self, question):
        super().__init__(question)
        self.min = question.get("min", None)
        self.max = question.get("max", None)
        self.step = question.get("step", None)

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

        option = option.__dict__ if isinstance(option, BaseOption) else option
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
    default_value = 0
    yes_answers = ["1", "yes", "y", "true", "t", "on"]
    no_answers = ["0", "no", "n", "false", "f", "off"]

    def __init__(self, question):
        super().__init__(question)
        self.yes = question.get("yes", 1)
        self.no = question.get("no", 0)
        if self.default is None:
            self.default = self.no

    @staticmethod
    def humanize(value, option={}):
        option = option.__dict__ if isinstance(option, BaseOption) else option

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
        option = option.__dict__ if isinstance(option, BaseOption) else option

        if isinstance(value, str):
            value = value.strip()

        technical_yes = option.get("yes", 1)
        technical_no = option.get("no", 0)

        no_answers = BooleanOption.no_answers
        yes_answers = BooleanOption.yes_answers

        assert (
            str(technical_yes).lower() not in no_answers
        ), f"'yes' value can't be in {no_answers}"
        assert (
            str(technical_no).lower() not in yes_answers
        ), f"'no' value can't be in {yes_answers}"

        no_answers += [str(technical_no).lower()]
        yes_answers += [str(technical_yes).lower()]

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

    def _get_prompt_message(self):
        message = super()._get_prompt_message()

        if not self.readonly:
            message += " [yes | no]"

        return message


# ─ TIME ──────────────────────────────────────────────────


class DateOption(BaseStringOption):
    type: Literal[OptionType.date] = OptionType.date
    pattern = {
        "regexp": r"^\d{4}-\d\d-\d\d$",
        "error": "config_validate_date",  # i18n: config_validate_date
    }

    def _value_pre_validator(self):
        from datetime import datetime

        super()._value_pre_validator()

        if self.value not in [None, ""]:
            try:
                datetime.strptime(self.value, "%Y-%m-%d")
            except ValueError:
                raise YunohostValidationError("config_validate_date")


class TimeOption(BaseStringOption):
    type: Literal[OptionType.time] = OptionType.time
    pattern = {
        "regexp": r"^(?:\d|[01]\d|2[0-3]):[0-5]\d$",
        "error": "config_validate_time",  # i18n: config_validate_time
    }


# ─ LOCATIONS ─────────────────────────────────────────────


class EmailOption(BaseStringOption):
    type: Literal[OptionType.email] = OptionType.email
    pattern = {
        "regexp": r"^.+@.+",
        "error": "config_validate_email",  # i18n: config_validate_email
    }


class WebPathOption(BaseInputOption):
    type: Literal[OptionType.path] = OptionType.path
    default_value = ""

    @staticmethod
    def normalize(value, option={}):
        option = option.__dict__ if isinstance(option, BaseOption) else option

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
    pattern = {
        "regexp": r"^https?://.*$",
        "error": "config_validate_url",  # i18n: config_validate_url
    }


# ─ FILE ──────────────────────────────────────────────────


class FileOption(BaseInputOption):
    type: Literal[OptionType.file] = OptionType.file
    upload_dirs: List[str] = []

    def __init__(self, question):
        super().__init__(question)
        self.accept = question.get("accept", "")

    @classmethod
    def clean_upload_dirs(cls):
        # Delete files uploaded from API
        for upload_dir in cls.upload_dirs:
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

        FileOption.upload_dirs += [upload_dir]

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


class BaseChoicesOption(BaseInputOption):
    def __init__(
        self,
        question: Dict[str, Any],
    ):
        super().__init__(question)
        # Don't restrict choices if there's none specified
        self.choices = question.get("choices", None)

    def _get_prompt_message(self) -> str:
        message = super()._get_prompt_message()

        if self.readonly:
            message = message
            choice = self.current_value

            if isinstance(self.choices, dict) and choice is not None:
                choice = self.choices[choice]

            return f"{colorize(message, 'purple')} {choice}"

        if self.choices:
            # Prevent displaying a shitload of choices
            # (e.g. 100+ available users when choosing an app admin...)
            choices = (
                list(self.choices.keys())
                if isinstance(self.choices, dict)
                else self.choices
            )
            choices_to_display = choices[:20]
            remaining_choices = len(choices[20:])

            if remaining_choices > 0:
                choices_to_display += [
                    m18n.n("other_available_options", n=remaining_choices)
                ]

            choices_to_display = " | ".join(
                str(choice) for choice in choices_to_display
            )

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
    default_value = ""


class TagsOption(BaseChoicesOption):
    type: Literal[OptionType.tags] = OptionType.tags
    default_value = ""

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

    def __init__(self, question):
        from yunohost.domain import domain_list, _get_maindomain

        super().__init__(question)

        if self.default is None:
            self.default = _get_maindomain()

        self.choices = {
            domain: domain + " ★" if domain == self.default else domain
            for domain in domain_list()["domains"]
        }

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

    def __init__(self, question):
        from yunohost.app import app_list

        super().__init__(question)
        self.filter = question.get("filter", None)

        apps = app_list(full=True)["apps"]

        if self.filter:
            apps = [
                app
                for app in apps
                if evaluate_simple_js_expression(self.filter, context=app)
            ]

        def _app_display(app):
            domain_path_or_id = f" ({app.get('domain_path', app['id'])})"
            return app["label"] + domain_path_or_id

        self.choices = {"_none": "---"}
        self.choices.update({app["id"]: _app_display(app) for app in apps})


class UserOption(BaseChoicesOption):
    type: Literal[OptionType.user] = OptionType.user

    def __init__(self, question):
        from yunohost.user import user_list, user_info
        from yunohost.domain import _get_maindomain

        super().__init__(question)

        users = user_list(fields = ["username", "fullname", "mail", "mail-alias"])["users"]

        self.choices = {
            username: f"{infos['fullname']} ({infos['mail']})"
            for username, infos in users.items()
        }

        if not self.choices:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.id,
                error="You should create a YunoHost user first.",
            )

        if self.default is None:
            # FIXME: this code is obsolete with the new admins group
            # Should be replaced by something like "any first user we find in the admin group"
            root_mail = "root@%s" % _get_maindomain()
            for user in self.choices.keys():
                if root_mail in users[user].get("mail-aliases", []):
                    self.default = user
                    break


class GroupOption(BaseChoicesOption):
    type: Literal[OptionType.group] = OptionType.group

    def __init__(self, question):
        from yunohost.user import user_group_list

        super().__init__(question)

        self.choices = list(
            user_group_list(short=True, include_primary_groups=False)["groups"]
        )

        def _human_readable_group(g):
            # i18n: visitors
            # i18n: all_users
            # i18n: admins
            return m18n.n(g) if g in ["visitors", "all_users", "admins"] else g

        self.choices = {g: _human_readable_group(g) for g in self.choices}

        if self.default is None:
            self.default = "all_users"


OPTIONS = {
    OptionType.display_text: DisplayTextOption,
    OptionType.markdown: MarkdownOption,
    OptionType.alert: AlertOption,
    OptionType.button: ButtonOption,
    OptionType.string: StringOption,
    OptionType.text: StringOption,
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
    raw_options: dict[str, Any],
    prefilled_answers: dict[str, Any] = {},
    context: Context = {},
    hooks: Hooks = {},
) -> list[BaseOption]:
    options = []
    answers = {**prefilled_answers}

    for id_, raw_option in raw_options.items():
        raw_option["id"] = id_
        raw_option["value"] = answers.get(id_)
        raw_option = hydrate_option_type(raw_option)
        option = OPTIONS[raw_option["type"]](raw_option)

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

        # FIXME not sure why we do not append Buttons to returned options
        options.append(option)

        if not option.is_visible(context):
            if isinstance(option, BaseInputOption):
                # FIXME There could be several use case if the question is not displayed:
                # - we doesn't want to give a specific value
                # - we want to keep the previous value
                # - we want the default value
                option.value = context[option.id] = None

            continue

        message = option._get_prompt_message()

        if option.readonly:
            if interactive:
                Moulinette.display(message)

            if isinstance(option, BaseInputOption):
                option.value = context[option.id] = option.current_value

            continue

        if isinstance(option, BaseInputOption):
            for i in range(5):
                if interactive and option.value is None:
                    prefill = ""
                    choices = (
                        option.choices if isinstance(option, BaseChoicesOption) else []
                    )

                    if option.current_value is not None:
                        prefill = option.humanize(option.current_value, option)
                    elif option.default is not None:
                        prefill = option.humanize(option.default, option)

                    option.value = Moulinette.prompt(
                        message=message,
                        is_password=isinstance(option, PasswordOption),
                        confirm=False,
                        prefill=prefill,
                        is_multiline=(option.type == "text"),
                        autocomplete=choices,
                        help=_value_for_locale(option.help),
                    )

                # Apply default value
                class_default = getattr(option, "default_value", None)
                if option.value in [None, ""] and (
                    option.default is not None or class_default is not None
                ):
                    option.value = (
                        class_default if option.default is None else option.default
                    )

                try:
                    # Normalize and validate
                    option.value = option.normalize(option.value, option)
                    option._value_pre_validator()
                except YunohostValidationError as e:
                    # If in interactive cli, re-ask the current question
                    if i < 4 and interactive:
                        logger.error(str(e))
                        option.value = None
                        continue

                    # Otherwise raise the ValidationError
                    raise

                break

            option.value = option.values[option.id] = option._value_post_validator()

            # Search for post actions in hooks
            post_hook = f"post_ask__{option.id}"
            if post_hook in hooks:
                option.values.update(hooks[post_hook](option))

            answers.update(option.values)
            context.update(option.values)

    return options


def ask_questions_and_parse_answers(
    raw_options: dict[str, Any],
    prefilled_answers: Union[str, Mapping[str, Any]] = {},
    current_values: Mapping[str, Any] = {},
    hooks: Hooks = {},
) -> list[BaseOption]:
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

    return prompt_or_validate_form(
        raw_options, prefilled_answers=answers, context=context, hooks=hooks
    )


def hydrate_questions_with_choices(raw_questions: List) -> List:
    out = []

    for raw_question in raw_questions:
        raw_question = hydrate_option_type(raw_question)
        question = OPTIONS[raw_question["type"]](raw_question)
        if isinstance(question, BaseChoicesOption) and question.choices:
            raw_question["choices"] = question.choices
            raw_question["default"] = question.default
        out.append(raw_question)

    return out
