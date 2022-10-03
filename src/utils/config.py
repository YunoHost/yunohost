# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2018 YUNOHOST.ORG

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

import glob
import os
import re
import urllib.parse
import tempfile
import shutil
import ast
import operator as op
from collections import OrderedDict
from typing import Optional, Dict, List, Union, Any, Mapping, Callable

from moulinette.interfaces.cli import colorize
from moulinette import Moulinette, m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import (
    read_file,
    write_to_file,
    read_toml,
    read_yaml,
    write_to_yaml,
    mkdir,
)

from yunohost.utils.i18n import _value_for_locale
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.log import OperationLogger

logger = getActionLogger("yunohost.config")
CONFIG_PANEL_VERSION_SUPPORTED = 1.0


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


class ConfigPanel:
    entity_type = "config"
    save_path_tpl: Union[str, None] = None
    config_path_tpl = "/usr/share/yunohost/config_{entity_type}.toml"
    save_mode = "full"

    @classmethod
    def list(cls):
        """
        List available config panel
        """
        try:
            entities = [
                re.match(
                    "^" + cls.save_path_tpl.format(entity="(?p<entity>)") + "$", f
                ).group("entity")
                for f in glob.glob(cls.save_path_tpl.format(entity="*"))
                if os.path.isfile(f)
            ]
        except FileNotFoundError:
            entities = []
        return entities

    def __init__(self, entity, config_path=None, save_path=None, creation=False):
        self.entity = entity
        self.config_path = config_path
        if not config_path:
            self.config_path = self.config_path_tpl.format(
                entity=entity, entity_type=self.entity_type
            )
        self.save_path = save_path
        if not save_path and self.save_path_tpl:
            self.save_path = self.save_path_tpl.format(entity=entity)
        self.config = {}
        self.values = {}
        self.new_values = {}

        if (
            self.save_path
            and self.save_mode != "diff"
            and not creation
            and not os.path.exists(self.save_path)
        ):
            raise YunohostValidationError(
                f"{self.entity_type}_unknown", **{self.entity_type: entity}
            )
        if self.save_path and creation and os.path.exists(self.save_path):
            raise YunohostValidationError(
                f"{self.entity_type}_exists", **{self.entity_type: entity}
            )

        # Search for hooks in the config panel
        self.hooks = {
            func: getattr(self, func)
            for func in dir(self)
            if callable(getattr(self, func))
            and re.match("^(validate|post_ask)__", func)
        }

    def get(self, key="", mode="classic"):
        self.filter_key = key or ""

        # Read config panel toml
        self._get_config_panel()

        if not self.config:
            raise YunohostValidationError("config_no_panel")

        # Read or get values and hydrate the config
        self._load_current_values()
        self._hydrate()

        # In 'classic' mode, we display the current value if key refer to an option
        if self.filter_key.count(".") == 2 and mode == "classic":
            option = self.filter_key.split(".")[-1]
            return self.values.get(option, None)

        # Format result in 'classic' or 'export' mode
        logger.debug(f"Formating result in '{mode}' mode")
        result = {}
        for panel, section, option in self._iterate():

            if section["is_action_section"] and mode != "full":
                continue

            key = f"{panel['id']}.{section['id']}.{option['id']}"
            if mode == "export":
                result[option["id"]] = option.get("current_value")
                continue

            ask = None
            if "ask" in option:
                ask = _value_for_locale(option["ask"])
            elif "i18n" in self.config:
                ask = m18n.n(self.config["i18n"] + "_" + option["id"])

            if mode == "full":
                option["ask"] = ask
                question_class = ARGUMENTS_TYPE_PARSERS[option.get("type", "string")]
                # FIXME : maybe other properties should be taken from the question, not just choices ?.
                option["choices"] = question_class(option).choices
                option["default"] = question_class(option).default
                option["pattern"] = question_class(option).pattern
            else:
                result[key] = {"ask": ask}
                if "current_value" in option:
                    question_class = ARGUMENTS_TYPE_PARSERS[
                        option.get("type", "string")
                    ]
                    result[key]["value"] = question_class.humanize(
                        option["current_value"], option
                    )
                    # FIXME: semantics, technically here this is not about a prompt...
                    if question_class.hide_user_input_in_prompt:
                        result[key][
                            "value"
                        ] = "**************"  # Prevent displaying password in `config get`

        if mode == "full":
            return self.config
        else:
            return result

    def list_actions(self):

        actions = {}

        # FIXME : meh, loading the entire config panel is again going to cause
        # stupid issues for domain (e.g loading registrar stuff when willing to just list available actions ...)
        self.filter_key = ""
        self._get_config_panel()
        for panel, section, option in self._iterate():
            if option["type"] == "button":
                key = f"{panel['id']}.{section['id']}.{option['id']}"
                actions[key] = _value_for_locale(option["ask"])

        return actions

    def run_action(
        self, action=None, args=None, args_file=None, operation_logger=None
    ):
        #
        # FIXME : this stuff looks a lot like set() ...
        #

        self.filter_key = ".".join(action.split(".")[:2])
        action_id = action.split(".")[2]

        # Read config panel toml
        self._get_config_panel()

        # FIXME: should also check that there's indeed a key called action
        if not self.config:
            raise YunohostValidationError("config_no_such_action", action=action)

        # Import and parse pre-answered options
        logger.debug("Import and parse pre-answered options")
        self._parse_pre_answered(args, None, args_file)

        # Read or get values and hydrate the config
        self._load_current_values()
        self._hydrate()
        Question.operation_logger = operation_logger
        self._ask(action=action_id)

        # FIXME: here, we could want to check constrains on
        # the action's visibility / requirements wrt to the answer to questions ...

        if operation_logger:
            operation_logger.start()

        try:
            self._run_action(action_id)
        except YunohostError:
            raise
        # Script got manually interrupted ...
        # N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            error = m18n.n("operation_interrupted")
            logger.error(m18n.n("config_action_failed", action=action, error=error))
            raise
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
            logger.error(m18n.n("config_action_failed", action=action, error=error))
            raise
        finally:
            # Delete files uploaded from API
            # FIXME : this is currently done in the context of config panels,
            # but could also happen in the context of app install ... (or anywhere else
            # where we may parse args etc...)
            FileQuestion.clean_upload_dirs()

        # FIXME: i18n
        logger.success(f"Action {action_id} successful")
        operation_logger.success()

    def set(
        self, key=None, value=None, args=None, args_file=None, operation_logger=None
    ):
        self.filter_key = key or ""

        # Read config panel toml
        self._get_config_panel()

        if not self.config:
            raise YunohostValidationError("config_no_panel")

        if (args is not None or args_file is not None) and value is not None:
            raise YunohostValidationError(
                "You should either provide a value, or a serie of args/args_file, but not both at the same time",
                raw_msg=True,
            )

        if self.filter_key.count(".") != 2 and value is not None:
            raise YunohostValidationError("config_cant_set_value_on_section")

        # Import and parse pre-answered options
        logger.debug("Import and parse pre-answered options")
        self._parse_pre_answered(args, value, args_file)

        # Read or get values and hydrate the config
        self._load_current_values()
        self._hydrate()
        Question.operation_logger = operation_logger
        self._ask()

        if operation_logger:
            operation_logger.start()

        try:
            self._apply()
        except YunohostError:
            raise
        # Script got manually interrupted ...
        # N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            error = m18n.n("operation_interrupted")
            logger.error(m18n.n("config_apply_failed", error=error))
            raise
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
            logger.error(m18n.n("config_apply_failed", error=error))
            raise
        finally:
            # Delete files uploaded from API
            # FIXME : this is currently done in the context of config panels,
            # but could also happen in the context of app install ... (or anywhere else
            # where we may parse args etc...)
            FileQuestion.clean_upload_dirs()

        self._reload_services()

        logger.success("Config updated as expected")
        operation_logger.success()

    def _get_toml(self):
        return read_toml(self.config_path)

    def _get_config_panel(self):

        # Split filter_key
        filter_key = self.filter_key.split(".") if self.filter_key != "" else []
        if len(filter_key) > 3:
            raise YunohostError(
                f"The filter key {filter_key} has too many sub-levels, the max is 3.",
                raw_msg=True,
            )

        if not os.path.exists(self.config_path):
            logger.debug(f"Config panel {self.config_path} doesn't exists")
            return None

        toml_config_panel = self._get_toml()

        # Check TOML config panel is in a supported version
        if float(toml_config_panel["version"]) < CONFIG_PANEL_VERSION_SUPPORTED:
            raise YunohostError(
                "config_version_not_supported", version=toml_config_panel["version"]
            )

        # Transform toml format into internal format
        format_description = {
            "root": {
                "properties": ["version", "i18n"],
                "defaults": {"version": 1.0},
            },
            "panels": {
                "properties": ["name", "services", "actions", "help"],
                "defaults": {
                    "services": [],
                    "actions": {"apply": {"en": "Apply"}},
                },
            },
            "sections": {
                "properties": ["name", "services", "optional", "help", "visible"],
                "defaults": {
                    "name": "",
                    "services": [],
                    "optional": True,
                    "is_action_section": False,
                },
            },
            "options": {
                "properties": [
                    "ask",
                    "type",
                    "bind",
                    "help",
                    "example",
                    "default",
                    "style",
                    "icon",
                    "placeholder",
                    "visible",
                    "optional",
                    "choices",
                    "yes",
                    "no",
                    "pattern",
                    "limit",
                    "min",
                    "max",
                    "step",
                    "accept",
                    "redact",
                    "filter",
                    "readonly",
                    "enabled",
                ],
                "defaults": {},
            },
        }

        def _build_internal_config_panel(raw_infos, level):
            """Convert TOML in internal format ('full' mode used by webadmin)
            Here are some properties of 1.0 config panel in toml:
            - node properties and node children are mixed,
            - text are in english only
            - some properties have default values
            This function detects all children nodes and put them in a list
            """

            defaults = format_description[level]["defaults"]
            properties = format_description[level]["properties"]

            # Start building the ouput (merging the raw infos + defaults)
            out = {key: raw_infos.get(key, value) for key, value in defaults.items()}

            # Now fill the sublevels (+ apply filter_key)
            i = list(format_description).index(level)
            sublevel = list(format_description)[i + 1] if level != "options" else None
            search_key = filter_key[i] if len(filter_key) > i else False

            for key, value in raw_infos.items():
                # Key/value are a child node
                if (
                    isinstance(value, OrderedDict)
                    and key not in properties
                    and sublevel
                ):
                    # We exclude all nodes not referenced by the filter_key
                    if search_key and key != search_key:
                        continue
                    subnode = _build_internal_config_panel(value, sublevel)
                    subnode["id"] = key
                    if level == "root":
                        subnode.setdefault("name", {"en": key.capitalize()})
                    elif level == "sections":
                        subnode["name"] = key  # legacy
                        subnode.setdefault("optional", raw_infos.get("optional", True))
                        # If this section contains at least one button, it becomes an "action" section
                        if subnode["type"] == "button":
                            out["is_action_section"] = True
                    out.setdefault(sublevel, []).append(subnode)
                # Key/value are a property
                else:
                    if key not in properties:
                        logger.warning(f"Unknown key '{key}' found in config panel")
                    # Todo search all i18n keys
                    out[key] = (
                        value if key not in ["ask", "help", "name"] else {"en": value}
                    )
            return out

        self.config = _build_internal_config_panel(toml_config_panel, "root")

        try:
            self.config["panels"][0]["sections"][0]["options"][0]
        except (KeyError, IndexError):
            raise YunohostValidationError(
                "config_unknown_filter_key", filter_key=self.filter_key
            )

        # List forbidden keywords from helpers and sections toml (to avoid conflict)
        forbidden_keywords = [
            "old",
            "app",
            "changed",
            "file_hash",
            "binds",
            "types",
            "formats",
            "getter",
            "setter",
            "short_setting",
            "type",
            "bind",
            "nothing_changed",
            "changes_validated",
            "result",
            "max_progression",
        ]
        forbidden_keywords += format_description["sections"]
        forbidden_readonly_types = [
            "password",
            "app",
            "domain",
            "user",
            "file"
        ]

        for _, _, option in self._iterate():
            if option["id"] in forbidden_keywords:
                raise YunohostError("config_forbidden_keyword", keyword=option["id"])
            if (
                option.get("readonly", False) and
                option.get("type", "string") in forbidden_readonly_types
            ):
                raise YunohostError(
                    "config_forbidden_readonly_type",
                    type=option["type"],
                    id=option["id"]
                )

        return self.config

    def _hydrate(self):
        # Hydrating config panel with current value
        for _, section, option in self._iterate():
            if option["id"] not in self.values:

                allowed_empty_types = ["alert", "display_text", "markdown", "file", "button"]

                if section["is_action_section"] and option.get("default") is not None:
                    self.values[option["id"]] = option["default"]
                elif (
                    option["type"] in allowed_empty_types
                    or option.get("bind") == "null"
                ):
                    continue
                else:
                    raise YunohostError(
                        f"Config panel question '{option['id']}' should be initialized with a value during install or upgrade.",
                        raw_msg=True,
                    )
            value = self.values[option["name"]]
            # In general, the value is just a simple value.
            # Sometimes it could be a dict used to overwrite the option itself
            value = value if isinstance(value, dict) else {"current_value": value}
            option.update(value)

        return self.values

    def _ask(self, action=None):
        logger.debug("Ask unanswered question and prevalidate data")

        if "i18n" in self.config:
            for panel, section, option in self._iterate():
                if "ask" not in option:
                    option["ask"] = m18n.n(self.config["i18n"] + "_" + option["id"])

        def display_header(message):
            """CLI panel/section header display"""
            if Moulinette.interface.type == "cli" and self.filter_key.count(".") < 2:
                Moulinette.display(colorize(message, "purple"))

        for panel, section, obj in self._iterate(["panel", "section"]):

            if section and section.get("visible") and not evaluate_simple_js_expression(
                section["visible"], context=self.new_values
            ):
                continue

            # Ugly hack to skip action section ... except when when explicitly running actions
            if not action:
                if section and section["is_action_section"]:
                    continue

                if panel == obj:
                    name = _value_for_locale(panel["name"])
                    display_header(f"\n{'='*40}\n>>>> {name}\n{'='*40}")
                else:
                    name = _value_for_locale(section["name"])
                    if name:
                        display_header(f"\n# {name}")
            elif section:
                # filter action section options in case of multiple buttons
                section["options"] = [
                    option for option in section["options"]
                    if option.get("type", "string") != "button" or option["id"] == action
                ]

            if panel == obj:
                continue

            # Check and ask unanswered questions
            prefilled_answers = self.args.copy()
            prefilled_answers.update(self.new_values)

            questions = ask_questions_and_parse_answers(
                section["options"],
                prefilled_answers=prefilled_answers,
                current_values=self.values,
                hooks=self.hooks,
            )
            self.new_values.update(
                {
                    question.name: question.value
                    for question in questions
                    if question.value is not None
                }
            )

    def _get_default_values(self):
        return {
            option["id"]: option["default"]
            for _, _, option in self._iterate()
            if "default" in option
        }

    @property
    def future_values(self):
        return {**self.values, **self.new_values}

    def __getattr__(self, name):
        if "new_values" in self.__dict__ and name in self.new_values:
            return self.new_values[name]

        if "values" in self.__dict__ and name in self.values:
            return self.values[name]

        return self.__dict__[name]

    def _load_current_values(self):
        """
        Retrieve entries in YAML file
        And set default values if needed
        """

        # Inject defaults if needed (using the magic .update() ;))
        self.values = self._get_default_values()

        # Retrieve entries in the YAML
        if os.path.exists(self.save_path) and os.path.isfile(self.save_path):
            self.values.update(read_yaml(self.save_path) or {})

    def _parse_pre_answered(self, args, value, args_file):
        args = urllib.parse.parse_qs(args or "", keep_blank_values=True)
        self.args = {key: ",".join(value_) for key, value_ in args.items()}

        if args_file:
            # Import YAML / JSON file but keep --args values
            self.args = {**read_yaml(args_file), **self.args}

        if value is not None:
            self.args = {self.filter_key.split(".")[-1]: value}

    def _apply(self):
        logger.info("Saving the new configuration...")
        dir_path = os.path.dirname(os.path.realpath(self.save_path))
        if not os.path.exists(dir_path):
            mkdir(dir_path, mode=0o700)

        values_to_save = self.future_values
        if self.save_mode == "diff":
            defaults = self._get_default_values()
            values_to_save = {
                k: v for k, v in values_to_save.items() if defaults.get(k) != v
            }

        # Save the settings to the .yaml file
        write_to_yaml(self.save_path, values_to_save)

    def _reload_services(self):

        from yunohost.service import service_reload_or_restart

        services_to_reload = set()
        for panel, section, obj in self._iterate(["panel", "section", "option"]):
            services_to_reload |= set(obj.get("services", []))

        services_to_reload = list(services_to_reload)
        services_to_reload.sort(key="nginx".__eq__)
        if services_to_reload:
            logger.info("Reloading services...")
        for service in services_to_reload:
            if hasattr(self, "entity"):
                service = service.replace("__APP__", self.entity)
            service_reload_or_restart(service)

    def _iterate(self, trigger=["option"]):
        for panel in self.config.get("panels", []):
            if "panel" in trigger:
                yield (panel, None, panel)
            for section in panel.get("sections", []):
                if "section" in trigger:
                    yield (panel, section, section)
                if "option" in trigger:
                    for option in section.get("options", []):
                        yield (panel, section, option)


class Question:
    hide_user_input_in_prompt = False
    pattern: Optional[Dict] = None

    def __init__(
        self,
        question: Dict[str, Any],
        context: Mapping[str, Any] = {},
        hooks: Dict[str, Callable] = {},
    ):
        self.name = question["name"]
        self.context = context
        self.hooks = hooks
        self.type = question.get("type", "string")
        self.default = question.get("default", None)
        self.optional = question.get("optional", False)
        self.visible = question.get("visible", None)
        self.readonly = question.get("readonly", False)
        # Don't restrict choices if there's none specified
        self.choices = question.get("choices", None)
        self.pattern = question.get("pattern", self.pattern)
        self.ask = question.get("ask", {"en": self.name})
        self.help = question.get("help")
        self.redact = question.get("redact", False)
        self.filter = question.get("filter", None)
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

    def _prompt(self, text):
        prefill = ""
        if self.current_value is not None:
            prefill = self.humanize(self.current_value, self)
        elif self.default is not None:
            prefill = self.humanize(self.default, self)
        self.value = Moulinette.prompt(
            message=text,
            is_password=self.hide_user_input_in_prompt,
            confirm=False,
            prefill=prefill,
            is_multiline=(self.type == "text"),
            autocomplete=self.choices or [],
            help=_value_for_locale(self.help),
        )

    def ask_if_needed(self):

        if self.visible and not evaluate_simple_js_expression(
            self.visible, context=self.context
        ):
            # FIXME There could be several use case if the question is not displayed:
            # - we doesn't want to give a specific value
            # - we want to keep the previous value
            # - we want the default value
            self.value = self.values[self.name] = None
            return self.values

        for i in range(5):
            # Display question if no value filled or if it's a readonly message
            if Moulinette.interface.type == "cli" and os.isatty(1):
                text_for_user_input_in_cli = self._format_text_for_user_input_in_cli()
                if self.readonly:
                    Moulinette.display(text_for_user_input_in_cli)
                    self.value = self.values[self.name] = self.current_value
                    return self.values
                elif self.value is None:
                    self._prompt(text_for_user_input_in_cli)

            # Apply default value
            class_default = getattr(self, "default_value", None)
            if self.value in [None, ""] and (
                self.default is not None or class_default is not None
            ):
                self.value = class_default if self.default is None else self.default

            try:
                # Normalize and validate
                self.value = self.normalize(self.value, self)
                self._prevalidate()
            except YunohostValidationError as e:
                # If in interactive cli, re-ask the current question
                if i < 4 and Moulinette.interface.type == "cli" and os.isatty(1):
                    logger.error(str(e))
                    self.value = None
                    continue

                # Otherwise raise the ValidationError
                raise

            break

        self.value = self.values[self.name] = self._post_parse_value()

        # Search for post actions in hooks
        post_hook = f"post_ask__{self.name}"
        if post_hook in self.hooks:
            self.values.update(self.hooks[post_hook](self))

        return self.values

    def _prevalidate(self):
        if self.value in [None, ""] and not self.optional:
            raise YunohostValidationError("app_argument_required", name=self.name)

        # we have an answer, do some post checks
        if self.value not in [None, ""]:
            if self.choices and self.value not in self.choices:
                raise YunohostValidationError(
                    "app_argument_choice_invalid",
                    name=self.name,
                    value=self.value,
                    choices=", ".join(self.choices),
                )
            if self.pattern and not re.match(self.pattern["regexp"], str(self.value)):
                raise YunohostValidationError(
                    self.pattern["error"],
                    name=self.name,
                    value=self.value,
                )

    def _format_text_for_user_input_in_cli(self):

        text_for_user_input_in_cli = _value_for_locale(self.ask)

        if self.readonly:
            text_for_user_input_in_cli = colorize(text_for_user_input_in_cli, "purple")
            if self.choices:
                return text_for_user_input_in_cli + f" {self.choices[self.current_value]}"
            return text_for_user_input_in_cli + f" {self.humanize(self.current_value)}"
        elif self.choices:

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

            choices_to_display = " | ".join(choices_to_display)

            text_for_user_input_in_cli += f" [{choices_to_display}]"

        return text_for_user_input_in_cli

    def _post_parse_value(self):
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


class StringQuestion(Question):
    argument_type = "string"
    default_value = ""


class EmailQuestion(StringQuestion):
    pattern = {
        "regexp": r"^.+@.+",
        "error": "config_validate_email",  # i18n: config_validate_email
    }


class URLQuestion(StringQuestion):
    pattern = {
        "regexp": r"^https?://.*$",
        "error": "config_validate_url",  # i18n: config_validate_url
    }


class DateQuestion(StringQuestion):
    pattern = {
        "regexp": r"^\d{4}-\d\d-\d\d$",
        "error": "config_validate_date",  # i18n: config_validate_date
    }

    def _prevalidate(self):
        from datetime import datetime

        super()._prevalidate()

        if self.value not in [None, ""]:
            try:
                datetime.strptime(self.value, "%Y-%m-%d")
            except ValueError:
                raise YunohostValidationError("config_validate_date")


class TimeQuestion(StringQuestion):
    pattern = {
        "regexp": r"^(?:\d|[01]\d|2[0-3]):[0-5]\d$",
        "error": "config_validate_time",  # i18n: config_validate_time
    }


class ColorQuestion(StringQuestion):
    pattern = {
        "regexp": r"^#[ABCDEFabcdef\d]{3,6}$",
        "error": "config_validate_color",  # i18n: config_validate_color
    }


class TagsQuestion(Question):
    argument_type = "tags"
    default_value = ""

    @staticmethod
    def humanize(value, option={}):
        if isinstance(value, list):
            return ",".join(value)
        return value

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, list):
            return ",".join(value)
        if isinstance(value, str):
            value = value.strip()
        return value

    def _prevalidate(self):
        values = self.value
        if isinstance(values, str):
            values = values.split(",")
        elif values is None:
            values = []
        for value in values:
            self.value = value
            super()._prevalidate()
        self.value = values

    def _post_parse_value(self):
        if isinstance(self.value, list):
            self.value = ",".join(self.value)
        return super()._post_parse_value()


class PasswordQuestion(Question):
    hide_user_input_in_prompt = True
    argument_type = "password"
    default_value = ""
    forbidden_chars = "{}"

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        super().__init__(question, context, hooks)
        self.redact = True
        if self.default is not None:
            raise YunohostValidationError(
                "app_argument_password_no_default", name=self.name
            )

    def _prevalidate(self):
        super()._prevalidate()

        if self.value not in [None, ""]:
            if any(char in self.value for char in self.forbidden_chars):
                raise YunohostValidationError(
                    "pattern_password_app", forbidden_chars=self.forbidden_chars
                )

            # If it's an optional argument the value should be empty or strong enough
            from yunohost.utils.password import assert_password_is_strong_enough

            assert_password_is_strong_enough("user", self.value)


class PathQuestion(Question):
    argument_type = "path"
    default_value = ""

    @staticmethod
    def normalize(value, option={}):

        option = option.__dict__ if isinstance(option, Question) else option

        if not value.strip():
            if option.get("optional"):
                return ""
            # Hmpf here we could just have a "else" case
            # but we also want PathQuestion.normalize("") to return "/"
            # (i.e. if no option is provided, hence .get("optional") is None
            elif option.get("optional") is False:
                raise YunohostValidationError(
                    "app_argument_invalid",
                    name=option.get("name"),
                    error="Question is mandatory",
                )

        return "/" + value.strip().strip(" /")


class BooleanQuestion(Question):
    argument_type = "boolean"
    default_value = 0
    yes_answers = ["1", "yes", "y", "true", "t", "on"]
    no_answers = ["0", "no", "n", "false", "f", "off"]

    @staticmethod
    def humanize(value, option={}):

        option = option.__dict__ if isinstance(option, Question) else option

        yes = option.get("yes", 1)
        no = option.get("no", 0)

        value = BooleanQuestion.normalize(value, option)

        if value == yes:
            return "yes"
        if value == no:
            return "no"
        if value is None:
            return ""

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("name"),
            value=value,
            choices="yes/no",
        )

    @staticmethod
    def normalize(value, option={}):

        option = option.__dict__ if isinstance(option, Question) else option

        if isinstance(value, str):
            value = value.strip()

        technical_yes = option.get("yes", 1)
        technical_no = option.get("no", 0)

        no_answers = BooleanQuestion.no_answers
        yes_answers = BooleanQuestion.yes_answers

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
            name=option.get("name"),
            value=strvalue,
            choices="yes/no",
        )

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        super().__init__(question, context, hooks)
        self.yes = question.get("yes", 1)
        self.no = question.get("no", 0)
        if self.default is None:
            self.default = self.no

    def _format_text_for_user_input_in_cli(self):
        text_for_user_input_in_cli = super()._format_text_for_user_input_in_cli()

        if not self.readonly:
            text_for_user_input_in_cli += " [yes | no]"

        return text_for_user_input_in_cli

    def get(self, key, default=None):
        return getattr(self, key, default)


class DomainQuestion(Question):
    argument_type = "domain"

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        from yunohost.domain import domain_list, _get_maindomain

        super().__init__(question, context, hooks)

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


class AppQuestion(Question):
    argument_type = "app"

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        from yunohost.app import app_list

        super().__init__(question, context, hooks)

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


class UserQuestion(Question):
    argument_type = "user"

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        from yunohost.user import user_list, user_info
        from yunohost.domain import _get_maindomain

        super().__init__(question, context, hooks)

        self.choices = {
            username: f"{infos['fullname']} ({infos['mail']})"
            for username, infos in user_list()["users"].items()
        }

        if not self.choices:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.name,
                error="You should create a YunoHost user first.",
            )

        if self.default is None:
            root_mail = "root@%s" % _get_maindomain()
            for user in self.choices.keys():
                if root_mail in user_info(user).get("mail-aliases", []):
                    self.default = user
                    break


class NumberQuestion(Question):
    argument_type = "number"
    default_value = None

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        super().__init__(question, context, hooks)
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
            return value

        option = option.__dict__ if isinstance(option, Question) else option
        raise YunohostValidationError(
            "app_argument_invalid",
            name=option.get("name"),
            error=m18n.n("invalid_number"),
        )

    def _prevalidate(self):
        super()._prevalidate()
        if self.value in [None, ""]:
            return

        if self.min is not None and int(self.value) < self.min:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.name,
                error=m18n.n("invalid_number_min", min=self.min),
            )

        if self.max is not None and int(self.value) > self.max:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.name,
                error=m18n.n("invalid_number_max", max=self.max),
            )


class DisplayTextQuestion(Question):
    argument_type = "display_text"

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        super().__init__(question, context, hooks)

        self.optional = True
        self.readonly = True
        self.style = question.get(
            "style", "info" if question["type"] == "alert" else ""
        )

    def _format_text_for_user_input_in_cli(self):
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


class FileQuestion(Question):
    argument_type = "file"
    upload_dirs: List[str] = []

    @classmethod
    def clean_upload_dirs(cls):
        # Delete files uploaded from API
        for upload_dir in cls.upload_dirs:
            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir)

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        super().__init__(question, context, hooks)
        self.accept = question.get("accept", "")

    def _prevalidate(self):
        if self.value is None:
            self.value = self.current_value

        super()._prevalidate()

        if Moulinette.interface.type != "api":
            if not self.value or not os.path.exists(str(self.value)):
                raise YunohostValidationError(
                    "app_argument_invalid",
                    name=self.name,
                    error=m18n.n("file_does_not_exist", path=str(self.value)),
                )

    def _post_parse_value(self):
        from base64 import b64decode

        if not self.value:
            return self.value

        upload_dir = tempfile.mkdtemp(prefix="ynh_filequestion_")
        _, file_path = tempfile.mkstemp(dir=upload_dir)

        FileQuestion.upload_dirs += [upload_dir]

        logger.debug(f"Saving file {self.name} for file question into {file_path}")

        def is_file_path(s):
            return isinstance(s, str) and s.startswith("/") and os.path.exists(s)

        if Moulinette.interface.type != "api" or is_file_path(self.value):
            content = read_file(str(self.value), file_mode="rb")
        else:
            content = b64decode(self.value)

        write_to_file(file_path, content, file_mode="wb")

        self.value = file_path

        return self.value


class ButtonQuestion(Question):
    argument_type = "button"
    enabled = None

    def __init__(
        self, question, context: Mapping[str, Any] = {}, hooks: Dict[str, Callable] = {}
    ):
        super().__init__(question, context, hooks)
        self.enabled = question.get("enabled", None)


ARGUMENTS_TYPE_PARSERS = {
    "string": StringQuestion,
    "text": StringQuestion,
    "select": StringQuestion,
    "tags": TagsQuestion,
    "email": EmailQuestion,
    "url": URLQuestion,
    "date": DateQuestion,
    "time": TimeQuestion,
    "color": ColorQuestion,
    "password": PasswordQuestion,
    "path": PathQuestion,
    "boolean": BooleanQuestion,
    "domain": DomainQuestion,
    "user": UserQuestion,
    "number": NumberQuestion,
    "range": NumberQuestion,
    "display_text": DisplayTextQuestion,
    "alert": DisplayTextQuestion,
    "markdown": DisplayTextQuestion,
    "file": FileQuestion,
    "app": AppQuestion,
    "button": ButtonQuestion,
}


def ask_questions_and_parse_answers(
    raw_questions: Dict,
    prefilled_answers: Union[str, Mapping[str, Any]] = {},
    current_values: Mapping[str, Any] = {},
    hooks: Dict[str, Callable[[], None]] = {},
) -> List[Question]:
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
    out = []

    for raw_question in raw_questions:
        question_class = ARGUMENTS_TYPE_PARSERS[raw_question.get("type", "string")]
        raw_question["value"] = answers.get(raw_question["name"])
        question = question_class(raw_question, context=context, hooks=hooks)
        if question.type == "button":
            if (
                not question.enabled  # type: ignore
                or evaluate_simple_js_expression(question.enabled, context=context)  # type: ignore
            ):
                continue
            else:
                raise YunohostValidationError(
                    "config_action_disabled",
                    action=question.name,
                    help=_value_for_locale(question.help)
                )

        new_values = question.ask_if_needed()
        answers.update(new_values)
        context.update(new_values)
        out.append(question)

    return out


def hydrate_questions_with_choices(raw_questions: List) -> List:
    out = []

    for raw_question in raw_questions:
        question = ARGUMENTS_TYPE_PARSERS[raw_question.get("type", "string")](
            raw_question
        )
        if question.choices:
            raw_question["choices"] = question.choices
            raw_question["default"] = question.default
        out.append(raw_question)

    return out
