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

import os
import re
import urllib.parse
import tempfile
import shutil
from collections import OrderedDict
from typing import Optional, Dict, List

from moulinette.interfaces.cli import colorize
from moulinette import Moulinette, m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import (
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


class ConfigPanel:
    def __init__(self, config_path, save_path=None):
        self.config_path = config_path
        self.save_path = save_path
        self.config = {}
        self.values = {}
        self.new_values = {}

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
                # edit self.config directly
                option["ask"] = ask
            else:
                result[key] = {"ask": ask}
                if "current_value" in option:
                    question_class = ARGUMENTS_TYPE_PARSERS[
                        option.get("type", "string")
                    ]
                    result[key]["value"] = question_class.humanize(
                        option["current_value"], option
                    )

        if mode == "full":
            return self.config
        else:
            return result

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
        args = urllib.parse.parse_qs(args or "", keep_blank_values=True)
        self.args = {key: ",".join(value_) for key, value_ in args.items()}

        if args_file:
            # Import YAML / JSON file but keep --args values
            self.args = {**read_yaml(args_file), **self.args}

        if value is not None:
            self.args = {self.filter_key.split(".")[-1]: value}

        # Read or get values and hydrate the config
        self._load_current_values()
        self._hydrate()
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
            "toml": {
                "properties": ["version", "i18n"],
                "default": {"version": 1.0},
            },
            "panels": {
                "properties": ["name", "services", "actions", "help"],
                "default": {
                    "services": [],
                    "actions": {"apply": {"en": "Apply"}},
                },
            },
            "sections": {
                "properties": ["name", "services", "optional", "help", "visible"],
                "default": {
                    "name": "",
                    "services": [],
                    "optional": True,
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
                ],
                "default": {},
            },
        }

        def convert(toml_node, node_type):
            """Convert TOML in internal format ('full' mode used by webadmin)
            Here are some properties of 1.0 config panel in toml:
            - node properties and node children are mixed,
            - text are in english only
            - some properties have default values
            This function detects all children nodes and put them in a list
            """
            # Prefill the node default keys if needed
            default = format_description[node_type]["default"]
            node = {key: toml_node.get(key, value) for key, value in default.items()}

            properties = format_description[node_type]["properties"]

            # Define the filter_key part to use and the children type
            i = list(format_description).index(node_type)
            subnode_type = (
                list(format_description)[i + 1] if node_type != "options" else None
            )
            search_key = filter_key[i] if len(filter_key) > i else False

            for key, value in toml_node.items():
                # Key/value are a child node
                if (
                    isinstance(value, OrderedDict)
                    and key not in properties
                    and subnode_type
                ):
                    # We exclude all nodes not referenced by the filter_key
                    if search_key and key != search_key:
                        continue
                    subnode = convert(value, subnode_type)
                    subnode["id"] = key
                    if node_type == "toml":
                        subnode.setdefault("name", {"en": key.capitalize()})
                    elif node_type == "sections":
                        subnode["name"] = key  # legacy
                        subnode.setdefault("optional", toml_node.get("optional", True))
                    node.setdefault(subnode_type, []).append(subnode)
                # Key/value are a property
                else:
                    if key not in properties:
                        logger.warning(f"Unknown key '{key}' found in config toml")
                    # Todo search all i18n keys
                    node[key] = (
                        value if key not in ["ask", "help", "name"] else {"en": value}
                    )
            return node

        self.config = convert(toml_config_panel, "toml")

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

        for _, _, option in self._iterate():
            if option["id"] in forbidden_keywords:
                raise YunohostError("config_forbidden_keyword", keyword=option["id"])
        return self.config

    def _hydrate(self):
        # Hydrating config panel with current value
        logger.debug("Hydrating config with current values")
        for _, _, option in self._iterate():
            if option["id"] not in self.values:
                allowed_empty_types = ["alert", "display_text", "markdown", "file"]
                if (
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

    def _ask(self):
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
            if panel == obj:
                name = _value_for_locale(panel["name"])
                display_header(f"\n{'='*40}\n>>>> {name}\n{'='*40}")
                continue
            name = _value_for_locale(section["name"])
            if name:
                display_header(f"\n# {name}")

            # Check and ask unanswered questions
            self.new_values.update(
                parse_args_in_yunohost_format(self.args, section["options"])
            )
        self.new_values = {
            key: value[0]
            for key, value in self.new_values.items()
            if not value[0] is None
        }
        self.errors = None

    def _get_default_values(self):
        return {
            option["id"]: option["default"]
            for _, _, option in self._iterate()
            if "default" in option
        }

    def _load_current_values(self):
        """
        Retrieve entries in YAML file
        And set default values if needed
        """

        # Retrieve entries in the YAML
        on_disk_settings = {}
        if os.path.exists(self.save_path) and os.path.isfile(self.save_path):
            on_disk_settings = read_yaml(self.save_path) or {}

        # Inject defaults if needed (using the magic .update() ;))
        self.values = self._get_default_values()
        self.values.update(on_disk_settings)

    def _apply(self):
        logger.info("Saving the new configuration...")
        dir_path = os.path.dirname(os.path.realpath(self.save_path))
        if not os.path.exists(dir_path):
            mkdir(dir_path, mode=0o700)

        values_to_save = {**self.values, **self.new_values}
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
            if hasattr(self, "app"):
                service = service.replace("__APP__", self.app)
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


class Question(object):
    hide_user_input_in_prompt = False
    pattern: Optional[Dict] = None

    def __init__(self, question, user_answers):
        self.name = question["name"]
        self.type = question.get("type", "string")
        self.default = question.get("default", None)
        self.current_value = question.get("current_value")
        self.optional = question.get("optional", False)
        self.choices = question.get("choices", [])
        self.pattern = question.get("pattern", self.pattern)
        self.ask = question.get("ask", {"en": self.name})
        self.help = question.get("help")
        self.value = user_answers.get(self.name)
        self.redact = question.get("redact", False)

        # Empty value is parsed as empty string
        if self.default == "":
            self.default = None

    @staticmethod
    def humanize(value, option={}):
        return str(value)

    @staticmethod
    def normalize(value, option={}):
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
            confirm=False,  # We doesn't want to confirm this kind of password like in webadmin
            prefill=prefill,
            is_multiline=(self.type == "text"),
        )

    def ask_if_needed(self):
        for i in range(5):
            # Display question if no value filled or if it's a readonly message
            if Moulinette.interface.type == "cli" and os.isatty(1):
                text_for_user_input_in_cli = self._format_text_for_user_input_in_cli()
                if getattr(self, "readonly", False):
                    Moulinette.display(text_for_user_input_in_cli)
                elif self.value is None:
                    self._prompt(text_for_user_input_in_cli)

            # Apply default value
            class_default = getattr(self, "default_value", None)
            if self.value in [None, ""] and (
                self.default is not None or class_default is not None
            ):
                self.value = class_default if self.default is None else self.default

            # Normalization
            # This is done to enforce a certain formating like for boolean
            self.value = self.normalize(self.value, self)

            # Prevalidation
            try:
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
        self.value = self._post_parse_value()

        return (self.value, self.argument_type)

    def _prevalidate(self):
        if self.value in [None, ""] and not self.optional:
            raise YunohostValidationError("app_argument_required", name=self.name)

        # we have an answer, do some post checks
        if self.value not in [None, ""]:
            if self.choices and self.value not in self.choices:
                self._raise_invalid_answer()
            if self.pattern and not re.match(self.pattern["regexp"], str(self.value)):
                raise YunohostValidationError(
                    self.pattern["error"],
                    name=self.name,
                    value=self.value,
                )

    def _raise_invalid_answer(self):
        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=self.name,
            value=self.value,
            choices=", ".join(self.choices),
        )

    def _format_text_for_user_input_in_cli(self, column=False):
        text_for_user_input_in_cli = _value_for_locale(self.ask)

        if self.choices:
            text_for_user_input_in_cli += " [{0}]".format(" | ".join(self.choices))

        if self.help or column:
            text_for_user_input_in_cli += ":\033[m"
        if self.help:
            text_for_user_input_in_cli += "\n - "
            text_for_user_input_in_cli += _value_for_locale(self.help)
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
        "regexp": r"^(1[12]|0?\d):[0-5]\d$",
        "error": "config_validate_time",  # i18n: config_validate_time
    }


class ColorQuestion(StringQuestion):
    pattern = {
        "regexp": r"^#[ABCDEFabcdef\d]{3,6}$",
        "error": "config_validate_color",  # i18n: config_validate_color
    }


class TagsQuestion(Question):
    argument_type = "tags"

    @staticmethod
    def humanize(value, option={}):
        if isinstance(value, list):
            return ",".join(value)
        return value

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, list):
            return ",".join(value)
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

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)
        self.redact = True
        if self.default is not None:
            raise YunohostValidationError(
                "app_argument_password_no_default", name=self.name
            )

    @staticmethod
    def humanize(value, option={}):
        if value:
            return "********"  # Avoid to display the password on screen
        return ""

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

    def _format_text_for_user_input_in_cli(self):
        need_column = self.current_value or self.optional
        text_for_user_input_in_cli = super()._format_text_for_user_input_in_cli(
            need_column
        )
        if self.current_value:
            text_for_user_input_in_cli += "\n - " + m18n.n(
                "app_argument_password_help_keep"
            )
        if self.optional:
            text_for_user_input_in_cli += "\n - " + m18n.n(
                "app_argument_password_help_optional"
            )

        return text_for_user_input_in_cli

    def _prompt(self, text):
        super()._prompt(text)
        if self.current_value and self.value == "":
            self.value = self.current_value
        elif self.value == " ":
            self.value = ""


class PathQuestion(Question):
    argument_type = "path"
    default_value = ""


class BooleanQuestion(Question):
    argument_type = "boolean"
    default_value = 0
    yes_answers = ["1", "yes", "y", "true", "t", "on"]
    no_answers = ["0", "no", "n", "false", "f", "off"]

    @staticmethod
    def humanize(value, option={}):

        yes = option.get("yes", 1)
        no = option.get("no", 0)
        value = str(value).lower()
        if value == str(yes).lower():
            return "yes"
        if value == str(no).lower():
            return "no"
        if value in BooleanQuestion.yes_answers:
            return "yes"
        if value in BooleanQuestion.no_answers:
            return "no"

        if value in ["none", ""]:
            return ""

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("name", ""),
            value=value,
            choices="yes, no, y, n, 1, 0",
        )

    @staticmethod
    def normalize(value, option={}):
        yes = option.get("yes", 1)
        no = option.get("no", 0)

        if str(value).lower() in BooleanQuestion.yes_answers:
            return yes

        if str(value).lower() in BooleanQuestion.no_answers:
            return no

        if value in [None, ""]:
            return None
        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("name", ""),
            value=value,
            choices="yes, no, y, n, 1, 0",
        )

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)
        self.yes = question.get("yes", 1)
        self.no = question.get("no", 0)
        if self.default is None:
            self.default = self.no

    def _format_text_for_user_input_in_cli(self):
        text_for_user_input_in_cli = super()._format_text_for_user_input_in_cli()

        text_for_user_input_in_cli += " [yes | no]"

        return text_for_user_input_in_cli

    def get(self, key, default=None):
        try:
            return getattr(self, key)
        except AttributeError:
            return default


class DomainQuestion(Question):
    argument_type = "domain"

    def __init__(self, question, user_answers):
        from yunohost.domain import domain_list, _get_maindomain

        super().__init__(question, user_answers)

        if self.default is None:
            self.default = _get_maindomain()

        self.choices = domain_list()["domains"]

    def _raise_invalid_answer(self):
        raise YunohostValidationError(
            "app_argument_invalid",
            name=self.name,
            error=m18n.n("domain_name_unknown", domain=self.value),
        )


class UserQuestion(Question):
    argument_type = "user"

    def __init__(self, question, user_answers):
        from yunohost.user import user_list, user_info
        from yunohost.domain import _get_maindomain

        super().__init__(question, user_answers)
        self.choices = user_list()["users"]

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

    def _raise_invalid_answer(self):
        raise YunohostValidationError(
            "app_argument_invalid",
            name=self.name,
            error=m18n.n("user_unknown", user=self.value),
        )


class NumberQuestion(Question):
    argument_type = "number"
    default_value = None

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)
        self.min = question.get("min", None)
        self.max = question.get("max", None)
        self.step = question.get("step", None)

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, int):
            return value

        if isinstance(value, str) and value.isdigit():
            return int(value)

        if value in [None, ""]:
            return value

        raise YunohostValidationError(
            "app_argument_invalid", name=option.name, error=m18n.n("invalid_number")
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
    readonly = True

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)

        self.optional = True
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
        if Moulinette.interface.type == "api":
            for upload_dir in cls.upload_dirs:
                if os.path.exists(upload_dir):
                    shutil.rmtree(upload_dir)

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)
        if question.get("accept"):
            self.accept = question.get("accept")
        else:
            self.accept = ""
        if Moulinette.interface.type == "api":
            if user_answers.get(f"{self.name}[name]"):
                self.value = {
                    "content": self.value,
                    "filename": user_answers.get(f"{self.name}[name]", self.name),
                }

    def _prevalidate(self):
        if self.value is None:
            self.value = self.current_value

        super()._prevalidate()
        if (
            isinstance(self.value, str)
            and self.value
            and not os.path.exists(self.value)
        ):
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.name,
                error=m18n.n("file_does_not_exist", path=self.value),
            )
        if self.value in [None, ""] or not self.accept:
            return

        filename = self.value if isinstance(self.value, str) else self.value["filename"]
        if "." not in filename or "." + filename.split(".")[
            -1
        ] not in self.accept.replace(" ", "").split(","):
            raise YunohostValidationError(
                "app_argument_invalid",
                name=self.name,
                error=m18n.n(
                    "file_extension_not_accepted", file=filename, accept=self.accept
                ),
            )

    def _post_parse_value(self):
        from base64 import b64decode

        # Upload files from API
        # A file arg contains a string with "FILENAME:BASE64_CONTENT"
        if not self.value:
            return self.value

        if Moulinette.interface.type == "api" and isinstance(self.value, dict):

            upload_dir = tempfile.mkdtemp(prefix="tmp_configpanel_")
            FileQuestion.upload_dirs += [upload_dir]
            filename = self.value["filename"]
            logger.debug(
                f"Save uploaded file {self.value['filename']} from API into {upload_dir}"
            )

            # Filename is given by user of the API. For security reason, we have replaced
            # os.path.join to avoid the user to be able to rewrite a file in filesystem
            # i.e. os.path.join("/foo", "/etc/passwd") == "/etc/passwd"
            file_path = os.path.normpath(upload_dir + "/" + filename)
            if not file_path.startswith(upload_dir + "/"):
                raise YunohostError(
                    f"Filename '{filename}' received from the API got a relative parent path, which is forbidden",
                    raw_msg=True,
                )
            i = 2
            while os.path.exists(file_path):
                file_path = os.path.normpath(upload_dir + "/" + filename + (".%d" % i))
                i += 1

            content = self.value["content"]

            write_to_file(file_path, b64decode(content), file_mode="wb")

            self.value = file_path
        return self.value


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
}


def parse_args_in_yunohost_format(user_answers, argument_questions):
    """Parse arguments store in either manifest.json or actions.json or from a
    config panel against the user answers when they are present.

    Keyword arguments:
        user_answers -- a dictionnary of arguments from the user (generally
                        empty in CLI, filed from the admin interface)
        argument_questions -- the arguments description store in yunohost
                              format from actions.json/toml, manifest.json/toml
                              or config_panel.json/toml
    """
    parsed_answers_dict = OrderedDict()

    for question in argument_questions:
        question_class = ARGUMENTS_TYPE_PARSERS[question.get("type", "string")]
        question = question_class(question, user_answers)

        answer = question.ask_if_needed()
        if answer is not None:
            parsed_answers_dict[question.name] = answer

    return parsed_answers_dict
