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
            raise YunohostError("config_no_panel")

        # Read or get values and hydrate the config
        self._load_current_values()
        self._hydrate()

        # Format result in full mode
        if mode == "full":
            return self.config

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
            else:
                if "ask" in option:
                    result[key] = {"ask": _value_for_locale(option["ask"])}
                elif "i18n" in self.config:
                    result[key] = {
                        "ask": m18n.n(self.config["i18n"] + "_" + option["id"])
                    }
                if "current_value" in option:
                    question_class = ARGUMENTS_TYPE_PARSERS[
                        option.get("type", "string")
                    ]
                    result[key]["value"] = question_class.humanize(
                        option["current_value"], option
                    )

        return result

    def set(self, key=None, value=None, args=None, args_file=None):
        self.filter_key = key or ""

        # Read config panel toml
        self._get_config_panel()

        if not self.config:
            raise YunohostError("config_no_panel")

        if (args is not None or args_file is not None) and value is not None:
            raise YunohostError("config_args_value")

        if self.filter_key.count(".") != 2 and not value is None:
            raise YunohostError("config_set_value_on_section")

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

        try:
            self._ask()
            self._apply()

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

        if self.errors:
            return {
                "errors": self.errors,
            }

        self._reload_services()

        logger.success("Config updated as expected")
        return {}

    def _get_toml(self):
        return read_toml(self.config_path)

    def _get_config_panel(self):

        # Split filter_key
        filter_key = self.filter_key.split(".")
        if len(filter_key) > 3:
            raise YunohostError("config_too_many_sub_keys", key=self.filter_key)

        if not os.path.exists(self.config_path):
            return None
        toml_config_panel = self._get_toml()

        # Check TOML config panel is in a supported version
        if float(toml_config_panel["version"]) < CONFIG_PANEL_VERSION_SUPPORTED:
            raise YunohostError(
                "config_version_not_supported", version=toml_config_panel["version"]
            )

        # Transform toml format into internal format
        defaults = {
            "toml": {"version": 1.0},
            "panels": {
                "name": "",
                "services": [],
                "actions": {"apply": {"en": "Apply"}},
            },  # help
            "sections": {
                "name": "",
                "services": [],
                "optional": True,
            },  # visibleIf help
            "options": {}
            # ask type source help helpLink example style icon placeholder visibleIf
            # optional choices pattern limit min max step accept redact
        }

        #
        # FIXME : this is hella confusing ...
        # from what I understand, the purpose is to have some sort of "deep_update"
        # to apply the defaults onto the loaded toml ...
        # in that case we probably want to get inspiration from
        # https://stackoverflow.com/questions/3232943/update-value-of-a-nested-dictionary-of-varying-depth
        #
        def convert(toml_node, node_type):
            """Convert TOML in internal format ('full' mode used by webadmin)
            Here are some properties of 1.0 config panel in toml:
            - node properties and node children are mixed,
            - text are in english only
            - some properties have default values
            This function detects all children nodes and put them in a list
            """
            # Prefill the node default keys if needed
            default = defaults[node_type]
            node = {key: toml_node.get(key, value) for key, value in default.items()}

            # Define the filter_key part to use and the children type
            i = list(defaults).index(node_type)
            search_key = filter_key.get(i)
            subnode_type = list(defaults)[i + 1] if node_type != "options" else None

            for key, value in toml_node.items():
                # Key/value are a child node
                if (
                    isinstance(value, OrderedDict)
                    and key not in default
                    and subnode_type
                ):
                    # We exclude all nodes not referenced by the filter_key
                    if search_key and key != search_key:
                        continue
                    subnode = convert(value, subnode_type)
                    subnode["id"] = key
                    if node_type == "sections":
                        subnode["name"] = key  # legacy
                        subnode.setdefault("optional", toml_node.get("optional", True))
                    node.setdefault(subnode_type, []).append(subnode)
                # Key/value are a property
                else:
                    # Todo search all i18n keys
                    node[key] = (
                        value if key not in ["ask", "help", "name"] else {"en": value}
                    )
            return node

        self.config = convert(toml_config_panel, "toml")

        try:
            self.config["panels"][0]["sections"][0]["options"][0]
        except (KeyError, IndexError):
            raise YunohostError(
                "config_empty_or_bad_filter_key", filter_key=self.filter_key
            )

        return self.config

    def _hydrate(self):
        # Hydrating config panel with current value
        logger.debug("Hydrating config with current values")
        for _, _, option in self._iterate():
            if option["name"] not in self.values:
                continue
            value = self.values[option["name"]]
            # In general, the value is just a simple value.
            # Sometimes it could be a dict used to overwrite the option itself
            value = value if isinstance(value, dict) else {"current_value": value}
            option.update(value)

        return self.values

    def _ask(self):
        logger.debug("Ask unanswered question and prevalidate data")

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
        write_to_yaml(self.save_path, self.new_values)

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
    operation_logger = None

    def __init__(self, question, user_answers):
        self.name = question["name"]
        self.type = question.get("type", "string")
        self.default = question.get("default", None)
        self.current_value = question.get("current_value")
        self.optional = question.get("optional", False)
        self.choices = question.get("choices", [])
        self.pattern = question.get("pattern")
        self.ask = question.get("ask", {"en": self.name})
        self.help = question.get("help")
        self.helpLink = question.get("helpLink")
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

    def ask_if_needed(self):
        while True:
            # Display question if no value filled or if it's a readonly message
            if Moulinette.interface.type == "cli":
                text_for_user_input_in_cli = self._format_text_for_user_input_in_cli()
                if getattr(self, "readonly", False):
                    Moulinette.display(text_for_user_input_in_cli)

                elif self.value is None:
                    prefill = ""
                    if self.current_value is not None:
                        prefill = self.humanize(self.current_value, self)
                    elif self.default is not None:
                        prefill = self.default
                    self.value = Moulinette.prompt(
                        message=text_for_user_input_in_cli,
                        is_password=self.hide_user_input_in_prompt,
                        confirm=self.hide_user_input_in_prompt,
                        prefill=prefill,
                        is_multiline=(self.type == "text"),
                    )

            # Normalization
            # This is done to enforce a certain formating like for boolean
            self.value = self.normalize(self.value, self)

            # Apply default value
            if self.value in [None, ""] and self.default is not None:
                self.value = (
                    getattr(self, "default_value", None)
                    if self.default is None
                    else self.default
                )

            # Prevalidation
            try:
                self._prevalidate()
            except YunohostValidationError as e:
                if Moulinette.interface.type == "api":
                    raise
                Moulinette.display(str(e), "error")
                self.value = None
                continue
            break
        self.value = self._post_parse_value()

        return (self.value, self.argument_type)

    def _prevalidate(self):
        if self.value in [None, ""] and not self.optional:
            raise YunohostValidationError("app_argument_required", name=self.name)

        # we have an answer, do some post checks
        if self.value is not None:
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

    def _format_text_for_user_input_in_cli(self):
        text_for_user_input_in_cli = _value_for_locale(self.ask)

        if self.choices:
            text_for_user_input_in_cli += " [{0}]".format(" | ".join(self.choices))

        if self.help or self.helpLink:
            text_for_user_input_in_cli += ":\033[m"
        if self.help:
            text_for_user_input_in_cli += "\n - "
            text_for_user_input_in_cli += _value_for_locale(self.help)
        if self.helpLink:
            if not isinstance(self.helpLink, dict):
                self.helpLink = {"href": self.helpLink}
            text_for_user_input_in_cli += f"\n - See {self.helpLink['href']}"
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
        if self.operation_logger:
            self.operation_logger.data_to_redact.extend(data_to_redact)
        elif data_to_redact:
            raise YunohostError(
                f"Can't redact {self.name} because no operation logger available in the context",
                raw_msg=True,
            )

        return self.value


class StringQuestion(Question):
    argument_type = "string"
    default_value = ""


class TagsQuestion(Question):
    argument_type = "tags"

    @staticmethod
    def humanize(value, option={}):
        if isinstance(value, list):
            return ",".join(value)
        return value

    def _prevalidate(self):
        values = self.value
        if isinstance(values, str):
            values = values.split(",")
        for value in values:
            self.value = value
            super()._prevalidate()
        self.value = values


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

        if self.value is not None:
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


class BooleanQuestion(Question):
    argument_type = "boolean"
    default_value = False
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
            self.default = False

    def _format_text_for_user_input_in_cli(self):
        text_for_user_input_in_cli = _value_for_locale(self.ask)

        text_for_user_input_in_cli += " [yes | no]"

        if self.default is not None:
            formatted_default = self.humanize(self.default)
            text_for_user_input_in_cli += " (default: {0})".format(formatted_default)

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
            "app_argument_invalid", field=self.name, error=m18n.n("domain_unknown")
        )


class UserQuestion(Question):
    argument_type = "user"

    def __init__(self, question, user_answers):
        from yunohost.user import user_list, user_info
        from yunohost.domain import _get_maindomain

        super().__init__(question, user_answers)
        self.choices = user_list()["users"]
        if self.default is None:
            root_mail = "root@%s" % _get_maindomain()
            for user in self.choices.keys():
                if root_mail in user_info(user).get("mail-aliases", []):
                    self.default = user
                    break

    def _raise_invalid_answer(self):
        raise YunohostValidationError(
            "app_argument_invalid",
            field=self.name,
            error=m18n.n("user_unknown", user=self.value),
        )


class NumberQuestion(Question):
    argument_type = "number"
    default_value = ""

    @staticmethod
    def humanize(value, option={}):
        return str(value)

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)
        self.min = question.get("min", None)
        self.max = question.get("max", None)
        self.step = question.get("step", None)

    def _prevalidate(self):
        super()._prevalidate()
        if not isinstance(self.value, int) and not (
            isinstance(self.value, str) and self.value.isdigit()
        ):
            raise YunohostValidationError(
                "app_argument_invalid",
                field=self.name,
                error=m18n.n("invalid_number"),
            )

        if self.min is not None and int(self.value) < self.min:
            raise YunohostValidationError(
                "app_argument_invalid",
                field=self.name,
                error=m18n.n("invalid_number"),
            )

        if self.max is not None and int(self.value) > self.max:
            raise YunohostValidationError(
                "app_argument_invalid",
                field=self.name,
                error=m18n.n("invalid_number"),
            )

    def _post_parse_value(self):
        if isinstance(self.value, int):
            return super()._post_parse_value()

        if isinstance(self.value, str) and self.value.isdigit():
            return int(self.value)

        raise YunohostValidationError(
            "app_argument_invalid", field=self.name, error=m18n.n("invalid_number")
        )


class DisplayTextQuestion(Question):
    argument_type = "display_text"
    readonly = True

    def __init__(self, question, user_answers):
        super().__init__(question, user_answers)

        self.optional = True
        self.style = question.get("style", "info")

    def _format_text_for_user_input_in_cli(self):
        text = self.ask["en"]

        if self.style in ["success", "info", "warning", "danger"]:
            color = {
                "success": "green",
                "info": "cyan",
                "warning": "yellow",
                "danger": "red",
            }
            return colorize(m18n.g(self.style), color[self.style]) + f" {text}"
        else:
            return text


class FileQuestion(Question):
    argument_type = "file"
    upload_dirs = []

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
            self.accept = question.get("accept").replace(" ", "").split(",")
        else:
            self.accept = []
        if Moulinette.interface.type == "api":
            if user_answers.get(f"{self.name}[name]"):
                self.value = {
                    "content": self.value,
                    "filename": user_answers.get(f"{self.name}[name]", self.name),
                }
        # If path file are the same
        if self.value and str(self.value) == self.current_value:
            self.value = None

    def _prevalidate(self):
        super()._prevalidate()
        if (
            isinstance(self.value, str)
            and self.value
            and not os.path.exists(self.value)
        ):
            raise YunohostValidationError(
                "app_argument_invalid",
                field=self.name,
                error=m18n.n("file_does_not_exist", path=self.value),
            )
        if self.value in [None, ""] or not self.accept:
            return

        filename = self.value if isinstance(self.value, str) else self.value["filename"]
        if "." not in filename or "." + filename.split(".")[-1] not in self.accept:
            raise YunohostValidationError(
                "app_argument_invalid",
                field=self.name,
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

        if Moulinette.interface.type == "api":

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
    "email": StringQuestion,
    "url": StringQuestion,
    "date": StringQuestion,
    "time": StringQuestion,
    "color": StringQuestion,
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
