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
import toml
import urllib.parse
import tempfile
from collections import OrderedDict

from moulinette.interfaces.cli import colorize
from moulinette import Moulinette, m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import (
    read_toml,
    read_yaml,
    write_to_yaml,
    mkdir,
)

from yunohost.service import _get_services
from yunohost.service import _run_service_command, _get_services
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
                result[key] = {"ask": _value_for_locale(option["ask"])}
                if "current_value" in option:
                    result[key]["value"] = option["current_value"]

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
            logger.error(m18n.n("config_failed", error=error))
            raise
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
            logger.error(m18n.n("config_failed", error=error))
            raise
        finally:
            # Delete files uploaded from API
            FileArgumentParser.clean_upload_dirs()

        if self.errors:
            return {
                "errors": errors,
            }

        self._reload_services()

        logger.success("Config updated as expected")
        return {}

    def _get_toml(self):
        return read_toml(self.config_path)

    def _get_config_panel(self):
        # Split filter_key
        filter_key = dict(enumerate(self.filter_key.split(".")))
        if len(filter_key) > 3:
            raise YunohostError("config_too_much_sub_keys")

        if not os.path.exists(self.config_path):
            return None
        toml_config_panel = self._get_toml()

        # Check TOML config panel is in a supported version
        if float(toml_config_panel["version"]) < CONFIG_PANEL_VERSION_SUPPORTED:
            raise YunohostError(
                "config_too_old_version", version=toml_config_panel["version"]
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
            key: str(value[0])
            for key, value in self.new_values.items()
            if not value[0] is None
        }

    def _apply(self):
        logger.info("Running config script...")
        dir_path = os.path.dirname(os.path.realpath(self.save_path))
        if not os.path.exists(dir_path):
            mkdir(dir_path, mode=0o700)
        # Save the settings to the .yaml file
        write_to_yaml(self.save_path, self.new_values)

    def _reload_services(self):
        logger.info("Reloading services...")
        services_to_reload = set()
        for panel, section, obj in self._iterate(["panel", "section", "option"]):
            services_to_reload |= set(obj.get("services", []))

        services_to_reload = list(services_to_reload)
        services_to_reload.sort(key="nginx".__eq__)
        for service in services_to_reload:
            if "__APP__":
                service = service.replace("__APP__", self.app)
            logger.debug(f"Reloading {service}")
            if not _run_service_command("reload-or-restart", service):
                services = _get_services()
                test_conf = services[service].get("test_conf", "true")
                errors = check_output(f"{test_conf}; exit 0") if test_conf else ""
                raise YunohostError(
                    "config_failed_service_reload", service=service, errors=errors
                )

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
    "empty class to store questions information"


class YunoHostArgumentFormatParser(object):
    hide_user_input_in_prompt = False
    operation_logger = None

    def parse_question(self, question, user_answers):
        parsed_question = Question()

        parsed_question.name = question["name"]
        parsed_question.type = question.get("type", "string")
        parsed_question.default = question.get("default", None)
        parsed_question.current_value = question.get("current_value")
        parsed_question.optional = question.get("optional", False)
        parsed_question.choices = question.get("choices", [])
        parsed_question.pattern = question.get("pattern")
        parsed_question.ask = question.get("ask", {"en": f"{parsed_question.name}"})
        parsed_question.help = question.get("help")
        parsed_question.helpLink = question.get("helpLink")
        parsed_question.value = user_answers.get(parsed_question.name)
        parsed_question.redact = question.get("redact", False)

        # Empty value is parsed as empty string
        if parsed_question.default == "":
            parsed_question.default = None

        return parsed_question

    def parse(self, question, user_answers):
        question = self.parse_question(question, user_answers)

        while True:
            # Display question if no value filled or if it's a readonly message
            if Moulinette.interface.type == "cli":
                text_for_user_input_in_cli = self._format_text_for_user_input_in_cli(
                    question
                )
                if getattr(self, "readonly", False):
                    Moulinette.display(text_for_user_input_in_cli)

                elif question.value is None:
                    prefill = ""
                    if question.current_value is not None:
                        prefill = question.current_value
                    elif question.default is not None:
                        prefill = question.default
                    question.value = Moulinette.prompt(
                        message=text_for_user_input_in_cli,
                        is_password=self.hide_user_input_in_prompt,
                        confirm=self.hide_user_input_in_prompt,
                        prefill=prefill,
                        is_multiline=(question.type == "text"),
                    )

            # Apply default value
            if question.value in [None, ""] and question.default is not None:
                question.value = (
                    getattr(self, "default_value", None)
                    if question.default is None
                    else question.default
                )

            # Prevalidation
            try:
                self._prevalidate(question)
            except YunohostValidationError as e:
                if Moulinette.interface.type == "api":
                    raise
                Moulinette.display(str(e), "error")
                question.value = None
                continue
            break
        # this is done to enforce a certain formating like for boolean
        # by default it doesn't do anything
        question.value = self._post_parse_value(question)

        return (question.value, self.argument_type)

    def _prevalidate(self, question):
        if question.value in [None, ""] and not question.optional:
            raise YunohostValidationError("app_argument_required", name=question.name)

        # we have an answer, do some post checks
        if question.value is not None:
            if question.choices and question.value not in question.choices:
                self._raise_invalid_answer(question)
            if question.pattern and not re.match(
                question.pattern["regexp"], str(question.value)
            ):
                raise YunohostValidationError(
                    question.pattern["error"],
                    name=question.name,
                    value=question.value,
                )

    def _raise_invalid_answer(self, question):
        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=question.name,
            value=question.value,
            choices=", ".join(question.choices),
        )

    def _format_text_for_user_input_in_cli(self, question):
        text_for_user_input_in_cli = _value_for_locale(question.ask)

        if question.choices:
            text_for_user_input_in_cli += " [{0}]".format(" | ".join(question.choices))

        if question.help or question.helpLink:
            text_for_user_input_in_cli += ":\033[m"
        if question.help:
            text_for_user_input_in_cli += "\n - "
            text_for_user_input_in_cli += _value_for_locale(question.help)
        if question.helpLink:
            if not isinstance(question.helpLink, dict):
                question.helpLink = {"href": question.helpLink}
            text_for_user_input_in_cli += f"\n - See {question.helpLink['href']}"
        return text_for_user_input_in_cli

    def _post_parse_value(self, question):
        if not question.redact:
            return question.value

        # Tell the operation_logger to redact all password-type / secret args
        # Also redact the % escaped version of the password that might appear in
        # the 'args' section of metadata (relevant for password with non-alphanumeric char)
        data_to_redact = []
        if question.value and isinstance(question.value, str):
            data_to_redact.append(question.value)
        if question.current_value and isinstance(question.current_value, str):
            data_to_redact.append(question.current_value)
        data_to_redact += [
            urllib.parse.quote(data)
            for data in data_to_redact
            if urllib.parse.quote(data) != data
        ]
        if self.operation_logger:
            self.operation_logger.data_to_redact.extend(data_to_redact)
        elif data_to_redact:
            raise YunohostError("app_argument_cant_redact", arg=question.name)

        return question.value


class StringArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "string"
    default_value = ""


class TagsArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "tags"

    def _prevalidate(self, question):
        values = question.value
        for value in values.split(","):
            question.value = value
            super()._prevalidate(question)
        question.value = values


class PasswordArgumentParser(YunoHostArgumentFormatParser):
    hide_user_input_in_prompt = True
    argument_type = "password"
    default_value = ""
    forbidden_chars = "{}"

    def parse_question(self, question, user_answers):
        question = super(PasswordArgumentParser, self).parse_question(
            question, user_answers
        )
        question.redact = True
        if question.default is not None:
            raise YunohostValidationError(
                "app_argument_password_no_default", name=question.name
            )

        return question

    def _prevalidate(self, question):
        super()._prevalidate(question)

        if question.value is not None:
            if any(char in question.value for char in self.forbidden_chars):
                raise YunohostValidationError(
                    "pattern_password_app", forbidden_chars=self.forbidden_chars
                )

            # If it's an optional argument the value should be empty or strong enough
            from yunohost.utils.password import assert_password_is_strong_enough

            assert_password_is_strong_enough("user", question.value)


class PathArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "path"
    default_value = ""


class BooleanArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "boolean"
    default_value = False

    def parse_question(self, question, user_answers):
        question = super().parse_question(question, user_answers)

        if question.default is None:
            question.default = False

        return question

    def _format_text_for_user_input_in_cli(self, question):
        text_for_user_input_in_cli = _value_for_locale(question.ask)

        text_for_user_input_in_cli += " [yes | no]"

        if question.default is not None:
            formatted_default = "yes" if question.default else "no"
            text_for_user_input_in_cli += " (default: {0})".format(formatted_default)

        return text_for_user_input_in_cli

    def _post_parse_value(self, question):
        if isinstance(question.value, bool):
            return 1 if question.value else 0

        if str(question.value).lower() in ["1", "yes", "y", "true"]:
            return 1

        if str(question.value).lower() in ["0", "no", "n", "false"]:
            return 0

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=question.name,
            value=question.value,
            choices="yes, no, y, n, 1, 0",
        )


class DomainArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "domain"

    def parse_question(self, question, user_answers):
        from yunohost.domain import domain_list, _get_maindomain

        question = super(DomainArgumentParser, self).parse_question(
            question, user_answers
        )

        if question.default is None:
            question.default = _get_maindomain()

        question.choices = domain_list()["domains"]

        return question

    def _raise_invalid_answer(self, question):
        raise YunohostValidationError(
            "app_argument_invalid", field=question.name, error=m18n.n("domain_unknown")
        )


class UserArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "user"

    def parse_question(self, question, user_answers):
        from yunohost.user import user_list, user_info
        from yunohost.domain import _get_maindomain

        question = super(UserArgumentParser, self).parse_question(
            question, user_answers
        )
        question.choices = user_list()["users"]
        if question.default is None:
            root_mail = "root@%s" % _get_maindomain()
            for user in question.choices.keys():
                if root_mail in user_info(user).get("mail-aliases", []):
                    question.default = user
                    break

        return question

    def _raise_invalid_answer(self, question):
        raise YunohostValidationError(
            "app_argument_invalid",
            field=question.name,
            error=m18n.n("user_unknown", user=question.value),
        )


class NumberArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "number"
    default_value = ""

    def parse_question(self, question, user_answers):
        question_parsed = super().parse_question(question, user_answers)
        question_parsed.min = question.get("min", None)
        question_parsed.max = question.get("max", None)
        if question_parsed.default is None:
            question_parsed.default = 0

        return question_parsed

    def _prevalidate(self, question):
        super()._prevalidate(question)
        if not isinstance(question.value, int) and not (
            isinstance(question.value, str) and question.value.isdigit()
        ):
            raise YunohostValidationError(
                "app_argument_invalid",
                field=question.name,
                error=m18n.n("invalid_number"),
            )

        if question.min is not None and int(question.value) < question.min:
            raise YunohostValidationError(
                "app_argument_invalid",
                field=question.name,
                error=m18n.n("invalid_number"),
            )

        if question.max is not None and int(question.value) > question.max:
            raise YunohostValidationError(
                "app_argument_invalid",
                field=question.name,
                error=m18n.n("invalid_number"),
            )

    def _post_parse_value(self, question):
        if isinstance(question.value, int):
            return super()._post_parse_value(question)

        if isinstance(question.value, str) and question.value.isdigit():
            return int(question.value)

        raise YunohostValidationError(
            "app_argument_invalid", field=question.name, error=m18n.n("invalid_number")
        )


class DisplayTextArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "display_text"
    readonly = True

    def parse_question(self, question, user_answers):
        question_parsed = super().parse_question(question, user_answers)

        question_parsed.optional = True
        question_parsed.style = question.get("style", "info")

        return question_parsed

    def _format_text_for_user_input_in_cli(self, question):
        text = question.ask["en"]

        if question.style in ["success", "info", "warning", "danger"]:
            color = {
                "success": "green",
                "info": "cyan",
                "warning": "yellow",
                "danger": "red",
            }
            return colorize(m18n.g(question.style), color[question.style]) + f" {text}"
        else:
            return text


class FileArgumentParser(YunoHostArgumentFormatParser):
    argument_type = "file"
    upload_dirs = []

    @classmethod
    def clean_upload_dirs(cls):
        # Delete files uploaded from API
        if Moulinette.interface.type == "api":
            for upload_dir in cls.upload_dirs:
                if os.path.exists(upload_dir):
                    shutil.rmtree(upload_dir)

    def parse_question(self, question, user_answers):
        question_parsed = super().parse_question(question, user_answers)
        if question.get("accept"):
            question_parsed.accept = question.get("accept").replace(" ", "").split(",")
        else:
            question_parsed.accept = []
        if Moulinette.interface.type == "api":
            if user_answers.get(f"{question_parsed.name}[name]"):
                question_parsed.value = {
                    "content": question_parsed.value,
                    "filename": user_answers.get(
                        f"{question_parsed.name}[name]", question_parsed.name
                    ),
                }
        # If path file are the same
        if (
            question_parsed.value
            and str(question_parsed.value) == question_parsed.current_value
        ):
            question_parsed.value = None

        return question_parsed

    def _prevalidate(self, question):
        super()._prevalidate(question)
        if (
            isinstance(question.value, str)
            and question.value
            and not os.path.exists(question.value)
        ):
            raise YunohostValidationError(
                "app_argument_invalid",
                field=question.name,
                error=m18n.n("invalid_number1"),
            )
        if question.value in [None, ""] or not question.accept:
            return

        filename = (
            question.value
            if isinstance(question.value, str)
            else question.value["filename"]
        )
        if "." not in filename or "." + filename.split(".")[-1] not in question.accept:
            raise YunohostValidationError(
                "app_argument_invalid",
                field=question.name,
                error=m18n.n("invalid_number2"),
            )

    def _post_parse_value(self, question):
        from base64 import b64decode

        # Upload files from API
        # A file arg contains a string with "FILENAME:BASE64_CONTENT"
        if not question.value:
            return question.value

        if Moulinette.interface.type == "api":

            upload_dir = tempfile.mkdtemp(prefix="tmp_configpanel_")
            FileArgumentParser.upload_dirs += [upload_dir]
            filename = question.value["filename"]
            logger.debug(
                f"Save uploaded file {question.value['filename']} from API into {upload_dir}"
            )

            # Filename is given by user of the API. For security reason, we have replaced
            # os.path.join to avoid the user to be able to rewrite a file in filesystem
            # i.e. os.path.join("/foo", "/etc/passwd") == "/etc/passwd"
            file_path = os.path.normpath(upload_dir + "/" + filename)
            if not file_path.startswith(upload_dir + "/"):
                raise YunohostError("relative_parent_path_in_filename_forbidden")
            i = 2
            while os.path.exists(file_path):
                file_path = os.path.normpath(upload_dir + "/" + filename + (".%d" % i))
                i += 1
            content = question.value["content"]
            try:
                with open(file_path, "wb") as f:
                    f.write(b64decode(content))
            except IOError as e:
                raise YunohostError("cannot_write_file", file=file_path, error=str(e))
            except Exception as e:
                raise YunohostError("error_writing_file", file=file_path, error=str(e))
            question.value = file_path
        return question.value


ARGUMENTS_TYPE_PARSERS = {
    "string": StringArgumentParser,
    "text": StringArgumentParser,
    "select": StringArgumentParser,
    "tags": TagsArgumentParser,
    "email": StringArgumentParser,
    "url": StringArgumentParser,
    "date": StringArgumentParser,
    "time": StringArgumentParser,
    "color": StringArgumentParser,
    "password": PasswordArgumentParser,
    "path": PathArgumentParser,
    "boolean": BooleanArgumentParser,
    "domain": DomainArgumentParser,
    "user": UserArgumentParser,
    "number": NumberArgumentParser,
    "range": NumberArgumentParser,
    "display_text": DisplayTextArgumentParser,
    "alert": DisplayTextArgumentParser,
    "markdown": DisplayTextArgumentParser,
    "file": FileArgumentParser,
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
        parser = ARGUMENTS_TYPE_PARSERS[question.get("type", "string")]()

        answer = parser.parse(question=question, user_answers=user_answers)
        if answer is not None:
            parsed_answers_dict[question["name"]] = answer

    return parsed_answers_dict
