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
import glob
import os
import re
import urllib.parse
from collections import OrderedDict
from typing import Union

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import mkdir, read_toml, read_yaml, write_to_yaml
from moulinette.utils.log import getActionLogger
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.form import (
    OPTIONS,
    BaseChoicesOption,
    BaseInputOption,
    BaseOption,
    FileOption,
    OptionType,
    ask_questions_and_parse_answers,
    evaluate_simple_js_expression,
)
from yunohost.utils.i18n import _value_for_locale

logger = getActionLogger("yunohost.configpanel")
CONFIG_PANEL_VERSION_SUPPORTED = 1.0


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
        self._get_raw_settings()
        self._hydrate()

        # In 'classic' mode, we display the current value if key refer to an option
        if self.filter_key.count(".") == 2 and mode == "classic":
            option = self.filter_key.split(".")[-1]
            value = self.values.get(option, None)

            option_type = None
            for _, _, option_ in self._iterate():
                if option_["id"] == option:
                    option_type = OPTIONS[option_["type"]]
                    break

            return option_type.normalize(value) if option_type else value

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
                question_class = OPTIONS[option.get("type", OptionType.string)]
                # FIXME : maybe other properties should be taken from the question, not just choices ?.
                if issubclass(question_class, BaseChoicesOption):
                    option["choices"] = question_class(option).choices
                if issubclass(question_class, BaseInputOption):
                    option["default"] = question_class(option).default
                    option["pattern"] = question_class(option).pattern
            else:
                result[key] = {"ask": ask}
                if "current_value" in option:
                    question_class = OPTIONS[option.get("type", OptionType.string)]
                    if hasattr(question_class, "humanize"):
                        result[key]["value"] = question_class.humanize(
                            option["current_value"], option
                        )
                    else:
                        result[key]["value"] = option["current_value"]

                    # FIXME: semantics, technically here this is not about a prompt...
                    if getattr(question_class, "hide_user_input_in_prompt", None):
                        result[key][
                            "value"
                        ] = "**************"  # Prevent displaying password in `config get`

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
        self._parse_pre_answered(args, value, args_file)

        # Read or get values and hydrate the config
        self._get_raw_settings()
        self._hydrate()
        BaseOption.operation_logger = operation_logger
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
            FileOption.clean_upload_dirs()

        self._reload_services()

        logger.success("Config updated as expected")
        operation_logger.success()

    def list_actions(self):
        actions = {}

        # FIXME : meh, loading the entire config panel is again going to cause
        # stupid issues for domain (e.g loading registrar stuff when willing to just list available actions ...)
        self.filter_key = ""
        self._get_config_panel()
        for panel, section, option in self._iterate():
            if option["type"] == OptionType.button:
                key = f"{panel['id']}.{section['id']}.{option['id']}"
                actions[key] = _value_for_locale(option["ask"])

        return actions

    def run_action(self, action=None, args=None, args_file=None, operation_logger=None):
        #
        # FIXME : this stuff looks a lot like set() ...
        #

        self.filter_key = ".".join(action.split(".")[:2])
        action_id = action.split(".")[2]

        # Read config panel toml
        self._get_config_panel()

        # FIXME: should also check that there's indeed a key called action
        if not self.config:
            raise YunohostValidationError(f"No action named {action}", raw_msg=True)

        # Import and parse pre-answered options
        logger.debug("Import and parse pre-answered options")
        self._parse_pre_answered(args, None, args_file)

        # Read or get values and hydrate the config
        self._get_raw_settings()
        self._hydrate()
        BaseOption.operation_logger = operation_logger
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
            FileOption.clean_upload_dirs()

        # FIXME: i18n
        logger.success(f"Action {action_id} successful")
        operation_logger.success()

    def _get_raw_config(self):
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

        toml_config_panel = self._get_raw_config()

        # Check TOML config panel is in a supported version
        if float(toml_config_panel["version"]) < CONFIG_PANEL_VERSION_SUPPORTED:
            logger.error(
                f"Config panels version {toml_config_panel['version']} are not supported"
            )
            return None

        # Transform toml format into internal format
        format_description = {
            "root": {
                "properties": ["version", "i18n"],
                "defaults": {"version": 1.0},
            },
            "panels": {
                "properties": ["name", "services", "actions", "help", "bind"],
                "defaults": {
                    "services": [],
                    "actions": {"apply": {"en": "Apply"}},
                },
            },
            "sections": {
                "properties": [
                    "name",
                    "services",
                    "optional",
                    "help",
                    "visible",
                    "bind",
                ],
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
                    # "confirm", # TODO: to ask confirmation before running an action
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
                        if subnode.get("type") == OptionType.button:
                            out["is_action_section"] = True
                    out.setdefault(sublevel, []).append(subnode)
                # Key/value are a property
                else:
                    if key not in properties:
                        logger.warning(f"Unknown key '{key}' found in config panel")
                    # Todo search all i18n keys
                    out[key] = (
                        value
                        if key not in ["ask", "help", "name"] or isinstance(value, dict)
                        else {"en": value}
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

        for _, _, option in self._iterate():
            if option["id"] in forbidden_keywords:
                raise YunohostError("config_forbidden_keyword", keyword=option["id"])

        return self.config

    def _get_default_values(self):
        return {
            option["id"]: option["default"]
            for _, _, option in self._iterate()
            if "default" in option
        }

    def _get_raw_settings(self):
        """
        Retrieve entries in YAML file
        And set default values if needed
        """

        # Inject defaults if needed (using the magic .update() ;))
        self.values = self._get_default_values()

        # Retrieve entries in the YAML
        if os.path.exists(self.save_path) and os.path.isfile(self.save_path):
            self.values.update(read_yaml(self.save_path) or {})

    def _hydrate(self):
        # Hydrating config panel with current value
        for _, section, option in self._iterate():
            if option["id"] not in self.values:
                allowed_empty_types = {
                    OptionType.alert,
                    OptionType.display_text,
                    OptionType.markdown,
                    OptionType.file,
                    OptionType.button,
                }

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
            value = self.values[option["id"]]

            # Allow to use value instead of current_value in app config script.
            # e.g. apps may write `echo 'value: "foobar"'` in the config file (which is more intuitive that `echo 'current_value: "foobar"'`
            # For example hotspot used it...
            # See https://github.com/YunoHost/yunohost/pull/1546
            if (
                isinstance(value, dict)
                and "value" in value
                and "current_value" not in value
            ):
                value["current_value"] = value["value"]

            # In general, the value is just a simple value.
            # Sometimes it could be a dict used to overwrite the option itself
            value = value if isinstance(value, dict) else {"current_value": value}
            option.update(value)

            self.values[option["id"]] = value.get("current_value")

        return self.values

    def _ask(self, action=None):
        logger.debug("Ask unanswered question and prevalidate data")

        if "i18n" in self.config:
            for panel, section, option in self._iterate():
                if "ask" not in option:
                    option["ask"] = m18n.n(self.config["i18n"] + "_" + option["id"])
                # auto add i18n help text if present in locales
                if m18n.key_exists(self.config["i18n"] + "_" + option["id"] + "_help"):
                    option["help"] = m18n.n(
                        self.config["i18n"] + "_" + option["id"] + "_help"
                    )

        def display_header(message):
            """CLI panel/section header display"""
            if Moulinette.interface.type == "cli" and self.filter_key.count(".") < 2:
                Moulinette.display(colorize(message, "purple"))

        for panel, section, obj in self._iterate(["panel", "section"]):
            if (
                section
                and section.get("visible")
                and not evaluate_simple_js_expression(
                    section["visible"], context=self.future_values
                )
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
                    option
                    for option in section["options"]
                    if option.get("type", OptionType.string) != OptionType.button
                    or option["id"] == action
                ]

            if panel == obj:
                continue

            # Check and ask unanswered questions
            prefilled_answers = self.args.copy()
            prefilled_answers.update(self.new_values)

            questions = ask_questions_and_parse_answers(
                {question["id"]: question for question in section["options"]},
                prefilled_answers=prefilled_answers,
                current_values=self.values,
                hooks=self.hooks,
            )
            self.new_values.update(
                {
                    question.id: question.value
                    for question in questions
                    if not question.readonly and question.value is not None
                }
            )

    @property
    def future_values(self):
        return {**self.values, **self.new_values}

    def __getattr__(self, name):
        if "new_values" in self.__dict__ and name in self.new_values:
            return self.new_values[name]

        if "values" in self.__dict__ and name in self.values:
            return self.values[name]

        return self.__dict__[name]

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
