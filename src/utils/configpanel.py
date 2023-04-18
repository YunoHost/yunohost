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
from collections import OrderedDict
from logging import getLogger
from typing import TYPE_CHECKING, Any, Literal, Sequence, Type, Union

from pydantic import BaseModel, Extra, validator

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import mkdir, read_toml, read_yaml, write_to_yaml
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.form import (
    AnyOption,
    BaseInputOption,
    BaseOption,
    BaseReadonlyOption,
    FileOption,
    OptionsModel,
    OptionType,
    Translation,
    build_form,
    evaluate_simple_js_expression,
    parse_prefilled_values,
    prompt_or_validate_form,
)
from yunohost.utils.i18n import _value_for_locale

if TYPE_CHECKING:
    from pydantic.fields import ModelField
    from yunohost.utils.form import FormModel, Hooks

logger = getLogger("yunohost.configpanel")


# ╭───────────────────────────────────────────────────────╮
# │  ╭╮╮╭─╮┌─╮┌─╴╷  ╭─╴                                   │
# │  ││││ ││ │├─╴│  ╰─╮                                   │
# │  ╵╵╵╰─╯└─╯╰─╴╰─╴╶─╯                                   │
# ╰───────────────────────────────────────────────────────╯

CONFIG_PANEL_VERSION_SUPPORTED = 1.0


class ContainerModel(BaseModel):
    id: str
    name: Union[Translation, None] = None
    services: list[str] = []
    help: Union[Translation, None] = None

    def translate(self, i18n_key: Union[str, None] = None):
        """
        Translate `ask` and `name` attributes of panels and section.
        This is in place mutation.
        """

        for key in ("help", "name"):
            value = getattr(self, key)
            if value:
                setattr(self, key, _value_for_locale(value))
            elif key == "help" and m18n.key_exists(f"{i18n_key}_{self.id}_help"):
                setattr(self, key, m18n.n(f"{i18n_key}_{self.id}_help"))


class SectionModel(ContainerModel, OptionsModel):
    visible: Union[bool, str] = True
    optional: bool = True

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        id: str,
        name: Union[Translation, None] = None,
        services: list[str] = [],
        help: Union[Translation, None] = None,
        visible: Union[bool, str] = True,
        **kwargs,
    ) -> None:
        options = self.options_dict_to_list(kwargs, optional=True)

        ContainerModel.__init__(
            self,
            id=id,
            name=name,
            services=services,
            help=help,
            visible=visible,
            options=options,
        )

    @property
    def is_action_section(self):
        return any([option.type is OptionType.button for option in self.options])

    def is_visible(self, context: dict[str, Any]):
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    def translate(self, i18n_key: Union[str, None] = None):
        """
        Call to `Container`'s `translate` for self translation
        + Call to `OptionsContainer`'s `translate_options` for options translation
        """
        super().translate(i18n_key)
        self.translate_options(i18n_key)


class PanelModel(ContainerModel):
    # FIXME what to do with `actions?
    actions: dict[str, Translation] = {"apply": {"en": "Apply"}}
    sections: list[SectionModel]

    class Config:
        extra = Extra.allow

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        id: str,
        name: Union[Translation, None] = None,
        services: list[str] = [],
        help: Union[Translation, None] = None,
        **kwargs,
    ) -> None:
        sections = [data | {"id": name} for name, data in kwargs.items()]
        super().__init__(
            id=id, name=name, services=services, help=help, sections=sections
        )

    def translate(self, i18n_key: Union[str, None] = None):
        """
        Recursivly mutate translatable attributes to their translation
        """
        super().translate(i18n_key)

        for section in self.sections:
            section.translate(i18n_key)


class ConfigPanelModel(BaseModel):
    version: float = CONFIG_PANEL_VERSION_SUPPORTED
    i18n: Union[str, None] = None
    panels: list[PanelModel]

    class Config:
        arbitrary_types_allowed = True
        extra = Extra.allow

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        version: float,
        i18n: Union[str, None] = None,
        **kwargs,
    ) -> None:
        panels = [data | {"id": name} for name, data in kwargs.items()]
        super().__init__(version=version, i18n=i18n, panels=panels)

    @property
    def sections(self):
        """Convinient prop to iter on all sections"""
        for panel in self.panels:
            for section in panel.sections:
                yield section

    @property
    def options(self):
        """Convinient prop to iter on all options"""
        for section in self.sections:
            for option in section.options:
                yield option

    def get_option(self, option_id) -> Union[AnyOption, None]:
        for option in self.options:
            if option.id == option_id:
                return option
        # FIXME raise error?
        return None

    @property
    def services(self) -> list[str]:
        services = set()
        for panel in self.panels:
            services |= set(panel.services)
            for section in panel.sections:
                services |= set(section.services)

        services_ = list(services)
        services_.sort(key="nginx".__eq__)
        return services_

    def iter_children(
        self,
        trigger: list[Literal["panel", "section", "option", "action"]] = ["option"],
    ):
        for panel in self.panels:
            if "panel" in trigger:
                yield (panel, None, None)
            for section in panel.sections:
                if "section" in trigger:
                    yield (panel, section, None)
                if "action" in trigger:
                    for option in section.options:
                        if option.type is OptionType.button:
                            yield (panel, section, option)
                if "option" in trigger:
                    for option in section.options:
                        yield (panel, section, option)

    def translate(self):
        """
        Recursivly mutate translatable attributes to their translation
        """
        for panel in self.panels:
            panel.translate(self.i18n)

    @validator("version", always=True)
    def check_version(cls, value, field: "ModelField"):
        if value < CONFIG_PANEL_VERSION_SUPPORTED:
            raise ValueError(
                f"Config panels version '{value}' are no longer supported."
            )

        return value


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╴╭─╮╭╮╷┌─╴╶┬╴╭─╮   ╶┬╴╭╮╮┌─╮╷                      │
# │  │  │ ││││├─╴ │ │╶╮    │ │││├─╯│                      │
# │  ╰─╴╰─╯╵╰╯╵  ╶┴╴╰─╯   ╶┴╴╵╵╵╵  ╰─╴                    │
# ╰───────────────────────────────────────────────────────╯

if TYPE_CHECKING:
    FilterKey = Sequence[Union[str, None]]
    RawConfig = OrderedDict[str, Any]
    RawSettings = dict[str, Any]
    ConfigPanelGetMode = Literal["classic", "full", "export"]


def parse_filter_key(key: Union[str, None] = None) -> "FilterKey":
    if key and key.count(".") > 2:
        raise YunohostError(
            f"The filter key {key} has too many sub-levels, the max is 3.",
            raw_msg=True,
        )

    if not key:
        return (None, None, None)
    keys = key.split(".")
    return tuple(keys[i] if len(keys) > i else None for i in range(3))


class ConfigPanel:
    entity_type = "config"
    save_path_tpl: Union[str, None] = None
    config_path_tpl = "/usr/share/yunohost/config_{entity_type}.toml"
    save_mode = "full"
    filter_key: "FilterKey" = (None, None, None)
    config: Union[ConfigPanelModel, None] = None
    form: Union["FormModel", None] = None
    hooks: "Hooks" = {}

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

    def get(
        self, key: Union[str, None] = None, mode: "ConfigPanelGetMode" = "classic"
    ) -> Any:
        self.filter_key = parse_filter_key(key)
        self.config, self.form = self._get_config_panel(prevalidate=False)

        panel_id, section_id, option_id = self.filter_key

        # In 'classic' mode, we display the current value if key refer to an option
        if option_id and mode == "classic":
            option = self.config.get_option(option_id)

            if option is None:
                # FIXME i18n
                raise YunohostValidationError(
                    f"Couldn't find any option with id {option_id}"
                )

            if isinstance(option, BaseReadonlyOption):
                return None

            return self.form[option_id]

        # Format result in 'classic' or 'export' mode
        self.config.translate()
        logger.debug(f"Formating result in '{mode}' mode")
        result = OrderedDict()
        for panel in self.config.panels:
            for section in panel.sections:
                if section.is_action_section and mode != "full":
                    continue

                for option in section.options:
                    if mode == "export":
                        if isinstance(option, BaseInputOption):
                            result[option.id] = self.form[option.id]
                        continue

                    if mode == "classic":
                        key = f"{panel.id}.{section.id}.{option.id}"
                        result[key] = {"ask": option.ask}

                        if isinstance(option, BaseInputOption):
                            result[key]["value"] = option.humanize(
                                self.form[option.id], option
                            )
                            if option.type is OptionType.password:
                                result[key][
                                    "value"
                                ] = "**************"  # Prevent displaying password in `config get`

        if mode == "full":
            return self.config.dict(exclude_none=True)
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
        if option_id and value is not None:
            self.args = {option_id: value}
        else:
            self.args = parse_prefilled_values(args, value, args_file)

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
        self.args = parse_prefilled_values(args, args_file)

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

    def _get_raw_config(self) -> "RawConfig":
        if not os.path.exists(self.config_path):
            raise YunohostValidationError("config_no_panel")

        return read_toml(self.config_path)

    def _get_raw_settings(self, config: ConfigPanelModel) -> "RawSettings":
        if not self.save_path or not os.path.exists(self.save_path):
            raise YunohostValidationError("config_no_settings")

        return read_yaml(self.save_path)

    def _get_partial_raw_config(self) -> "RawConfig":
        def filter_keys(
            data: "RawConfig",
            key: str,
            model: Union[Type[ConfigPanelModel], Type[PanelModel], Type[SectionModel]],
        ) -> "RawConfig":
            # filter in keys defined in model, filter out panels/sections/options that aren't `key`
            return OrderedDict(
                {k: v for k, v in data.items() if k in model.__fields__ or k == key}
            )

        raw_config = self._get_raw_config()

        panel_id, section_id, option_id = self.filter_key
        if panel_id:
            raw_config = filter_keys(raw_config, panel_id, ConfigPanelModel)

            if section_id:
                raw_config[panel_id] = filter_keys(
                    raw_config[panel_id], section_id, PanelModel
                )

                if option_id:
                    raw_config[panel_id][section_id] = filter_keys(
                        raw_config[panel_id][section_id], option_id, SectionModel
                    )

        return raw_config

    def _get_partial_raw_settings_and_mutate_config(
        self, config: ConfigPanelModel
    ) -> tuple[ConfigPanelModel, "RawSettings"]:
        raw_settings = self._get_raw_settings(config)
        values = {}

        for _, section, option in config.iter_children():
            value = data = raw_settings.get(option.id, getattr(option, "default", None))

            if isinstance(data, dict):
                # Settings data if gathered from bash "ynh_app_config_show"
                # may be a custom getter that returns a dict with `value` or `current_value`
                # and other attributes meant to override those of the option.

                if "value" in data:
                    value = data.pop("value")

                # Allow to use value instead of current_value in app config script.
                # e.g. apps may write `echo 'value: "foobar"'` in the config file (which is more intuitive that `echo 'current_value: "foobar"'`
                # For example hotspot used it...
                # See https://github.com/YunoHost/yunohost/pull/1546
                # FIXME do we still need the `current_value`?
                if "current_value" in data:
                    value = data.pop("current_value")

                # Mutate other possible option attributes
                for k, v in data.items():
                    setattr(option, k, v)

            if isinstance(option, BaseInputOption):  # or option.bind == "null":
                values[option.id] = value

        return (config, values)

    def _get_config_panel(
        self, prevalidate: bool = False
    ) -> tuple[ConfigPanelModel, "FormModel"]:
        raw_config = self._get_partial_raw_config()
        config = ConfigPanelModel(**raw_config)
        config, raw_settings = self._get_partial_raw_settings_and_mutate_config(config)
        config.translate()
        Settings = build_form(config.options)
        settings = (
            Settings(**raw_settings)
            if prevalidate
            else Settings.construct(**raw_settings)
        )

        try:
            config.panels[0].sections[0].options[0]
        except (KeyError, IndexError):
            raise YunohostValidationError(
                "config_unknown_filter_key", filter_key=self.filter_key
            )

        return (config, settings)

    def ask(
        self,
        config: ConfigPanelModel,
        settings: "FormModel",
        prefilled_answers: dict[str, Any] = {},
        action_id: Union[str, None] = None,
        hooks: "Hooks" = {},
    ) -> "FormModel":
        # FIXME could be turned into a staticmethod
        logger.debug("Ask unanswered question and prevalidate data")

        interactive = Moulinette.interface.type == "cli" and os.isatty(1)

        if interactive:
            config.translate()

        for panel in config.panels:
            if interactive:
                Moulinette.display(
                    colorize(f"\n{'='*40}\n>>>> {panel.name}\n{'='*40}", "purple")
                )

            # A section or option may only evaluate its conditions (`visible`
            # and `enabled`) with its panel's local context that is built
            # prompt after prompt.
            # That means that a condition can only reference options of its
            # own panel and options that are previously defined.
            context: dict[str, Any] = {}

            for section in panel.sections:
                if (
                    action_id is None and section.is_action_section
                ) or not section.is_visible(context):
                    # FIXME useless?
                    Moulinette.display("Skipping section '{panel.id}.{section.id}'…")
                    continue

                if interactive and section.name:
                    Moulinette.display(colorize(f"\n# {section.name}", "purple"))

                # filter action section options in case of multiple buttons
                options = [
                    option
                    for option in section.options
                    if option.type is not OptionType.button or option.id == action_id
                ]

                settings = prompt_or_validate_form(
                    options,
                    settings,
                    prefilled_answers=prefilled_answers,
                    context=context,
                    hooks=hooks,
                )

<<<<<<< HEAD
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
=======
        return settings
>>>>>>> be777b928 (configpanel: update _ask)

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

        services_to_reload = self.config.services

        if services_to_reload:
            logger.info("Reloading services...")
        for service in services_to_reload:
            if hasattr(self, "entity"):
                service = service.replace("__APP__", self.entity)
            service_reload_or_restart(service)
