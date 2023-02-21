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

import contextlib
import os
import re
from typing import TYPE_CHECKING, Type, Any, Literal, OrderedDict, Sequence, Union

import pydantic
from packaging.version import Version
from pydantic import BaseModel, validator
from pydantic.fields import ModelField

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import mkdir, read_toml, read_yaml, write_to_yaml
from moulinette.utils.log import getActionLogger
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.form import (
    BaseInputOption,
    ButtonOption,
    OptionType,
    OptionsContainer,
    Translation,
    build_form,
    evaluate_simple_js_expression,
    fill_form,
    parse_prefilled_values,
    prompt_form,
)
from yunohost.utils.i18n import _value_for_locale

if TYPE_CHECKING:
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny
    from yunohost.utils.form import YunoForm


logger = getActionLogger("yunohost.config")

# ╭───────────────────────────────────────────────────────╮
# │  ╭╮╮╭─╮┌─╮┌─╴╷  ╭─╴                                   │
# │  ││││ ││ │├─╴│  ╰─╮                                   │
# │  ╵╵╵╰─╯└─╯╰─╴╰─╴╶─╯                                   │
# ╰───────────────────────────────────────────────────────╯
CONFIG_PANEL_VERSION_SUPPORTED = "1.0"


class Container(BaseModel):
    id: str
    name: Union[str, None] = None
    services: list[str] = []
    help: Translation = None

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


class Section(Container, OptionsContainer):
    visible: Union[bool, str] = True
    # optional: bool = True
    # options: list[Annotated[AnyOption, Field(discriminator="type")]]

    @property
    def is_action_section(self):
        return any([option.type is OptionType.button for option in self.options])

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        id: str,
        name: Union[str, None] = None,
        services: list[str] = [],
        help: Translation = None,
        visible: Union[bool, str] = True,
        **kwargs,
    ) -> None:
        # Looks like this allow to use Container init while still matching
        # "options" of OptionsContainer
        options = self.options_dict_to_list(kwargs, defaults={"optional": True})

        Container.__init__(
            self,
            id=id,
            name=name,
            services=services,
            help=help,
            visible=visible,
            options=options,
        )

    def is_visible(self, context: dict[str, Any]):
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    def translate(self, i18n_key: Union[str, None] = None):
        """
        Call to `Container`'s `translate` for self translation
        + Call to `OptionsContainer`'s `translate_options` for options translation
        """
        super().translate(i18n_key)  #
        self.translate_options(i18n_key)  #


class Panel(Container):
    # actions: dict[str, Translation] = {"apply": {"en": "Apply"}}
    sections: list[Section]

    class Config:
        extra = pydantic.Extra.allow

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        id: str,
        name: Union[str, None] = None,
        services: list[str] = [],
        help: Translation = None,
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


class ConfigPanel(BaseModel):
    version: str = "1.0"
    i18n: Union[str, None] = None
    panels: list[Panel]

    class Config:
        arbitrary_types_allowed = True
        extra = pydantic.Extra.allow

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        version: Version,
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
                        if isinstance(option, ButtonOption):
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

    @validator("version", pre=True, always=True)
    def parse_as_version(cls, v, field: ModelField):
        if not isinstance(v, Version):
            try:
                v = Version(v)
            except:
                raise ValueError(f"Wrong version format: {v}")

        if v < Version(CONFIG_PANEL_VERSION_SUPPORTED):
            raise ValueError(f"Config panels version '{v}' are no longer supported.")

        return str(v)


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╴╭─╮╭╮╷┌─╴╶┬╴╭─╮   ╶┬╴╭╮╮┌─╮╷                      │
# │  │  │ ││││├─╴ │ │╶╮    │ │││├─╯│                      │
# │  ╰─╴╰─╯╵╰╯╵  ╶┴╴╰─╯   ╶┴╴╵╵╵╵  ╰─╴                    │
# ╰───────────────────────────────────────────────────────╯


class Config:
    entity_type = "config"
    base_path: str = "/usr/share/yunohost"
    save_path_tpl: Union[str, None] = None
    config_path_tpl: str = "config_{entity_type}.toml"
    save_mode = "full"

    def __init__(
        self,
        entity: str,
        config_path: Union[str, None] = None,
        save_path: Union[str, None] = None,
        creation: bool = False,
    ):
        self.entity = entity

        self.config_path = config_path or os.path.join(
            self.base_path,
            self.config_path_tpl.format(entity=entity, entity_type=self.entity_type),
        )

        self.save_path = save_path
        if not save_path and self.save_path_tpl:
            self.save_path = os.path.join(
                self.base_path, self.save_path_tpl.format(entity=entity)
            )

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

    @staticmethod
    @contextlib.contextmanager
    def _try_apply_or_run(error: str, action_id: Union[str, None] = None):
        try:
            yield
        except YunohostError:
            raise
        # Script got manually interrupted ...
        # N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            logger.error(
                m18n.n(error, action=action_id, error=m18n.n("operation_interrupted"))
            )
            raise
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            logger.error(
                m18n.n(
                    error,
                    action=action_id,
                    error=m18n.n(
                        "unexpected_error", error="\n" + traceback.format_exc()
                    ),
                )
            )
            raise
        finally:
            # Delete files uploaded from API
            # FIXME : this is currently done in the context of config panels,
            # but could also happen in the context of app install ... (or anywhere else
            # where we may parse args etc...)
            # FileQuestion.clean_upload_dirs()
            # FIXME deal with uploaded file
            print("FILES TO RM")

    def _get_config_data(
        self,
        panel_id: Union[str, None] = None,
        section_id: Union[str, None] = None,
        option_id: Union[str, None] = None,
    ) -> dict[str, Any]:
        if not os.path.exists(self.config_path):
            raise YunohostValidationError("config_no_panel")
            # f"Config panel {self.config_path} doesn't exists"

        return read_toml(self.config_path)

    def _get_settings_data(self, config: "ConfigPanel") -> dict[str, Any]:
        if not self.save_path or not os.path.exists(self.save_path):
            raise YunohostValidationError("config_no_settings")
            # f"Config panel {self.config_path} doesn't exists"

        return read_yaml(self.save_path)

    def _get_partial_config_data(
        self,
        panel_id: Union[str, None] = None,
        section_id: Union[str, None] = None,
        option_id: Union[str, None] = None,
    ) -> dict[str, Any]:
        def filter_keys(
            data: dict[str, Any],
            key: str,
            model: Union[Type[ConfigPanel], Type[Panel], Type[Section]],
        ) -> dict[str, Any]:
            # filter in keys defined in model, filter out panels/sections/options that aren't `key`
            return {k: v for k, v in data.items() if k in model.__fields__ or k == key}

        config_data = self._get_config_data(panel_id, section_id, option_id)

        if panel_id:
            config_data = filter_keys(config_data, panel_id, ConfigPanel)

            if section_id:
                config_data[panel_id] = filter_keys(
                    config_data[panel_id], section_id, Panel
                )

                if option_id:
                    config_data[panel_id][section_id] = filter_keys(
                        config_data[panel_id][section_id], option_id, Section
                    )

        return config_data

    def _get_partial_settings_data_and_mutate_config(
        self, config: ConfigPanel
    ) -> tuple[ConfigPanel, dict[str, Any]]:
        settings_data = self._get_settings_data(config)
        values = {}

        for option in config.options:
            value = data = settings_data.get(
                option.id, getattr(option, "default", None)
            )

            if isinstance(data, dict):
                # Settings data if gathered from bash "ynh_app_config_show"
                # may be a custom getter that returns a dict with `value` or `current_value`
                # and other attributes meant to override those of the option.

                if "value" in data:
                    value = data.pop("value")

                # FIXME do we still need the `current_value`?
                if "current_value" in data:
                    value = data.pop("current_value")

                # Mutate other possible option attributes
                for k, v in data.items():
                    setattr(option, k, v)

            if isinstance(option, BaseInputOption):  # or option.bind == "null":
                values[option.id] = value

        return (config, values)

    def _get_config_and_settings(
        self, panel_id, section_id, option_id, prevalidate: bool = False
    ) -> tuple[ConfigPanel, "YunoForm"]:
        config_data = self._get_partial_config_data(panel_id, section_id, option_id)
        config = ConfigPanel(**config_data)
        config, settings_data = self._get_partial_settings_data_and_mutate_config(
            config
        )
        config.translate()
        Settings = build_form(config.options)
        # FIXME will probably have problems with required stuff if not filled on install
        # Probably need to not parse & validate data at instantiation
        # settings = Settings(**settings_data)
        settings = (
            Settings(**settings_data)
            if prevalidate
            else Settings.construct(**settings_data)
        )

        return (config, settings)

    def _get_keys(self, key: Union[str, None] = None) -> Sequence[Union[str, None]]:
        if key and key.count(".") > 2:
            raise YunohostError(
                f"The filter key {key} has too many sub-levels, the max is 3.",
                raw_msg=True,
            )

        if not key:
            return (None, None, None)
        keys = key.split(".")
        return tuple(keys[i] if len(keys) > i else None for i in range(3))

    def get(
        self,
        key: Union[str, None] = None,
        mode: Literal["classic", "full", "export"] = "classic",
    ):
        panel_id, section_id, option_id = self._get_keys(key)

        config, settings = self._get_config_and_settings(
            panel_id, section_id, option_id
        )

        if mode == "classic" and option_id:
            return settings.normalize(option_id)

        result = config.dict() if mode == "full" else OrderedDict()

        if mode == "full":
            result["version"] = str(result["version"])

        for p, panel in enumerate(config.panels):
            for s, section in enumerate(panel.sections):
                for o, option in enumerate(section.options):
                    if mode == "classic":
                        key = ".".join((panel.id, section.id, option.id))
                        result[key] = {"ask": option.ask}
                        if isinstance(option, BaseInputOption):
                            result[key]["value"] = settings.normalize(option.id)
                    elif isinstance(option, BaseInputOption):
                        value = settings.normalize(option.id)
                        if mode == "export":
                            result[option.id] = value
                        elif mode == "full":
                            result["panels"][p]["sections"][s]["options"][o][
                                "value"
                            ] = value

        return result

    def _save(self, values: dict[str, Any]):
        logger.info("Saving the new configuration...")

        if not self.save_path:
            raise YunohostError("Couln't save settings, save path is not defined")

        dir_path = os.path.dirname(os.path.realpath(self.save_path))
        if not os.path.exists(dir_path):
            mkdir(dir_path, mode=0o700)

        write_to_yaml(self.save_path, values)

    def _apply(
        self,
        settings: "YunoForm",
        exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
    ):
        """
        Save settings in yaml file.
        If `save_mode` is `"diff"` (which is the default), only values that are
        different from their default value will be saved.
        """
        logger.info("Saving the new configuration...")

        if not self.save_path:
            raise YunohostError("Couln't save settings, save path is not defined")

        exclude_defaults = self.save_mode == "diff"
        values = settings.dict(exclude_defaults=exclude_defaults, exclude=exclude)

        dir_path = os.path.dirname(os.path.realpath(self.save_path))
        if not os.path.exists(dir_path):
            mkdir(dir_path, mode=0o700)

        write_to_yaml(self.save_path, values)

        return values

    def _reload_services(self, config: ConfigPanel):
        from yunohost.service import service_reload_or_restart

        if config.services:
            logger.info("Reloading services...")
            for service in config.services:
                if hasattr(self, "entity"):
                    service = service.replace("__APP__", self.entity)
                service_reload_or_restart(service)

    def set(
        self,
        key: Union[str, None] = None,
        value: Any = None,
        args: Union[str, None] = None,
        args_file=None,
        operation_logger=None,
    ):
        panel_id, section_id, option_id = self._get_keys(key)

        if option_id is None and value is not None:
            raise YunohostValidationError("config_cant_set_value_on_section")

        settings_args = parse_prefilled_values(args, args_file)
        if settings_args and value is not None:
            raise YunohostValidationError(
                "You should either provide a value, or a serie of args/args_file, but not both at the same time",
                raw_msg=True,
            )
        elif option_id and value is not None:
            settings_args = {option_id: value}

        # Do not prevalidate current settings else required values without
        # default will raise a validation error before being able to ask it
        config, settings = self._get_config_and_settings(
            panel_id, section_id, option_id, prevalidate=False
        )

        # Clear fields set when created
        settings.__fields_set__.clear()
        # FIXME check len(__fields__) > len(settings_args) to choose if prompt or fill in cli
        if Moulinette.interface.type == "cli" and os.isatty(1):
            settings = prompt_config(config, settings, prefilled_answers=settings_args)
        else:
            settings = fill_config(config, settings, settings_args)

        # Validate settings to parse everything back to python types?
        # settings = settings.validate(settings.dict())

        if operation_logger:
            operation_logger.start()

        # i18n: config_apply_failed
        with self._try_apply_or_run("config_apply_failed"):
            self._apply(settings)

        self._reload_services(config)

        logger.success("Config updated as expected")
        operation_logger.success()
        return settings.dict()

    def list_actions(self):
        config = ConfigPanel(**self._get_config_data())

        return {
            f"{panel.id}.{section.id}.{action.id}": action.ask
            for panel, section, action in config.iter_children(trigger=["action"])
        }

    def _run_action(self, action_id: str, settings: "YunoForm"):
        raise NotImplementedError()

    def run_action(
        self,
        key: str,
        args: Union[str, None] = None,
        args_file=None,
        operation_logger=None,
    ):
        panel_id, section_id, action_id = self._get_keys(key)

        if not action_id or not all([panel_id, section_id, action_id]):
            raise YunohostValidationError(
                "Please provide a full action key like 'panel.section.action'",
                raw_msg=True,
            )

        # Get entire section since some data may be required for the action to run
        config, settings = self._get_config_and_settings(
            panel_id, section_id, None, prevalidate=False
        )

        if not any(option.id == action_id for option in config.options):
            raise YunohostValidationError(
                f"No action named '{action_id}'", raw_msg=True
            )

        settings_args = parse_prefilled_values(args, args_file)

        if Moulinette.interface.type == "cli" and os.isatty(1):
            settings = prompt_config(
                config, settings, settings_args, action_id=action_id
            )
        else:
            settings = fill_config(config, settings, settings_args, action_id=action_id)

        if operation_logger:
            operation_logger.start()

        # i18n: config_action_failed
        with self._try_apply_or_run("config_action_failed", action_id):
            self._run_action(action_id, settings)

        # FIXME: i18n
        logger.success(f"Action {action_id} successful")
        operation_logger.success()


def fill_config(
    config: ConfigPanel,
    settings: "YunoForm",
    prefilled_answers: dict[str, Any],
    action_id: Union[str, None] = None,
) -> "YunoForm":
    """
    API only method to validate form passed as query string.
    Most checks should be handled by the webadmin but we recheck in case of direct call to API or webadmin missing stuff.
    """
    logger.debug("Validating settings...")

    context: dict[str, Any] = {}
    for section in config.sections:
        if (action_id is None and section.is_action_section) or not section.is_visible(
            context
        ):
            skipped_options = [
                option.id
                for option in section.options
                if option.id in prefilled_answers
            ]
            if skipped_options:
                logger.warning(
                    f"Skipping settings: '{skipped_options}' since conditions are not fullfilled."
                )
            continue

        settings = fill_form(
            section.options,
            settings,
            prefilled_answers,
            context=context,
            action_id=action_id,
        )

    return settings


def prompt_config(
    config: ConfigPanel,
    settings: "YunoForm",
    prefilled_answers: dict[str, Any],
    action_id: Union[str, None] = None,
) -> "YunoForm":
    """
    CLI only method to interactively prompt the config form
    """
    logger.debug("Ask unanswered question and prevalidate data")

    for panel in config.panels:
        # A section or option may only evaluate its conditions (`visible`
        # and `enabled`) with its panel's local context that is built
        # prompt after prompt.
        # That means that a condition can only reference options of its
        # own panel and options that are previously defined.
        context: dict[str, Any] = {}
        Moulinette.display(
            colorize(f"\n{'='*40}\n>>>> {panel.name}\n{'='*40}", "purple")
        )

        for section in panel.sections:
            if (
                action_id is None and section.is_action_section
            ) or not section.is_visible(context):
                # FIXME useless?
                Moulinette.display("Skipping section '{panel.id}.{section.id}'…")
                continue

            if section.name:
                Moulinette.display(colorize(f"\n# {section.name}", "purple"))

            settings = prompt_form(
                section.options,
                settings,
                prefilled_answers,
                context=context,
                action_id=action_id,
            )

    return settings

