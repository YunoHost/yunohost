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
import re
import urllib
from enum import Enum
from pathlib import Path
from types import new_class
from typing import Annotated, Any, Literal, Type, TypeVar, Union, get_args, cast

import pydantic
from pydantic import BaseModel, root_validator, validator
from pydantic.fields import Field, FieldInfo

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import read_yaml
from moulinette.utils.log import getActionLogger
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.i18n import _value_for_locale

# Use a more generic logger name?
logger = getActionLogger("yunohost.config")


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╴╷ ╷╭─╴╶┬╴╭─╮╭╮╮   ╶┬╴╷ ╷┌─╮┌─╴╭─╴                 │
# │  │  │ │╰─╮ │ │ ││││    │ ╰─┤├─╯├─╴╰─╮                 │
# │  ╰─╴╰─╯╶─╯ ╵ ╰─╯╵╵╵    ╵ ╶─╯╵  ╰─╴╶─╯                 │
# ╰───────────────────────────────────────────────────────╯

T = TypeVar("T")


class ConstrainedComaList(pydantic.ConstrainedList[T]):  # type: ignore
    """
    Special type to handle bash style list parsing
    """

    @classmethod
    def __get_validators__(cls):
        # First parse possible bash style list `"item,item"` -> `["item", "item"]`
        yield cls.parse_bash_style_list
        # yield pydantic validators (parsing items to given `item_type`, regex validations, etc.)
        yield from super().__get_validators__()

    @classmethod
    def parse_bash_style_list(
        cls, v: Union[list[T], str, None]
    ) -> Union[list[T], list[str], None]:
        if v is None or v == "":
            # FIXME parse `""` as `[]` instead?
            return None

        if isinstance(v, str):
            values = [value.strip() for value in v.split(",")]
            return [value for value in values if value]

        return v


def concomalist(
    item_type: Type[T],
    *,
    min_items: Union[int, None] = None,
    max_items: Union[int, None] = None,
    unique_items: Union[bool, None] = None,
) -> Type[list[T]]:
    """
    Special factory (copypasta of pydantic.conlist) to create a constrained
    list class that handle our custom bash style list parsing.
    """
    # __args__ is needed to conform to typing generics api
    namespace = dict(
        min_items=min_items,
        max_items=max_items,
        unique_items=unique_items,
        item_type=item_type,
        __args__=(item_type,),
    )
    # We use new_class to be able to deal with Generic types
    return new_class(
        "ConstrainedComaListValue",
        (ConstrainedComaList,),
        {},
        lambda ns: ns.update(namespace),
    )


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
    # choice
    select = "select"
    tags = "tags"
    # file
    file = "file"
    # entity
    app = "app"
    domain = "domain"
    user = "user"
    group = "group"


Translation = Union[dict[str, str], str, None]
Style = Literal["success", "info", "warning", "danger"]


class Pattern(BaseModel):
    regexp: str
    error: Translation = "error_pattern"


def enum_to_cls(enum_value: OptionType):
    """
    Return the corresponding: option type enum value -> class definition
    """
    # FIXME probably better way to get type class
    _, types = pydantic.utils.get_discriminator_alias_and_values(
        AnyOption, discriminator_key="type"
    )
    return get_args(AnyOption)[types.index(OptionType[enum_value])]


class BaseOption(BaseModel):
    """
    BaseOption is the base model for any config panel or manifest install
    dynamic form 'option'.
    Any parsing or validation defined on this model or subclasses are to
    validate and interprete what devs/packagers writes, not what a user could
    provide for this option.

    The parsing/validation of user inputs are built upon options as another
    dynamic model created by `build_form`.
    """

    type: OptionType
    ask: Translation
    name: Union[str, None] = None  # FIXME name or id?
    id: str
    bind: Union[str, None] = None
    readonly: bool = False
    visible: Union[str, bool] = True

    class Config:
        arbitrary_types_allowed = True
        use_enum_values = True
        validate_assignment = True

        @staticmethod
        def schema_extra(schema: dict[str, Any], model: type["BaseOption"]) -> None:
            # FIXME Do proper doctstring for Options
            del schema["description"]
            schema["additionalProperties"] = False

    def is_visible(self, context: dict[str, Any]):
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    @root_validator(pre=True)
    def warn_unsupported_keys(cls, values):
        extras = set(values.keys()) - set(cls.__fields__.keys())
        if extras:
            for extra in extras:
                logger.warning(
                    f"Unknown key '{extra}' found in option '{values['id']}'"
                )
        return values

    @validator("id")
    def validate_id(cls, v, values):
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

        if v in forbidden_keywords:
            raise YunohostError("config_forbidden_keyword", keyword=values["id"])

        return v

    @validator("readonly")
    def allowed_as_readonly(cls, v, values):
        forbidden_readonly_types = [
            OptionType.password,
            # FIXME not sure why those are not allowed but maybe I misunderstood what `readonly` originally means.
            OptionType.file,
            OptionType.app,
            OptionType.domain,
            OptionType.user,
            OptionType.group,
        ]

        if v and values["type"] in forbidden_readonly_types:
            raise YunohostError(
                "config_forbidden_readonly_type",
                type=values["type"],
                id=values["id"],
            )

        return v


# ╭───────────────────────────────────────────────────────╮
# │ DISPLAY OPTIONS                                       │
# ╰───────────────────────────────────────────────────────╯


class BaseReadonlyOption(BaseOption):
    _type = str
    readonly: bool = True

    @validator("readonly")
    def force(cls, v):
        if v is False:
            logger.warning(
                "Packagers: `readonly` can't be `False` for option of type `{cls.type}`, forcing to `True`"
            )
        return True


class DisplayTextOption(BaseReadonlyOption):
    type: Literal[OptionType.display_text]


class MarkdownOption(BaseReadonlyOption):
    type: Literal[OptionType.markdown]


class BaseStyledReadonlyOption(BaseReadonlyOption):
    style: Union[Style, None] = None
    icon: Union[str, None] = None


class AlertOption(BaseStyledReadonlyOption):
    type: Literal[OptionType.alert]
    style: Style = "info"


class ButtonOption(BaseStyledReadonlyOption):
    type: Literal[OptionType.button]
    style: Style = "success"
    enabled: Union[str, bool] = True
    # confirm: bool = False  # TODO: to ask confirmation before running an action

    def is_enabled(self, context: dict[str, Any]):
        if isinstance(self.enabled, bool):
            return self.enabled

        return evaluate_simple_js_expression(self.enabled, context=context)


# ╭───────────────────────────────────────────────────────╮
# │ INPUT OPTIONS                                         │
# ╰───────────────────────────────────────────────────────╯
InputOptions = Literal[
    OptionType.string,
    OptionType.text,
    OptionType.color,
    OptionType.password,
    OptionType.number,
    OptionType.range,
    OptionType.boolean,
    OptionType.date,
    OptionType.time,
    OptionType.email,
    OptionType.path,
    OptionType.url,
    OptionType.select,
    OptionType.tags,
    OptionType.file,
    OptionType.app,
    OptionType.domain,
    OptionType.user,
    OptionType.group,
]


class BaseInputOption(BaseOption):
    _anno: Any
    pattern: Union[Pattern, None] = None
    limit: Union[int, None] = None  # FIXME move
    optional: bool = False  # FIXME keep required as default?
    placeholder: Union[str, None] = None
    help: Translation = None
    example: Union[str, None] = None
    redact: bool = False
    default: Any

    @property
    def _dynamic_annotation(self):
        return self._anno

    def get_field_attrs(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {}

        if self.readonly:
            attrs["allow_mutation"] = False

        if self.example:
            attrs["examples"] = [self.example]

        if self.default is not None:
            attrs["default"] = self.default
        elif not self.optional:
            attrs["default"] = ...
        else:
            attrs["default"] = None

        return attrs

    def as_dynamic_model_field(
        self,
    ) -> tuple[Union[object, Any], FieldInfo]:
        attrs = self.get_field_attrs()
        anno = (
            self._dynamic_annotation
            if not self.optional
            else Union[self._dynamic_annotation, None]
        )
        field = Field(default=attrs.pop("default", None), **attrs)

        return (anno, field)

    @validator("readonly", pre=True)
    def can_be_readonly(cls, v, values):
        forbidden_types = ("password", "app", "domain", "user", "file")
        if v is True and values["type"] in forbidden_types:
            raise ValueError(
                m18n.n(
                    "config_forbidden_readonly_type",
                    type=values["type"],
                    id=values["id"],
                )
            )
        return v


# ─ STRINGS ───────────────────────────────────────────────


class BaseStringOption(BaseInputOption):
    _anno = str
    default: Union[str, None] = ""

    @property
    def _dynamic_annotation(self):
        if self.pattern:
            return pydantic.constr(regex=self.pattern.regexp)
        return self._anno

    def get_field_attrs(self):
        attrs = super().get_field_attrs()
        if self.pattern:
            attrs["regex_error"] = self.pattern.error  # Extra
        return attrs


class StringOption(BaseStringOption):
    type: Literal[OptionType.string]


class TextOption(BaseStringOption):
    type: Literal[OptionType.text]


class PasswordOption(BaseInputOption):
    type: Literal[OptionType.password]
    _anno = pydantic.SecretStr
    default: None = None
    redact: bool = True
    # Unique
    forbidden_chars: str = "{}"  # FIXME add custom validator

    @root_validator(pre=True)
    def force(cls, values):
        values["default"] = None
        values["redact"] = True
        return values


class ColorOption(BaseInputOption):
    type: Literal[OptionType.color]
    _anno = pydantic.color.Color
    default: Union[pydantic.color.Color, None]


# ─ NUMERIC ───────────────────────────────────────────────


class BaseNumberOption(BaseInputOption):
    _anno = Union[int, float]
    default: Union[int, float, None]

    min: Union[int, None] = None
    max: Union[int, None] = None
    step: Union[int, None] = None

    def get_field_attrs(self):
        attrs = super().get_field_attrs()
        attrs["ge"] = self.min
        attrs["le"] = self.max
        attrs["step"] = self.step  # Extra

        return attrs


class NumberOption(BaseNumberOption):
    type: Literal[OptionType.number]


class RangeOption(BaseNumberOption):
    type: Literal[OptionType.range]


# ─ BOOLEAN ───────────────────────────────────────────────


class BooleanOption(BaseInputOption):
    type: Literal[OptionType.boolean]
    _anno = bool
    default: Union[bool, None] = False
    yes: Any = "1"
    no: Any = "0"
    _possible_cli_yes: set[str] = {"0", "no", "n", "false", "f", "off"}
    _possible_cli_no: set[str] = {"0", "no", "n", "false", "f", "off"}

    def get_field_attrs(self):
        attrs = super().get_field_attrs()
        attrs["parse"] = {  # Extra
            "yes": self.yes,
            "no": self.no,
            # "possible_yes": self._possible_cli_yes,
            # "possible_no": self._possible_cli_no,
        }
        return attrs

    @validator("yes", pre=True)
    def yes_is_not_falsy_value(cls, v):
        if str(v).lower() in cls._possible_cli_no:
            raise ValueError(f"'yes' value can't be in {cls._possible_cli_no}")
        return v

    @validator("no", pre=True)
    def no_is_not_truthy_value(cls, v):
        if str(v).lower() in cls._possible_cli_yes:
            raise ValueError(f"'no' value can't be in {cls._possible_cli_yes}")
        return v


# ─ TIME ──────────────────────────────────────────────────
class DateOption(BaseInputOption):
    type: Literal[OptionType.date]
    _anno = datetime.date
    default: Union[datetime.date, None]


class TimeOption(BaseInputOption):
    type: Literal[OptionType.time]
    _anno = datetime.time
    default: Union[datetime.time, None]


# ─ LOCATIONS ─────────────────────────────────────────────


class EmailOption(BaseInputOption):
    type: Literal[OptionType.email]
    _anno = pydantic.EmailStr
    default: Union[pydantic.EmailStr, None]


class PathOption(BaseInputOption):
    type: Literal[OptionType.path]
    _anno = Path
    default: Union[Path, None]


class UrlOption(BaseInputOption):
    type: Literal[OptionType.url]
    _anno = pydantic.HttpUrl
    default: Union[pydantic.HttpUrl, None]


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
    # OptionType.file,
    # OptionType.app,
    # OptionType.domain,
    # OptionType.user,
    # OptionType.group,
]


class BaseChoicesOption(BaseInputOption):
    _anno = Any
    item_type: ChoosableOptions = OptionType.string
    choices: Union[dict[str, Any], list[Any], None]
    default: Any = None

    @property
    def _dynamic_annotation(self):
        annotation = enum_to_cls(self.item_type)._anno
        # Repeat pattern stuff since we can't call the bare class `_dynamic_annotation` prop without instantiating it
        if annotation is str and self.pattern:
            annotation = pydantic.constr(regex=self.pattern.regexp)

        if self.choices is not None:
            choices = (
                self.choices if isinstance(self.choices, list) else self.choices.keys()
            )
            annotation = Literal[tuple(choices)]

        return annotation

    @root_validator()
    def validate_default_in_choices(cls, values):
        default = values.get("default", None)
        choices = values.get("choices", None)

        if not default or not choices:
            return values

        choices = choices.keys() if isinstance(choices, dict) else choices

        if default not in choices:
            raise ValueError(f"default value '{default}' is not a valid choice.")

        return values


class SelectOption(BaseChoicesOption):
    type: Literal[OptionType.select]
    choices: Union[dict[str, Any], list[Any]]
    default: Union[str, None] = None


class TagsOption(BaseChoicesOption):
    type: Literal[OptionType.tags]
    choices: Union[list[Any], None] = None
    default: Union[ConstrainedComaList[str], list, None] = None
    icon: Union[str, None] = None

    @property
    def _dynamic_annotation(self):
        return concomalist(super()._dynamic_annotation)


# ─ FILE ──────────────────────────────────────────────────


class FileOption(BaseInputOption):
    type: Literal[OptionType.file]
    # `FilePath` for CLI (file must be a file and must exists)
    # `str` for API for now since moulinette doesn't handle files
    _anno = Union[str, pydantic.FilePath]
    # Unique
    accept: Union[str, None] = None


# ─ ENTITIES ──────────────────────────────────────────────


class AppOption(BaseChoicesOption):
    type: Literal[OptionType.app]
    _anno = str
    # Unique
    filter: Union[str, bool, None] = None

    @root_validator(pre=True)
    def inject_apps_as_choices(cls, values):
        return values
        from yunohost.app import app_list

        apps = app_list(full=True)["apps"]

        if values.get("filter"):
            apps = [
                app
                for app in apps
                if evaluate_simple_js_expression(values["filter"], context=app)
            ]

        values["choices"] = {
            app["id"]: f"{app['label']} ({app.get('domain_path', app['id'])})"
            for app in apps
        }

        return values


class DomainOption(BaseChoicesOption):
    type: Literal[OptionType.domain]
    _anno = str
    # Unique
    # filter: Union[str, None] = None

    @root_validator()
    def inject_domains_as_choices(cls, values):
        # FIXME remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.domain import domain_list

        domain_list = domain_list()
        main_domain = domain_list["main"]

        # if values.get("filter"):

        values["choices"] = {
            domain: domain + " ★" if domain == main_domain else domain
            for domain in domain_list["domains"]
        }

        if not values["optional"] and values["default"] is None:
            values["default"] = main_domain

        return values


class UserOption(BaseChoicesOption):
    type: Literal[OptionType.user]
    _anno = str
    # Unique
    # filter: Union[str, None] = None

    @root_validator()
    def inject_users_as_choices(cls, values):
        from yunohost.user import user_list

        # FIXME remove calls to resources in validators (pydantic V2 should adress this)
        users = user_list(["username", "fullname", "mail", "groups"])["users"].items()
        # if values.get("filter"):

        values["choices"] = {
            username: f"{infos['fullname']} ({infos['mail']})"
            + (" ★" if "admins" in infos["groups"] else "")
            for username, infos in users
        }

        if not values["choices"]:
            # FIXME Is this the right place?
            raise YunohostValidationError(
                "app_argument_invalid",
                name=values["id"],
                error="You should create a YunoHost user first.",
            )
        if not values["optional"] and values["default"] is None:
            values["default"] = next(
                username for username, infos in users if "admins" in infos["groups"]
            )

        return values


class GroupOption(BaseChoicesOption):
    type: Literal[OptionType.group]
    _anno = str
    # Unique
    # filter: Union[str, None] = None

    @root_validator()
    def inject_groups_as_choices(cls, values):
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.user import user_group_list

        def _human_readable_group(groupname):
            # i18n: visitors
            # i18n: all_users
            # i18n: admins
            return (
                m18n.n(groupname)
                if groupname in ["visitors", "all_users", "admins"]
                else groupname
            )

        # TODO could allow filter (without primary groups for example)
        # if values.get("filter"):

        values["choices"] = {
            groupname: _human_readable_group(groupname)
            for groupname in user_group_list(short=True, include_primary_groups=False)[
                "groups"
            ]
        }

        if not values["optional"] and values["default"] is None:
            values["default"] = "all_users"

        return values


AnyOption = Union[
    # display
    DisplayTextOption,
    MarkdownOption,
    AlertOption,
    # action
    ButtonOption,
    # text
    StringOption,
    TextOption,
    PasswordOption,
    ColorOption,
    # number
    NumberOption,
    RangeOption,
    # boolean
    BooleanOption,
    # time
    DateOption,
    TimeOption,
    # location
    EmailOption,
    PathOption,
    UrlOption,
    # choice
    SelectOption,
    TagsOption,
    # file
    FileOption,
    # entity
    AppOption,
    DomainOption,
    UserOption,
    GroupOption,
]


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╴╭─╮┌─╮╭╮╮                                         │
# │  ├─╴│ │├┬╯│││                                         │
# │  ╵  ╰─╯╵ ╰╵╵╵                                         │
# ╰───────────────────────────────────────────────────────╯


class OptionsContainer(BaseModel):
    # Pydantic will match option types to their models class based on the "type" attribute
    options: list[Annotated[AnyOption, Field(discriminator="type")]]

    class Config:
        extra = pydantic.Extra.allow

    @staticmethod
    def options_dict_to_list(options: dict[str, Any], defaults: dict[str, Any] = {}):
        return [
            data
            | {
                "id": name,
                "type": data.get("type", "string"),
            }
            for name, data in options.items()
        ]

    def __init__(self, **kwargs) -> None:
        super().__init__(options=self.options_dict_to_list(kwargs))

    def translate_options(self, i18n_key: Union[str, None] = None):
        """
        Mutate in place translatable attributes of options to their translations
        """
        for option in self.options:
            for key in ("ask", "help"):
                if not hasattr(option, key):
                    continue

                value = getattr(option, key)
                if value:
                    setattr(option, key, _value_for_locale(value))
                elif key == "ask" and m18n.key_exists(f"{i18n_key}_{option.id}"):
                    setattr(option, key, m18n.n(f"{i18n_key}_{option.id}"))
                elif key == "help" and m18n.key_exists(f"{i18n_key}_{option.id}_help"):
                    setattr(option, key, m18n.n(f"{i18n_key}_{option.id}_help"))
                elif key == "ask":
                    # FIXME raise error?
                    option.ask = option.id


class YunoForm(BaseModel):
    """
    Base form on which dynamic forms are built upon Options.
    """

    def __getitem__(self, name: str):
        return getattr(self, name)

    def __setitem__(self, name: str, value: Any):
        setattr(self, name, value)

    def get(self, name: str, default: Any = None) -> Any:
        try:
            return getattr(self, name)
        except:
            return default

    class Config:
        validate_assignment = True
        extra = pydantic.Extra.ignore

    def dict(self, *, as_env: bool = False, normalize: bool = True, **kwargs):
        data = super().dict(**kwargs)
        if as_env:
            return {k: self.bashify(k) for k in data}
        if normalize:
            return {k: self.normalize(k) for k in data}
        return data

    def normalize(self, option_id: str) -> str:
        """
        Return a value as Python default types.
        """
        v = self[option_id]
        if isinstance(v, pydantic.SecretStr):
            return v.get_secret_value()
        elif isinstance(v, pydantic.color.Color):
            return v.as_hex()
        elif isinstance(v, Path):
            return str(v)
        else:
            return v

    def bashify(self, option_id: str) -> str:
        """
        Stringify a value for bash environment
        """
        v = self[option_id]
        if isinstance(v, bool):
            extra = self.__fields__[option_id].field_info.extra
            return extra["parse"]["yes" if v is True else "no"]
        elif not v:
            return ""
        elif isinstance(v, pydantic.SecretStr):
            return v.get_secret_value()
        elif isinstance(v, pydantic.color.Color):
            return v.as_hex()
        elif isinstance(v, list):
            return ",".join(v)
        else:
            return str(v)

    def humanize(self, option_id: str) -> str:
        """
        Stringify a value to be used in cli prompt
        """
        v = self[option_id]
        if isinstance(v, bool):
            return "yes" if v is True else "no"
        elif isinstance(v, pydantic.color.Color):
            return v.as_named()
        else:
            return self.bashify(option_id)

    @validator("*", pre=True)
    def parse_string(cls, v):
        """
        Global validator to clean strings and parse None from CLI
        """
        # FIXME maybe do not parse `""` as None
        if isinstance(v, str):
            v = v.strip()
            if v in ("", "null", "none", "_none"):
                return None
        return v


def parse_prefilled_values(
    args: Union[str, None] = None,
    args_file=None,  # FIXME TYPING
) -> dict[str, Any]:
    """
    Retrieve form values from yaml file or query string.
    """
    values: dict[str, Any] = {}
    if args_file:
        # Import YAML / JSON file
        values |= read_yaml(args_file)
    if args:
        values |= {
            k: ",".join(v)
            for k, v in urllib.parse.parse_qs(args, keep_blank_values=True).items()
        }
    return values


def build_form(
    options: list[AnyOption], name: str = "DynamicYunoForm"
) -> Type[YunoForm]:
    """
    Returns a dynamic pydantic model class that can act as a form with validation when instanciated.
    """
    options_as_fields: Any = {
        option.id: option.as_dynamic_model_field()
        for option in options
        if isinstance(option, BaseInputOption)  # filter out non input options
    }
    return pydantic.create_model(
        name,
        __base__=YunoForm,
        **options_as_fields,
    )


def fill_form(
    options: list[AnyOption],
    form: "YunoForm",
    prefilled_answers: dict[str, Any],
    context: dict[str, Any] = {},
    action_id: Union[str, None] = None,
) -> "YunoForm":
    """
    API only method to validate a form passed as query string.
    Most checks should be handled by the webadmin but we recheck in case of
    direct call to API or webadmin missing some validation.
    """
    logger.debug("Validating form...")

    for option in options:
        if isinstance(option, ButtonOption):
            if action_id == option.id:
                if option.is_visible(context) and option.is_enabled(context):
                    # Action can be ran, quit prompt mode and return current form
                    return form
                else:
                    # TODO provide an meaningfull error within option declaration?
                    raise YunohostValidationError(
                        f"Action '{action_id}' couldn't be ran, its conditions are not fullfilled."
                    )

        prefilled = option.id in prefilled_answers
        if not option.is_visible(context):
            if prefilled:
                logger.warning(
                    f"Skipping setting: '{option.id}' since conditions are not fullfilled."
                )
            continue

        prev_value = form[option.id]
        try:
            form[option.id] = (
                prefilled_answers[option.id] if prefilled else form[option.id]
            )
            context[option.id] = form.normalize(option.id)
            if form[option.id] == prev_value:
                form.__fields_set__.remove(option.id)
        except pydantic.ValidationError as e:
            # TODO could test every form values and return all errors directly instead of the first one
            errors = "\n".join([error["msg"] for error in e.errors()])
            raise YunohostValidationError(errors, raw_msg=True)

    return form


def prompt_form(
    options: list[AnyOption],
    form: "YunoForm",
    prefilled_answers: dict[str, Any],
    context: dict[str, Any] = {},
    action_id: Union[str, None] = None,
) -> "YunoForm":
    """
    CLI only method to interactively prompt and validate a form an option at a time.
    """
    for option in options:
        if isinstance(option, ButtonOption):
            if option.id != action_id:
                # Skip other buttons/actions that may be defined in the same action section
                continue
            if option.is_visible(context) and option.is_enabled(context):
                # Action can be ran, quit prompt mode and return current form
                return form
            else:
                # TODO provide an meaningfull error within option toml declaration?
                raise YunohostValidationError(
                    f"Action '{action_id}' couldn't be ran, its conditions are not fullfilled."
                )

        if not option.is_visible(context):
            if not isinstance(option, BaseReadonlyOption):
                context[option.id] = form.normalize(option.id)
            if option.id in prefilled_answers:
                logger.warning(
                    f"Skipping setting: '{option.id}' since conditions are not fullfilled."
                )
            continue

        # Cast option.ask to str since it should be translated
        message = cast(str, option.ask)

        if isinstance(option, BaseReadonlyOption):
            if isinstance(option, AlertOption):
                colors = {
                    "success": "green",
                    "info": "cyan",
                    "warning": "yellow",
                    "danger": "red",
                }
                title = (
                    m18n.g(option.style)
                    if option.style != "danger"
                    else m18n.n("danger")
                )
                message = f"{colorize(title, colors[option.style])} {message}"
            Moulinette.display(message)
            continue

        prefill = form.humanize(option.id)
        if option.readonly:
            # FIXME a bit annoying to parse the value
            # Parse the readonly value in case it come from bash then populate the context
            form[option.id] = prefill
            context[option.id] = form.normalize(option.id)
            message = f"{colorize(message, 'purple')} {prefill}"
            Moulinette.display(message)
            continue

        choices = []
        if isinstance(option, BaseChoicesOption) and option.choices:
            choices = (
                list(option.choices.keys())
                if isinstance(option.choices, dict)
                else option.choices
            )
            # Prevent displaying a shitload of choices
            # (e.g. 100+ available users when choosing an app admin...)
            choices_to_display = choices[:20]
            remaining_choices = len(choices[20:])

            if remaining_choices > 0:
                choices_to_display += [
                    m18n.n("other_available_options", n=remaining_choices)
                ]

            message += f" [{' | '.join(choices_to_display)}]"

        prev_value = form[option.id]
        while True:
            if option.id in prefilled_answers:
                # value was given thru query string or file, test it as if it was prompted
                value = prefilled_answers[option.id]
            else:
                value = Moulinette.prompt(
                    message=message,
                    is_password=option.redact,
                    confirm=False,
                    prefill=prefill,
                    # default=option.humanize(option.default),
                    is_multiline=(option.type == "text"),
                    autocomplete=choices,
                    help=option.help,
                )

            try:
                form[option.id] = value
                context[option.id] = form.normalize(option.id)

                if form[option.id] == prev_value:
                    form.__fields_set__.remove(option.id)

                break
            except pydantic.ValidationError as e:
                if option.id in prefilled_answers:
                    Moulinette.display(
                        "Prefilled answer from args or file is not valid, you can correct it now:",
                        style="error",
                    )
                    # Remove given prefilled_anwsers since its not valid.
                    # Will prompt for a correction
                    del prefilled_answers[option.id]

                for error in e.errors():
                    # FIXME rework errors (use yunohost ones or translate pydantic ones)
                    Moulinette.display(error["msg"], style="error")
                # Save erroneus answer and let ppl correct it
                prefill = value

        # TODO hooks
        # Question._post_parse_value (redac stuff in operation logger)
    return form


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╴╷ ╷╭─┐╷                                           │
# │  ├─╴│╭╯├─┤│                                           │
# │  ╰─╴╰╯ ╵ ╵╰─╴                                         │
# ╰───────────────────────────────────────────────────────╯

# Those js-like evaluate functions are used to eval safely `visible` and
# `enabled` attributes.
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


def js_to_python(expr: str) -> str:
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


def evaluate_simple_js_expression(expr: str, context: dict[str, Any] = {}) -> bool:
    if not expr.strip():
        return False
    node = ast.parse(js_to_python(expr), mode="eval").body
    return evaluate_simple_ast(node, context)
