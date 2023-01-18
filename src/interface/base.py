from __future__ import (
    annotations,
)  # Enable self reference a class in its own method arguments

import inspect
import types
import re

from enum import Enum
from typing import (
    Annotated,
    Any,
    Callable,
    Iterable,
    Iterator,
    Optional,
    TypeVar,
    Union,
    get_origin,
    get_args,
)

import pydantic

from yunohost.interface.types import PrivateParam


ViewFunc = TypeVar("ViewFunc")


class InterfaceKind(Enum):
    API = "api"
    CLI = "cli"


def pass_func(func: ViewFunc) -> ViewFunc:
    return func


def merge_dicts(*dicts: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}

    for dict_ in dicts:
        for key, value in dict_.items():
            if key not in merged or isinstance(merged[key], (str, int, float, bool)):
                merged[key] = value
            else:
                merged[key] |= value

    return merged


def get_params_doc(docstring: Optional[str]) -> dict[str, str]:
    if not docstring:
        return {}

    return {
        param_name: param_desc
        for param_name, param_desc in re.findall(
            r"- \*\*(\w+)\*\*: (.*)", docstring, re.MULTILINE
        )
    }


def validate_pattern(pattern: str, value: str, name: Optional[str] = None):

    if not re.match(pattern, value, re.UNICODE):
        error = name if name else "'{value}' does'nt match pattern '{pattern}'"
        raise ValueError(error.format(value=value, pattern=pattern))

    return value


def override_function(
    func: Callable,
    func_signature: inspect.Signature,
    new_params: list[inspect.Parameter],
    decorator: Optional[Callable] = None,
    name: Optional[str] = None,
    doc: Optional[str] = None,
) -> Callable:
    returned_func = decorator or types.FunctionType(
        func.__code__,
        func.__globals__,
        func.__name__,
        func.__defaults__,
        func.__closure__,
    )
    returned_func.__name__ = name or func.__name__
    returned_func.__doc__ = doc or func.__doc__
    returned_func.__signature__ = func_signature.replace(parameters=tuple(new_params))  # type: ignore

    return returned_func


class BaseInterface:
    kind: InterfaceKind
    local_data: dict[str, Any] = {}

    def __init__(
        self,
        root: bool = False,
        name: str = "",
        help: str = "",
        prefix: str = "",
    ):
        self.name = "root" if root else name or ""
        self.help = help
        self.prefix = prefix

    def __call__(self, *args, **kwargs):
        self.local_data = kwargs
        return pass_func

    def clear_local_data(self):
        self.local_data = {}

    @staticmethod
    def build_fields(
        params: Iterable[inspect.Parameter],
        annotations: dict[str, Any],
        doc: dict[str, str],
        positional_params: list[str],
    ) -> Iterator[tuple[inspect.Parameter, Optional[pydantic.fields.FieldInfo]]]:

        for param in params:
            annotation = annotations[param.name]
            field: Optional[pydantic.fields.FieldInfo] = None
            description = doc.get(param.name, None)

            if get_origin(annotation) is Annotated:
                annotation, field = get_args(annotation)

                if get_origin(field) is PrivateParam:
                    field = None
                elif isinstance(field, pydantic.fields.FieldInfo):
                    field = update_field_from_annotation(
                        field,
                        param.default,
                        name=param.name,
                        description=description,
                        positional=param.name in positional_params,
                    )
                else:
                    raise Exception(
                        "Views function paramaters can only be 'Annotated[Any, PrivateParam | Param]' but found '{new_param}'"
                    )

            else:
                field = Field(
                    param.default,
                    name=param.name,
                    description=description,
                    positional=param.name in positional_params,
                )

            param = param.replace(annotation=annotation)

            yield param, field

    def api(self, *args, **kwargs):
        return pass_func

    def cli(self, *args, **kwargs):
        return pass_func


def Field(
    default: Any = ...,
    *,
    name: Optional[str] = None,
    positional: bool = False,
    param_decls: Optional[list[str]] = None,
    deprecated: bool = False,
    description: Optional[str] = None,
    hidden: bool = False,
    regex: Optional[Union[str, tuple[str, str]]] = None,
    ask: Union[str, bool] = False,
    confirm: bool = False,
    redac: bool = False,
    file: bool = False,
    panel: Optional[str] = None,
    example: Optional[str] = None,
    # default_factory: Optional[NoArgAnyCallable] = None,
    # alias: str = None,
    # title: str = None,
    # exclude: Union['AbstractSetIntStr', 'MappingIntStrAny', Any] = None,
    # include: Union['AbstractSetIntStr', 'MappingIntStrAny', Any] = None,
    # const: bool = None,
    # gt: float = None,
    # ge: float = None,
    # lt: float = None,
    # le: float = None,
    # multiple_of: float = None,
    # allow_inf_nan: bool = None,
    # max_digits: int = None,
    # decimal_places: int = None,
    # min_items: int = None,
    # max_items: int = None,
    # unique_items: bool = None,
    # min_length: int = None,
    # max_length: int = None,
    # allow_mutation: bool = True,
    # discriminator: str = None,
    # repr: bool = True,
    **kwargs: Any,
) -> pydantic.fields.FieldInfo:

    pattern_name = kwargs.get("pattern_name", None)
    if isinstance(regex, tuple):
        pattern_name, regex = regex

    return pydantic.fields.Field(
        default=... if default is inspect.Parameter.empty else default,
        # default_factory=default_factory,
        # alias=alias,
        # title=title,
        description=description,  # type: ignore
        # exclude=exclude,
        # include=include,
        # const=const,
        # gt=gt,
        # ge=ge,
        # lt=lt,
        # le=le,
        # multiple_of=multiple_of,
        # allow_inf_nan=allow_inf_nan,
        # max_digits=max_digits,
        # decimal_places=decimal_places,
        # min_items=min_items,
        # max_items=max_items,
        # unique_items=unique_items,
        # min_length=min_length,
        # max_length=max_length,
        # allow_mutation=allow_mutation,
        regex=regex,  # type: ignore
        # discriminator=discriminator,
        # repr=repr,
        # Yunohost custom
        name=name,
        param_decls=param_decls,
        positional=positional,
        deprecated=deprecated,
        hidden=hidden,
        # Typer Option only
        ask=False if deprecated else ask,
        confirm=confirm,
        redac=redac,
        # Type
        file=file,
        # Rich
        panel=panel,
        pattern_name=pattern_name,
        example=example,
        # **kwargs,
    )


def update_field_from_annotation(
    field: pydantic.fields.FieldInfo,
    default: Any,
    name: Optional[str] = None,
    description: Optional[str] = None,
    positional: bool = False,
):
    #  FIXME proper copyy?
    copy = {attr: getattr(field, attr) for attr in field.__slots__}
    field = Field(**copy | copy.pop("extra"))

    field.default = ... if default is inspect.Parameter.empty else default
    if name:
        field.extra["name"] = name
    if description:
        field.description = description
    if positional:
        field.extra["positional"] = positional
        field.extra["ask"] = False

    return field
