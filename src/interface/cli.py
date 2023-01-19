from __future__ import (
    annotations,
)  # Enable self reference a class in its own method arguments

import os
import inspect
import yaml

import typer
import pydantic

from typing import (
    Any,
    Callable,
    Optional,
    Union,
    get_type_hints,
)
from rich import print as rprint
from rich.syntax import Syntax

from yunohost.interface.base import (
    BaseInterface,
    InterfaceKind,
    merge_dicts,
    get_params_doc,
    override_function,
    validate_pattern,
)
from yunohost.utils.error import YunohostValidationError


def parse_cli_command(command: str) -> tuple[str, list[str]]:
    command, *args = command.split(" ")
    return command, [arg.strip("{}") for arg in args]


def print_as_yaml(data: Any):
    data = yaml.dump(data, default_flow_style=False)
    rprint(Syntax(data, "yaml", background_color="default"))


def pattern_validator(pattern: str, name: Optional[str]):
    def inner_validator(ctx: typer.Context, param_: typer.CallbackParam, value: str):
        if ctx.resilient_parsing:
            return
        try:
            return validate_pattern(pattern, value, name)
        except ValueError as e:
            raise typer.BadParameter(str(e))

    return inner_validator


class Interface(BaseInterface):
    kind = InterfaceKind.CLI
    instance: typer.Typer
    name: str

    def __init__(self, root: bool = False, **kwargs):
        super().__init__(root=root, **kwargs)
        self.instance = typer.Typer(rich_markup_mode="markdown")

    def add(self, interface: Interface):
        self.instance.add_typer(
            interface.instance, name=interface.name, help=interface.help
        )

    @staticmethod
    def display(content: str):
        if os.environ.get("INTERFACE") == "cli":
            rprint(content)
        else:
            from moulinette import Moulinette

            Moulinette.display(content)

    @staticmethod
    def prompt(ask: str, is_password=False, confirm=False, **kwargs):
        if os.environ.get("INTERFACE") == "cli":
            return typer.prompt(
                ask, hide_input=is_password, confirmation_prompt=confirm
            )
        else:
            from moulinette import Moulinette

            return Moulinette.prompt(
                ask, is_password=is_password, confirm=confirm, **kwargs
            )

    def cli(self, command_def: str, **extra_data):
        def decorator(func: Callable):
            local_data = merge_dicts(self.local_data, extra_data)

            signature = inspect.signature(func)
            annotations = get_type_hints(func, include_extras=True)
            params = signature.parameters.values()
            doc = get_params_doc(func.__doc__)
            command, positional_params = parse_cli_command(command_def)

            forward_params = []
            override_params = []

            for param, field in self.build_fields(
                params, annotations, doc, positional_params
            ):
                forward_params.append(param)

                if field:
                    override_param = param.replace(
                        default=field_to_typer_default(field)
                    )
                    override_params.append(override_param)

            def hook_results(*args, **kwargs):
                try:
                    results = func(*args, **kwargs)
                    print_as_yaml(results)
                    return results
                except YunohostValidationError as e:
                    raise typer.BadParameter(e.strerror)
                except:
                    raise

            command_func = override_function(
                func,
                signature,
                override_params,
                decorator=hook_results,
                doc=func.__doc__.split("\b")[0] if func.__doc__ else None,
            )
            self.instance.command(
                command, deprecated=local_data.get("deprecated", False)
            )(command_func)

            self.clear_local_data()
            func.__signature__ = override_function(func, signature, forward_params)  # type: ignore
            return func

        return decorator


def field_to_typer_default(
    field: pydantic.fields.FieldInfo,
) -> Union[typer.models.ArgumentInfo, typer.models.OptionInfo]:
    name = field.extra["name"]
    positional = field.extra["positional"]
    param_decls = field.extra["param_decls"]
    panel = field.extra["panel"]

    generic = {
        "callback": None,
        # "metavar": None,
        "show_default": field.default is not Ellipsis,
        "help": field.description,
        "hidden": field.extra["hidden"],
        # "show_choices": True,
        "rich_help_panel": panel,
    }

    if field.extra["deprecated"] and not panel:
        generic["rich_help_panel"] = "Deprecated Options"

    if field.regex:
        generic["callback"] = pattern_validator(
            field.regex, field.extra["pattern_name"]
        )

    if not positional:
        specific: dict[str, Any] = {
            "prompt": field.extra["ask"],  # Union[bool, str]
            "confirmation_prompt": field.extra["confirm"],  # bool
            # "prompt_required": True,  # bool
            "hide_input": field.extra["redac"],  # bool
            # "is_flag": None,  # Optional[bool]
            # "flag_value": None,  # Optional[Any]
            # "count": False,  # bool
            # "allow_from_autoenv": True,
        }

    if positional:
        return typer.Argument(
            field.default,
            **generic,
        )

    if param_decls:
        param_decls.insert(0, "--" + name.replace("_", "-"))
    else:
        param_decls = ["--" + name.replace("_", "-"), "-" + name[0]]

    return typer.Option(
        field.default,
        *param_decls,
        **generic,
        **specific,
    )
