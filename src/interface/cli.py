from __future__ import (
    annotations,
)  # Enable self reference a class in its own method arguments

import os
import inspect
import typer
import yaml

from typing import Any, Callable
from rich import print as rprint
from rich.syntax import Syntax

from yunohost.interface.base import (
    BaseInterface,
    InterfaceKind,
    merge_dicts,
    get_params_doc,
    override_function,
)
from yunohost.utils.error import YunohostValidationError


def parse_cli_command(command: str) -> tuple[str, list[str]]:
    command, *args = command.split(" ")
    return command, [arg.strip("{}") for arg in args]


def print_as_yaml(data: Any):
    data = yaml.dump(data, default_flow_style=False)
    rprint(Syntax(data, "yaml", background_color="default"))


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
            return typer.prompt(ask, hide_input=is_password, confirmation_prompt=confirm)
        else:
            from moulinette import Moulinette
            return Moulinette.prompt(ask, is_password=is_password, confirm=confirm, **kwargs)


    def cli(self, command_def: str, **extra_data):
        def decorator(func: Callable):
            signature = inspect.signature(func)
            override_params = []
            params = self.filter_params(signature.parameters.values())
            local_data = merge_dicts(self.local_data, extra_data)
            params_doc = get_params_doc(func.__doc__)
            command, args = parse_cli_command(command_def)

            for param in params:
                param_default = (
                    param.default
                    if not param.default == param.empty
                    else ...  # required
                )

                param_kwargs = local_data.get(param.name, {})
                param_kwargs["help"] = params_doc.get(param.name, None)

                if param_kwargs.pop("deprecated", False):
                    param_kwargs["rich_help_panel"] = "Deprecated Options"

                if param_kwargs.get("prompt", False):
                    if param.name == "password":
                        param_kwargs["confirmation_prompt"] = True
                        param_kwargs["hide_input"] = True

                # Populate default param value with typer.Argument|Option
                if param_kwargs.pop("file", False):
                    new_param = param.replace(
                        annotation=typer.FileText,
                        default=param_default
                    )
                elif param.kind == param.VAR_POSITIONAL:
                    new_param = param
                elif param.name in args:
                    new_param = param.replace(default=typer.Argument(param_default, **param_kwargs))
                else:
                    new_param = param.replace(default=typer.Option(param_default, **param_kwargs))

                override_params.append(new_param)

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

            return func

        return decorator
