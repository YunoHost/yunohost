from __future__ import annotations

import inspect
import typer
import yaml

from typing import Any, Optional
from rich import print as rprint
from rich.syntax import Syntax


def parse_cli_command(command: str) -> tuple[str, list[str]]:
    command, *args = command.split(" ")
    return command, [arg.strip("{}") for arg in args]


def print_as_yaml(data: Any):
    data = yaml.dump(data, default_flow_style=False)
    rprint(Syntax(data, "yaml", background_color="default"))


class Interface:
    type = "cli"

    instance: typer.Typer
    name: str

    def __init__(self, root: bool = False, name: Optional[str] = None):
        self.instance = typer.Typer()
        self.name = "root" if root else name or ""

    def add(self, interface: Interface):
        self.instance.add_typer(interface.instance, name=interface.name)

    def cli(self, command_def: str, **kwargs):
        def decorator(func):
            signature = inspect.signature(func)
            override_params = []
            command, args = parse_cli_command(command_def)

            for param in signature.parameters.values():

                # Auto setup typer Argument or Option kwargs
                default_kwargs = kwargs.get(param.name, {})
                # if param.name not in args and not default_kwargs.get("hidden", False):
                #     default_kwargs["prompt"] = True
                if param.name == "password":
                    default_kwargs["confirmation_prompt"] = True
                    default_kwargs["hide_input"] = True

                # Define new default value for typer
                default_cls = typer.Argument if param.name in args else typer.Option
                if param.default is None:
                    default_value = default_cls(None, **default_kwargs)
                elif param.default is param.empty:
                    default_value = default_cls(..., **default_kwargs)
                else:
                    default_value = default_cls(param.default, **default_kwargs)

                override_params.append(param.replace(default=default_value))

            def hook_results(*args, **kwargs):
                results = func(*args, **kwargs)
                print_as_yaml(results)
                return results

            hook_results.__name__ = func.__name__
            hook_results.__signature__ = signature.replace(
                parameters=tuple(override_params)
            )
            self.instance.command(command)(hook_results)

            return func

        return decorator

    def api(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator
