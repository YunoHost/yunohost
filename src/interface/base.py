import inspect
import types
import re

from enum import Enum
from typing import Any, Callable, Optional, TypeVar

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
    returned_func.__signature__ = func_signature.replace(parameters=tuple(new_params))

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

    def filter_params(self, params: list[inspect.Parameter]) -> list[inspect.Parameter]:
        private = self.local_data.get("private", [])

        if private:
            return [param for param in params if param.name not in private]

        return params

    def api(self, *args, **kwargs):
        return pass_func

    def cli(self, *args, **kwargs):
        return pass_func
