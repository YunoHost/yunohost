from __future__ import annotations

import inspect
import types
import fastapi
import pydantic

from typing import Optional, Union


def snake_to_camel_case(snake: str) -> str:
    return "".join(word.title() for word in snake.split("_"))


def get_path_param(route: str) -> Optional[str]:
    last_path = route.split("/")[-1]
    if last_path and "{" in last_path:
        return last_path.strip("{}")
    return None


def alter_params_for_body(
    parameters, as_body, as_body_except
) -> list[Union[list[inspect.Parameter], inspect.Parameter]]:
    if as_body_except:
        body_params = []
        rest = []
        for param in parameters:
            if param.name not in as_body_except:
                body_params.append(param)
            else:
                rest.append(param)
        return [body_params, *rest]

    if as_body:
        return [parameters]

    return parameters


def params_to_body(
    params: list[inspect.Parameter], func_name: str
) -> inspect.Parameter:
    model = pydantic.create_model(
        snake_to_camel_case(func_name),
        **{
            param.name: (
                param.annotation,
                param.default if param.default != param.empty else ...,
            )
            for param in params
        },
    )

    return inspect.Parameter(
        func_name.split("_")[0],
        inspect.Parameter.POSITIONAL_ONLY,
        default=...,
        annotation=model,
    )


class Interface:
    type = "api"

    instance: Union[fastapi.FastAPI, fastapi.APIRouter]
    name: str

    def __init__(self, root: bool = False, name: Optional[str] = None):
        self.instance = fastapi.FastAPI() if root else fastapi.APIRouter()
        self.name = "root" if root else name or ""

    def add(self, interface: Interface):
        assert isinstance(interface.instance, fastapi.APIRouter)
        self.instance.include_router(
            interface.instance, prefix=f"/{interface.name}", tags=[interface.name]
        )

    def cli(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def api(
        self,
        route: str,
        method: str = "get",
        as_body: bool = False,
        as_body_except: Optional[list[str]] = None,
        **kwargs,
    ):
        as_body = as_body if not as_body_except else True

        def decorator(func):
            signature = inspect.signature(func)
            override_params = []
            params = alter_params_for_body(
                signature.parameters.values(), as_body, as_body_except
            )
            path_param = get_path_param(route)

            for param in params:
                if isinstance(param, list):
                    override_params.append(params_to_body(param, func.__name__))
                else:
                    default_kwargs = kwargs.get(param.name, {})
                    default_cls = (
                        fastapi.Path if param.name == path_param else fastapi.Query
                    )

                    if param.default is None:
                        default_value = default_cls(None, **default_kwargs)
                    elif param.default is param.empty:
                        default_value = default_cls(..., **default_kwargs)
                    else:
                        default_value = default_cls(param.default, **default_kwargs)

                    override_params.append(param.replace(default=default_value))

            route_func = getattr(self.instance, method)(route)
            override_signature = signature.replace(parameters=tuple(override_params))

            if as_body:

                def body_to_args_back(*args, **kwargs):
                    new_kwargs = {}
                    for kwarg, value in kwargs.items():
                        if issubclass(type(value), pydantic.BaseModel):
                            new_kwargs = value.dict() | new_kwargs
                        else:
                            new_kwargs[kwarg] = value
                    return func(*args, **new_kwargs)

                body_to_args_back.__name__ = func.__name__
                body_to_args_back.__signature__ = override_signature
                route_func(body_to_args_back)
            else:
                func_copy = types.FunctionType(
                    func.__code__,
                    func.__globals__,
                    func.__name__,
                    func.__defaults__,
                    func.__closure__,
                )
                func_copy.__signature__ = override_signature
                route_func(func_copy)

            return func

        return decorator
