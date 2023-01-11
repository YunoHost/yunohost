from __future__ import (
    annotations,
)  # Enable self reference a class in its own method arguments

import inspect
import re
import fastapi
import pydantic
import starlette

from typing import Any, Optional, Union

from pydantic.error_wrappers import ErrorWrapper

from yunohost.interface.base import (
    BaseInterface,
    InterfaceKind,
    merge_dicts,
    get_params_doc,
    override_function,
)
from yunohost.utils.error import YunohostValidationError


def snake_to_camel_case(snake: str) -> str:
    return "".join(word.title() for word in snake.split("_"))


def parse_api_route(route: str) -> list[str]:
    return re.findall(r"{(\w+)}", route)


def params_to_body(
    params: list[inspect.Parameter],
    data: dict[str, Any],
    doc: dict[str, Any],
    func_name: str,
) -> inspect.Parameter:
    model = pydantic.create_model(
        snake_to_camel_case(func_name),
        **{
            param.name: (
                param.annotation,
                pydantic.Field(
                    param.default if param.default != param.empty else ...,
                    description=doc.get(param.name, None),
                    **data.get(param.name, {}),
                ),
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


class Interface(BaseInterface):
    kind = InterfaceKind.API

    instance: Union[fastapi.FastAPI, fastapi.APIRouter]
    name: str

    def __init__(self, root: bool = False, **kwargs):
        super().__init__(root=root, **kwargs)
        self.instance = fastapi.FastAPI() if root else fastapi.APIRouter()

    def add(self, interface: Interface):
        assert isinstance(interface.instance, fastapi.APIRouter)
        self.instance.include_router(
            interface.instance, prefix=interface.prefix, tags=[interface.name] if interface.name else []
        )

    def prepare_params(
        self,
        params: list[inspect.Parameter],
        as_body: bool,
        as_body_except: Optional[list[str]] = None,
    ) -> list[Union[list[inspect.Parameter], inspect.Parameter]]:
        params = self.filter_params(params)

        if as_body_except:
            body_params = []
            rest = []
            for param in params:
                if param.name not in as_body_except:
                    body_params.append(param)
                else:
                    rest.append(param)
            return [body_params, *rest]

        if as_body:
            return [params]

        return params

    def api(
        self,
        route: str,
        method: str = "get",
        as_body: bool = False,
        as_body_except: Optional[list[str]] = None,
        **extra_data,
    ):
        as_body = as_body if not as_body_except else True

        def decorator(func):
            signature = inspect.signature(func)
            override_params = []
            params = self.prepare_params(
                signature.parameters.values(), as_body, as_body_except
            )
            local_data = merge_dicts(self.local_data, extra_data)
            params_doc = get_params_doc(func.__doc__)
            paths = parse_api_route(route)

            for param in params:
                if isinstance(param, list):
                    override_params.append(
                        params_to_body(param, local_data, params_doc, func.__name__)
                    )
                else:
                    param_kwargs = local_data.get(param.name, {})
                    param_kwargs["description"] = params_doc.get(param.name, None)
                    param_default = (
                        param.default
                        if not param.default == param.empty
                        else ...  # required
                    )

                    if param.name in paths:
                        param_default = fastapi.Path(param_default, **param_kwargs)
                    else:
                        param_default = fastapi.Query(param_default, **param_kwargs)

                    override_params.append(param.replace(default=param_default))

            def hook_results(*args, **kwargs):
                new_kwargs = {}
                opened_files = []

                for name, value in kwargs.items():
                    if isinstance(value, pydantic.BaseModel):
                        # Turn pydantic model back to individual kwargs
                        new_kwargs = value.dict() | new_kwargs
                    else:
                        new_kwargs[name] = value

                try:
                    return func(*args, **new_kwargs)
                except YunohostValidationError as e:
                    # Try to mimic Pydantic validation errors
                    # FIXME replace dummy error information
                    raise fastapi.exceptions.RequestValidationError([ErrorWrapper(ValueError(e.strerror), ("query", "test"))])
                except:
                    raise

            route_func = override_function(
                func,
                signature,
                override_params,
                decorator=hook_results,
                doc=func.__doc__.split("\f")[0] if func.__doc__ else None,
            )

            summary = func.__doc__.split("\b")[0] if func.__doc__ else None
            getattr(self.instance, method)(
                route, summary=summary, deprecated=local_data.get("deprecated")
            )(route_func)

            self.clear_local_data()

            return func

        return decorator
