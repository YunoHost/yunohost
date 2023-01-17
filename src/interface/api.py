from __future__ import (
    annotations,
)  # Enable self reference a class in its own method arguments

import inspect
import re
import codecs

import fastapi
import pydantic
import starlette

from typing import Optional, Union, get_type_hints

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
        def decorator(func):
            local_data = merge_dicts(self.local_data, extra_data)

            signature = inspect.signature(func)
            annotations = get_type_hints(func, include_extras=True)
            params = signature.parameters.values()
            doc = get_params_doc(func.__doc__)
            positional_params = parse_api_route(route)

            forward_params = []
            override_params = []
            body_fields = {}
            for param, field in self.build_fields(
                Interface, params, annotations, doc, positional_params
            ):

                if field and field.extra.get("file"):
                    param = param.replace(annotation=fastapi.UploadFile)

                forward_params.append(param)

                if not field or field.extra["deprecated"]:
                    continue

                if as_body or (
                    as_body_except is not None and param.name not in as_body_except
                ):
                    body_fields[param.name] = (param.annotation, field)
                else:
                    override_param = param.replace(
                        default=field_to_fastapi_default(field)
                    )
                    override_params.append(override_param)

            if body_fields:
                override_params.insert(
                    0, field_to_fastapi_body_default(body_fields, func.__name__)
                )

            def hook_results(*args, **kwargs):
                new_kwargs = {}
                opened_files = []

                for name, value in kwargs.items():
                    if isinstance(value, pydantic.BaseModel):
                        # Turn pydantic model back to individual kwargs
                        new_kwargs = value.dict() | new_kwargs
                    elif isinstance(value, starlette.datastructures.UploadFile):
                        # views expects a opened file (fastapi UploadFile is a bytes SpooledTemporaryFile)
                        new_kwargs[name] = codecs.iterdecode(value.file, "utf-8")
                        opened_files.append(name)
                    else:
                        new_kwargs[name] = value

                try:
                    return func(*args, **new_kwargs)
                except YunohostValidationError as e:
                    # Try to mimic Pydantic validation errors
                    # FIXME replace dummy error information
                    raise fastapi.exceptions.RequestValidationError(
                        [
                            pydantic.errors.ErrorWrapper(
                                ValueError(e.strerror), ("query", "test")
                            )
                        ]
                    )
                except:
                    raise
                finally:
                    # I guess we need to close the opened file
                    for kwarg_name in opened_files:
                        kwargs[kwarg_name].file.close()

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


def field_to_fastapi_body_default(
    fields: dict[str, tuple[type, pydantic.fields.FieldInfo]],
    func_name: str,
) -> inspect.Parameter:

    model = pydantic.create_model(
        snake_to_camel_case(func_name),
        **fields,
    )
    default = fastapi.Body(
        ...,
        example={
            name: field.extra["example"] or f"missing example of {str(t)}"
            if field.default in (..., None)
            else field.default
            for name, (t, field) in fields.items()
        },
    )

    return inspect.Parameter(
        func_name.split("_")[0],
        inspect.Parameter.POSITIONAL_ONLY,
        default=default,
        annotation=model,
    )


def field_to_fastapi_default(
    field: pydantic.fields.FieldInfo,
) -> Union[fastapi.params.Path, fastapi.params.Query]:
    generic = {
        "description": field.description,
        "regex": field.regex,
        "include_in_schema": not field.extra["hidden"],
        "deprecated": field.extra["deprecated"],
        "example": field.extra["example"],
    }

    if field.extra["positional"]:
        return fastapi.Path(
            field.default,
            **generic,
        )

    return fastapi.Query(
        field.default,
        **generic,
    )
