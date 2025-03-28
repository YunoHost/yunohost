import typing as t
from dataclasses import dataclass
from pydantic import ValidationError
from pydantic_core import PydanticCustomError, PydanticUseDefault, core_schema as cs

if t.TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core import CoreSchema


Mode = t.Literal["python", "bash"]
Translation = dict[str, str] | str


@dataclass
class Pattern:
    regexp: str
    error: Translation = "pydantic.value_error.str.regex"


# TYPE CHECKING
NONISH_VALUES: t.Final = (None, "")  # null, nil, undefined
def is_nonish(v: t.Any) -> bool:
    v = v.strip().lower() if isinstance(v, str) else v
    return True if v in NONISH_VALUES else False


# COERCING/SERIALIZING


def coerce_nonish_to_default(v: t.Any) -> t.Any:
    if is_nonish(v):
        raise PydanticUseDefault()
    return v


def coerce_nonish_to_none(v: t.Any) -> t.Any:
    return None if is_nonish(v) else v


def serialize_none_to_empty_str(v: t.Any) -> t.Any:
    return "" if v is None else v


# CORE SCHEMA HELPERS


def find_type_schema(schema: "CoreSchema", type_: str) -> t.Union["CoreSchema", None]:
    if schema["type"] == type_:
        return schema
    if schema["type"] == "nullable":
        return find_type_schema(schema["schema"], type_)
    if schema["type"] == "union":
        return next((s for s in schema["choices"] if s["type"] == type_), None)
    return None


# CONSTRAINTS


@dataclass
class StringConstraints:
    mode: Mode = "python"
    has_default: bool = False
    pattern: Pattern | None = None

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        str_schema = find_type_schema(schema, "str")

        if str_schema is None:
            return schema

        str_schema.update(
            cs.no_info_wrap_validator_function(
                self.pattern_error_wrapper,
                cs.str_schema(
                    pattern=self.pattern.regexp if self.pattern else None,
                    strip_whitespace=True,
                    coerce_numbers_to_str=True,
                ),
            ),
        )

        schema = cs.no_info_before_validator_function(
            (coerce_nonish_to_default if self.has_default else coerce_nonish_to_none),
            schema,
            serialization=cs.plain_serializer_function_ser_schema(
                serialize_none_to_empty_str
            ),
        )

        return schema

    def pattern_error_wrapper(self, v: str, handler: t.Any):
        """
        Catch "string_pattern_mismatch" validation error to raise another error with
        the custom pattern error message
        """
        if not self.pattern:
            return handler(v)
        try:
            return handler(v)
        except ValidationError as err:
            pattern_error = next(
                (e for e in err.errors() if e["type"] == "string_pattern_mismatch"),
                None,
            )
            if pattern_error:
                raise PydanticCustomError(
                    "string_pattern_mismatch", str(self.pattern.error)
                )
            raise err
