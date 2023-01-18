from __future__ import (
    annotations,
)  # Enable self reference a class in its own method arguments

from typing import Annotated, Generic, TypeVar


T = TypeVar("T")


class PrivateParam(Generic[T]):
    ...


Private = Annotated[T, PrivateParam[T]]
