#!/usr/bin/env python3

from pathlib import Path
from typing import Any, Callable, ParamSpec, TypeVar

Param = ParamSpec("Param")
RetType = TypeVar("RetType")


class CachedFile:
    def __init__(self, file: str | Path) -> None:
        """Cache the result of this function based on the file passed to the decorator.

        If the file is modified, the cache is invalidated and the function is called again.
        """

        if isinstance(file, str):
            file = Path(file)

        self.file = file
        self.mtime_ns = 0
        self.ctime_ns = 0
        self.result: Any = None

    def __call__(self, func: Callable[Param, RetType]) -> Callable[Param, RetType]:
        def wrapper(*args: Param.args, **kwargs: Param.kwargs) -> RetType:
            stat = self.file.stat()
            if (
                stat.st_mtime_ns != self.mtime_ns
                or stat.st_ctime_ns != self.ctime_ns
                or self.result is None
            ):
                self.mtime_ns = stat.st_mtime_ns
                self.ctime_ns = stat.st_ctime_ns
                self.result = func(*args, **kwargs)
            return self.result

        return wrapper
