#!/usr/bin/env python3

from typing import Any, Callable


def recursive_apply(function: Callable, data: Any) -> Any:
    if isinstance(data, dict):  # FIXME: hashable?
        return {key: recursive_apply(value, function) for key, value in data.items()}

    if isinstance(data, list):  # FIXME: iterable?
        return [recursive_apply(value, function) for value in data]

    return function(data)
