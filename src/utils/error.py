#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from typing import Any

from moulinette import m18n
from moulinette.core import MoulinetteAuthenticationError, MoulinetteError


class YunohostError(MoulinetteError):
    http_code = 500

    """
    Yunohost base exception

    The (only?) main difference with MoulinetteError being that keys
    are translated via m18n.n (namespace) instead of m18n.g (global?)
    """

    def __init__(
        self,
        key: str | dict[str, str],
        raw_msg: bool = False,
        log_ref: str | None = None,
        error_details: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.key = key  # Saving the key is useful for unit testing
        self.kwargs = kwargs  # Saving the key is useful for unit testing
        self.log_ref = log_ref
        self.error_details = error_details
        if raw_msg:
            msg = key
        else:
            msg = m18n.n(key, *args, **kwargs)

        super(YunohostError, self).__init__(msg, raw_msg=True)

    def content(self):
        if self.log_ref:
            return {"error": self.strerror, "log_ref": self.log_ref}
        elif self.error_details:
            return {"error": self.strerror, "details": self.error_details}
        else:
            return super().content()


class YunohostValidationError(YunohostError):
    http_code = 400

    def content(self):
        return {"error": self.strerror, "error_key": self.key, **self.kwargs}


class YunohostAuthenticationError(MoulinetteAuthenticationError):
    pass
