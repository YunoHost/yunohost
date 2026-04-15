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

import gettext
import os
from pathlib import Path
from typing import Any

from moulinette.interfaces.cli import get_locale

from moulinette import m18n as moulinette_m18n

DEFAULT_LOCALE = "en"


class M18N:
    def __init__(self) -> None:
        self.default_locale = DEFAULT_LOCALE
        moulinette_m18n.default_locale = self.default_locale
        moulinette_m18n.n = self.n

    def set_locales_dir(self, path: Path | str) -> None:
        self.locales_dir = Path(path)
        gettext.bindtextdomain(domain="yunohost", localedir=self.locales_dir)
        gettext.textdomain(domain="yunohost")
        moulinette_m18n.set_locales_dir(str(path))
        moulinette_m18n.set_locale(get_locale())

    def _set_locale(self) -> None:
        # For now, Moulinette sets the locale, we need to ensure it's set in
        # our context too. gettext uses the environment variable LANGUAGE.
        locale = moulinette_m18n.locale
        if locale in ["C", "", None]:
            locale = self.default_locale
        self.locale = locale
        os.environ["LANGUAGE"] = self.locale

    def g(self, key: str, *args: str, **kwargs: str) -> str:
        """
        g returns global translations, e.g from Moulinette scope
        """
        return moulinette_m18n.g(key, *args, **kwargs)

    def n(self, key: str, *args: Any, **kwargs: Any) -> str:
        self._set_locale()
        message = gettext.gettext(key)
        # TODO: try except formatting
        formatted = message.format(*args, **kwargs)
        return formatted

    def key_exists(self, key: str) -> bool:
        return gettext.gettext(key) != key


m18n = M18N()


def _value_for_locale(values: str | dict[str, str]) -> str:
    """
    Return proper value for current locale

    Keyword arguments:
        values -- A dict of values associated to their locale

    Returns:
        An utf-8 encoded string

    """
    if not isinstance(values, dict):
        return values

    for lang in [m18n.locale, m18n.default_locale]:
        try:
            return values[lang]
        except KeyError:
            continue

    # Fallback to first value
    return list(values.values())[0]
