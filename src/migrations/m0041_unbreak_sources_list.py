#!/usr/bin/env python3
#
# Copyright (c) 2026 YunoHost Contributors
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

import logging
from pathlib import Path
import re

from ..tools import Migration

logger = logging.getLogger("yunohost.migration")


class MyMigration(Migration):
    """Fix sources.list mangled by migration to Trixie """

    introduced_in_version = "13.0"
    dependencies = ["migrate_to_trixie"]

    def unbreak_sources_list(self):
        sources_list_d = Path("/etc/apt/sources.list.d")
        dot_list: list[Path] = [*sources_list_d.glob("*.list")]
        if (main_sources := Path("/etc/apt/sources.list")).exists():
            dot_list.append(main_sources)

        def patch_list_line(line: str) -> str:
            """
            - fixes up invalid result of 0036 that squased consecutive `deb` lines together
            - also fixes up `deb-src` that became `deb -src`
            """

            deb_re = r"^(?P<first>deb.*)(?P<second>(?P<deb>deb)\s+(?P<options>\[[^\]]*\])?\s*(?P<uri>[^\s]*)\s*(?P<suite>[^\s]*)\s*(?P<components>.*))$"
            if not (match := re.match(deb_re, line)):
                return line

            first = match.groupdict().get("first")
            second = match.groupdict().get("second")

            if first is not None and second is not None:
                first = first.replace("deb -src", "deb-src")
                second = second.replace("deb -src", "deb-src")
                line = first + "\n" + second

            return line

        for file in dot_list:
            lines = file.read_text().splitlines()
            file.write_text("\n".join(patch_list_line(line) for line in lines))

    def run(self):
        self.unbreak_sources_list()
