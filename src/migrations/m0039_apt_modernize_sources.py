#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
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
import subprocess

from ..tools import Migration

logger = logging.getLogger("yunohost.migration")


class MyMigration(Migration):
    "Modernize the Apt source files to Deb822"

    introduced_in_version = "13.0"
    mode = "auto"

    def run(self) -> None:
        subprocess.run(["apt", "modernize-sources"], input=b"y", check=True)
