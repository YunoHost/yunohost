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

from moulinette import m18n

from yunohost.tools import Migration

logger = logging.getLogger("yunohost.migration")


class MyMigration(Migration):
    "Display new terms of services to admins"

    mode = "manual"

    def run(self):
        pass

    @property
    def disclaimer(self):
        return (
            m18n.n("migration_0031_terms_of_services")
            + "\n\n"
            + m18n.n("tos_postinstall_acknowledgement")
        )
