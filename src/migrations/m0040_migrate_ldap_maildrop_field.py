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

from yunohost.utils.ldap import _get_ldap_interface
from ..tools import Migration

logger = logging.getLogger("yunohost.migration")


class MyMigration(Migration):
    "Migrate LDAP maildrop field from username to user mail"

    mode = "auto"

    def migrate_ldap_maildrop(self) -> None:
        ldap = _get_ldap_interface()
        users_infos = ldap.search(
            "ou=users",
            "(objectclass=mailAccount)",
            [
                "uid",
                "mail",
                "maildrop"
            ],
        )

        for infos in users_infos:
            username = infos['uid'][0]
            logger.debug("Migrating maildrop field for user %s", username)
            # FIXME Big fat WARNING: currently we put the user email in the last maildrop entry
            # this is a temporary workaround to fix this discussion
            # https://github.com/YunoHost/yunohost/pull/2341#discussion_r3879745312
            # As soon as we have implemented the main email as the external email
            # we will put again the main email in the first entry of the maildrop
            new_maildrop = set(infos["maildrop"][1:] + [infos['mail'][0]])
            ldap.update(f"uid={username},ou=users", {"maildrop": new_maildrop})

    def run(self):
        self.migrate_ldap_maildrop()

    def run_after_system_restore(self):
        self.run()
