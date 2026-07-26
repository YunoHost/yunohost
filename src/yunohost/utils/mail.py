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


from .process import check_output


def get_pending_mails_nb() -> int:
    """
    Return number of pending mails in queue
    """
    command = (
        'postqueue -p | grep -v "Mail queue is empty" | grep -c "^[A-Z0-9]" || true'
    )
    output = check_output(command)
    return int(output)
