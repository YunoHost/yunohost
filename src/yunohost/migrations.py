# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2016 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_domain.py

    Migration framework for our data modifications.
"""

import os
import re


def migrations_list(auth):
    """
    List migrations
    """

    migrations = {"migrations": []}

    try:
        import yunohost_migrations
    except ImportError:
        return migrations

    for migration in filter(lambda x: re.match("^\d+_.+\.py$", x), os.listdir(yunohost_migrations.__path__[0])):
        migration = migration[:-len(".py")]
        migrations["migrations"].append({
            "number": migration.split("_", 1)[0],
            "name": migration.split("_", 1)[1],
        })

    migrations["migrations"] = sorted(migrations["migrations"], key=lambda x: x["number"])

    return migrations
