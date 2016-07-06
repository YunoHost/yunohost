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
import json
from importlib import import_module
from moulinette.utils.log import getActionLogger


MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations_state.json"

logger = getActionLogger('yunohost.migrations')


def migrations_list(auth):
    """
    List migrations
    """

    migrations = {"migrations": []}

    try:
        import data_migrations
    except ImportError:
        return migrations

    # XXX error handling on __path__[0] and listdir
    for migration in filter(lambda x: re.match("^\d+_.+\.py$", x), os.listdir(data_migrations.__path__[0])):
        migration = migration[:-len(".py")]
        migrations["migrations"].append({
            "number": migration.split("_", 1)[0],
            "name": migration.split("_", 1)[1],
        })

    migrations["migrations"] = sorted(migrations["migrations"], key=lambda x: x["number"])

    return migrations


def migrations_migrate(auth):
    """
    Perform migrations
    """

    if not os.path.exists(MIGRATIONS_STATE_PATH):
        state = {"last_runned_migration": None}
    else:
        # XXX error handling
        state = json.load(open(MIGRATIONS_STATE_PATH))

    migrations = []

    try:
        import data_migrations
    except ImportError:
        return

    # XXX error handling
    for migration in filter(lambda x: re.match("^\d+_.+\.py$", x), os.listdir(data_migrations.__path__[0])):
        number = migration.split("_", 1)[0]

        # skip already runnned migrations
        if state["last_runned_migration"] is not None and\
           state["last_runned_migration"]["number"] <= number:
            continue

        migration = migration[:-len(".py")]
        migrations.append({
            "number": number,
            "name": migration.split("_", 1)[1],
            "module": import_module("yunohost.data_migrations.{}".format(migration)), # XXX error handling
        })

    migrations = sorted(migrations, key=lambda x: x["number"])

    for migration in migrations:
        logger.info("Running migration {number} {name}...".format(**migration))
        migration["module"].Migration().migrate() # XXX error handling
