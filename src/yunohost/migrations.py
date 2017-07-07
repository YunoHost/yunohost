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
    List existing migrations
    """

    migrations = {"migrations": []}

    for migration in _get_migrations_list():
        migrations["migrations"].append({
            "number": migration.split("_", 1)[0],
            "name": migration.split("_", 1)[1],
        })

    return migrations


def migrations_migrate(auth):
    """
    Perform migrations
    """
    state = migrations_state()

    migrations = []

    # loading all migrations that haven't already runned
    for migration in migrations_list()::
        # skip already runnned migrations
        if state["last_runned_migration"] is not None and\
           int(migration["number"]) <= int(state["last_runned_migration"]["number"]):
            continue

        migrations.append({
            "number": migration["number"],
            "name": migration["name"]
            # this is python buildin method to import a module using a name, we use that to import the migration
            # has a python object so we'll be able to run it in the next lop
            "module": import_module("yunohost.data_migrations.{}".format(migration)), # XXX error handling
        })

    migrations = sorted(migrations, key=lambda x: x["number"])

    # run migrations in order
    for migration in migrations:
        logger.info("Running migration {number} {name}...".format(**migration))

        try:
            migration["module"].MyMigration().migrate()
        except Exception as e:
            # migration failed, let's stop here but still update state because
            # we managed to run the previous ones
            logger.error("Migration {number} {name} has failed with exception {exception}, abording".format(exception=e, **migration), exec_info=1)
            break

        # update the state to include the latest runned migration
        state["last_runned_migration"] = {
            "number": migration["number"],
            "name": migration["name"],
        }

    try:
        state = json.dumps(state, indent=4)
    except Exception as e:
        raise MoulinetteError(
            errno.EINVAL,
                "Unable to serialize migration state ('{state}') in json because of exception {exception}".format(
                exception=e,
                state=state,
            )
        )

    try:
        open(MIGRATIONS_STATE_PATH, "w").write(state)
    except Exception as e:
        raise MoulinetteError(
            errno.EINVAL,
                "Unable to save migration state ('{state}') at {path} because of exception {exception}".format(
                exception=e,
                path=MIGRATIONS_STATE_PATH,
                state=state,
            )
        )


def migrations_state():
    if not os.path.exists(MIGRATIONS_STATE_PATH):
        return {"last_runned_migration": None}
    else:
        try:
            return json.load(open(MIGRATIONS_STATE_PATH))
        except Exception as e:
            raise MoulinetteError(
                errno.EINVAL,
                "Unable to load state json file located at {path}, exception: {exception)".format(
                    exception=e,
                    path=MIGRATIONS_STATE_PATH
                )
            )


def _get_migrations_list():
    migrations = []

    try:
        import data_migrations
    except ImportError:
        # not data migrations present, return empty list
        return migrations

    migrations_path = data_migrations.__path__[0]

    if not os.path.exists(migrations_path):
        logger.warn("Can't access migrations files at path %s".format(migrations_path))
        return migrations

    for migration in filter(lambda x: re.match("^\d+_[a-zA-Z0-9_]+\.py$", x), os.listdir(migrations_path)):
        migrations.append(migration[:-len(".py")])

    return sorted(migrations)


class Migration(object):
    def migrate(self):
        self.forward()

    def forward(self):
        raise NotImplementedError()

    def backward(self):
        pass
