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

""" yunohost_migrations.py

    Migration framework for our data modifications.
"""

import os
import re
import json
import errno
from importlib import import_module
from moulinette.utils.log import getActionLogger
from moulinette.core import MoulinetteError


MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations_state.json"

logger = getActionLogger('yunohost.migrations')


def migrations_list():
    """
    List existing migrations
    """

    migrations = {"migrations": []}

    for migration in _get_migrations_list():
        migrations["migrations"].append({
            "number": int(migration.split("_", 1)[0]),
            "name": migration.split("_", 1)[1],
            "file_name": migration,
        })

    return migrations


def migrations_migrate(target=None, skip=False):
    """
    Perform migrations
    """

    # state is a datastructure that represent the last run migration
    # it has this form:
    # {
    #     "last_run_migration": {
    #             "number": "00xx",
    #             "name": "some name",
    #         }
    # }
    state = migrations_state()

    last_run_migration_number = state["last_run_migration"]["number"] if state["last_run_migration"] else 0

    migrations = []

    # loading all migrations
    for migration in migrations_list()["migrations"]:
        logger.debug("Loading migration {number} {name}...".format(
            number=migration["number"],
            name=migration["name"],
        ))

        try:
            # this is python builtin method to import a module using a name, we
            # use that to import the migration as a python object so we'll be
            # able to run it in the next loop
            module = import_module("yunohost.data_migrations.{file_name}".format(**migration))
        except Exception:
            import traceback
            traceback.print_exc()

            raise MoulinetteError(errno.EINVAL, "WARNING: failed to load migration {number} {name}".format(
                number=migration["number"],
                name=migration["name"],
            ))
            break

        migrations.append({
            "number": migration["number"],
            "name": migration["name"],
            "module": module,
        })

    migrations = sorted(migrations, key=lambda x: x["number"])

    if not migrations:
        logger.info("No migrations to run.")
        return

    all_migration_numbers = [x["number"] for x in migrations]

    if target is None:
        target = migrations[-1]["number"]

    # validate input, target must be "0" or a valid number
    elif target != 0 and target not in all_migration_numbers:
        raise MoulinetteError(errno.EINVAL, "Invalide number for target argument, available migrations numbers are 0 or {}".format(", ".join(map(str, all_migration_numbers))))

    logger.debug("migration target is {}".format(target))

    # no new migrations to run
    if target == last_run_migration_number:
        logger.warn("no migrations to run")
        return

    logger.debug("last run migration is {}".format(last_run_migration_number))

    # we need to run missing migrations
    if last_run_migration_number < target:
        logger.debug("migrating forward")
        # drop all already run migrations
        migrations = filter(lambda x: x["number"] > last_run_migration_number, migrations)
        mode = "forward"

    # we need to go backward on already run migrations
    elif last_run_migration_number > target:
        logger.debug("migrating backward.")
        # drop all not already run migrations
        migrations = filter(lambda x: x["number"] <= last_run_migration_number, migrations)
        mode = "backward"

    else:  # can't happen, this case is handle before
        raise Exception()

    # effectively run selected migrations
    for migration in migrations:
        if not skip:
            logger.warn("Running migration {number} {name}...".format(**migration))

            try:
                if mode == "forward":
                    migration["module"].MyMigration().migrate()
                elif mode == "backward":
                    migration["module"].MyMigration().backward()
                else:  # can't happen
                    raise Exception("Illegal state for migration: '%s', should be either 'forward' or 'backward'" % mode)
            except Exception as e:
                # migration failed, let's stop here but still update state because
                # we managed to run the previous ones
                logger.error("Migration {number} {name} has failed with exception {exception}, aborting".format(exception=e, **migration), exc_info=1)
                break

        else:  # if skip
            logger.warn("skip migration {number} {name}...".format(**migration))

        # update the state to include the latest run migration
        state["last_run_migration"] = {
            "number": migration["number"],
            "name": migration["name"],
        }

    # special case where we want to go back from the start
    if target == 0:
        state["last_run_migration"] = None

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
                "Unable to save migration state ('{state}') in {path} because of exception {exception}".format(
                exception=e,
                path=MIGRATIONS_STATE_PATH,
                state=state,
            )
        )


def migrations_state():
    """
    Show current migration state
    """
    if not os.path.exists(MIGRATIONS_STATE_PATH):
        return {"last_run_migration": None}
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
