import os
import re
from importlib import import_module

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.filesystem import read_json
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.preactions.checkmigrations')

# FIXME this is a duplicate from tools.py
MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations_state.json"

def main(function, arguements):
    # Allow to do any action about migrations
    if 'tools_' in function or '_list' in function or 'service_' in function:
        return

    try:
        import yunohost.data_migrations
    except ImportError:
        # not data migrations present, return
        return

    migrations_path = yunohost.data_migrations.__path__[0]

    if not os.path.exists(migrations_path):
        logger.warn(m18n.n('migrations_cant_reach_migration_file', migrations_path))
        return

    last_migration = -1
    if os.path.exists(MIGRATIONS_STATE_PATH):
        last_migration = read_json(MIGRATIONS_STATE_PATH)['last_run_migration']['number']

    migrations = sorted(filter(lambda x: re.match("^\d+_[a-zA-Z0-9_]+\.py$", x), os.listdir(migrations_path)), reverse=True)

    # Check for each migration which are not done if it's required
    for migration_file in migrations:
        migration_id = migration_file[:-len(".py")]
        number, name = migration_id.split("_", 1)

        # Skype all migration already done
        if int(number) <= last_migration:
            return

        logger.debug(m18n.n('migrations_loading_migration',
                            number=number, name=name))
        try:
            # this is python builtin method to import a module using a name, we
            # use that to import the migration as a python object so we'll be
            # able to run it in the next loop
            module = import_module("yunohost.data_migrations.{}".format(migration_id))
            migration =  module.MyMigration(migration_id)
        except Exception:
            import traceback
            traceback.print_exc()

            raise YunohostError('migrations_error_failed_to_load_migration',
                                  number=number, name=name)

        if migration.required:
            raise YunohostError('migrations_required')
