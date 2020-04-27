from moulinette.utils.log import getActionLogger
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):

    "Migrate from official.json to apps.json (outdated, replaced by migration 13)"

    def run(self):
        logger.info("This migration is oudated and doesn't do anything anymore. The migration 13 will handle this instead.")
        pass
