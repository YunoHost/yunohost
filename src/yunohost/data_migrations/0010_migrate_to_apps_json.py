from moulinette.utils.log import getActionLogger
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):

    "Migrate from official.json to apps.json (outdated, replaced by migration 12)"

    def migrate(self):

        logger.info("This is migration is oudated and doesn't do anything anymore. The migration 12 will handle this instead.")
        pass

    def backward(self):

        pass
