from moulinette.utils.log import getActionLogger
from yunohost.app import app_fetchlist, app_removelist
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')

class MyMigration(Migration):

    "Migrate from official.json to apps.json"

    def migrate(self):

        # Remove official.json list
        app_removelist(name="yunohost")

        # Replace by apps.json list
        app_fetchlist(name="yunohost",
            url="https://app.yunohost.org/apps.json")

    def backward(self):

        # Remove apps.json list
        app_removelist(name="yunohost")

        # Replace by official.json list
        app_fetchlist(name="yunohost",
            url="https://app.yunohost.org/official.json")
