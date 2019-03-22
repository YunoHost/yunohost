from moulinette.utils.log import getActionLogger
from yunohost.app import app_fetchlist, app_removelist, _read_appslist_list
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')

class MyMigration(Migration):

    "Migrate from official.json to apps.json"

    def migrate(self):

        # Remove all the deprecated lists
        lists_to_remove = [
            "https://app.yunohost.org/official.json",
            "https://app.yunohost.org/community.json",
            "https://labriqueinter.net/apps/labriqueinternet.json"
        ]

        appslists = _read_appslist_list()
        for appslist, infos in appslists.items():
            if infos["url"] in lists_to_remove:
                app_removelist(name=appslist)

        # Replace by apps.json list
        app_fetchlist(name="yunohost",
                      url="https://app.yunohost.org/apps.json")

    def backward(self):

        # Remove apps.json list
        app_removelist(name="yunohost")

        # Replace by official.json list
        app_fetchlist(name="yunohost",
            url="https://app.yunohost.org/official.json")
