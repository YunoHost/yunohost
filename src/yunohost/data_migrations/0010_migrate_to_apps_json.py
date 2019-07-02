import os

from moulinette.utils.log import getActionLogger
from yunohost.app import app_fetchlist, app_removelist, _read_appslist_list, APPSLISTS_JSON
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')

BASE_CONF_PATH = '/home/yunohost.conf'
BACKUP_CONF_DIR = os.path.join(BASE_CONF_PATH, 'backup')
APPSLISTS_BACKUP = os.path.join(BACKUP_CONF_DIR, "appslist_before_migration_to_unified_list.json")


class MyMigration(Migration):

    "Migrate from official.json to apps.json"

    def migrate(self):

        # Backup current app list json
        os.system("cp %s %s" % (APPSLISTS_JSON, APPSLISTS_BACKUP))

        # Remove all the deprecated lists
        lists_to_remove = [
            "app.yunohost.org/list.json",       # Old list on old installs, alias to official.json
            "app.yunohost.org/official.json",
            "app.yunohost.org/community.json",
            "labriqueinter.net/apps/labriqueinternet.json",
            "labriqueinter.net/internetcube.json"
        ]

        appslists = _read_appslist_list()
        for appslist, infos in appslists.items():
            if infos["url"].split("//")[-1] in lists_to_remove:
                app_removelist(name=appslist)

        # Replace by apps.json list
        app_fetchlist(name="yunohost",
                      url="https://app.yunohost.org/apps.json")

    def backward(self):

        if os.path.exists(APPSLISTS_BACKUP):
            os.system("cp %s %s" % (APPSLISTS_BACKUP, APPSLISTS_JSON))
