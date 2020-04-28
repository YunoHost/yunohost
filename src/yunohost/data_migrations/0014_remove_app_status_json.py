import os

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json

from yunohost.tools import Migration
from yunohost.app import app_setting, APPS_SETTING_PATH

logger = getActionLogger('yunohost.migration')

class MyMigration(Migration):

    """Remove legacy app status.json files"""

    def run(self):

        apps = os.listdir(APPS_SETTING_PATH)

        for app in apps:
            status_file = os.path.join(APPS_SETTING_PATH, app, "status.json")
            if not os.path.exists(status_file):
                continue

            try:
                status = read_json(status_file)
                current_revision = status.get("remote", {}).get("revision", "?")
                app_setting(app, 'current_revision', current_revision)
            except Exception as e:
                logger.warning("Could not migrate status.json from app %s: %s", (app, str(e)))
            else:
                os.system("rm %s" % status_file)
