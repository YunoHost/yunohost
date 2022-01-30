import subprocess
import time

from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.utils.legacy import LEGACY_SETTINGS, translate_legacy_settings_to_configpanel_settings
from yunohost.settings import settings_set

logger = getActionLogger("yunohost.migration")

SETTINGS_PATH = "/etc/yunohost/settings.json"

class MyMigration(Migration):

    "Migrate old global settings to the new ConfigPanel global settings"

    dependencies = ["migrate_to_bullseye"]

    def run(self):
        if not os.path.exists(SETTINGS_PATH):
            return

        try:
            old_settings = json.load(open(SETTINGS_PATH))
        except Exception as e:
            raise YunohostError("global_settings_cant_open_settings", reason=e)

        for key, value in old_settings.items():
            if key in LEGACY_SETTINGS:
                settings_set(key=key, value=value)
