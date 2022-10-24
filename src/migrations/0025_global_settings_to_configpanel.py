import os

from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json, write_to_yaml

from yunohost.tools import Migration
from yunohost.utils.legacy import translate_legacy_settings_to_configpanel_settings

logger = getActionLogger("yunohost.migration")

SETTINGS_PATH = "/etc/yunohost/settings.yml"
OLD_SETTINGS_PATH = "/etc/yunohost/settings.json"


class MyMigration(Migration):

    "Migrate old global settings to the new ConfigPanel global settings"

    dependencies = ["migrate_to_bullseye"]

    def run(self):
        if not os.path.exists(OLD_SETTINGS_PATH):
            return

        try:
            old_settings = read_json(OLD_SETTINGS_PATH)
        except Exception as e:
            raise YunohostError(f"Can't open setting file : {e}", raw_msg=True)

        settings = {
            translate_legacy_settings_to_configpanel_settings(k).split('.')[-1]: v["value"]
            for k, v in old_settings.items()
        }

        if settings.get("smtp_relay_host"):
            settings["smtp_relay_enabled"] = True

        # Here we don't use settings_set() from settings.py to prevent
        # Questions to be asked when one run the migration from CLI.
        write_to_yaml(SETTINGS_PATH, settings)
