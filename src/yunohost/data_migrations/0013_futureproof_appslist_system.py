
import os
import shutil

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json

from yunohost.tools import Migration
from yunohost.app import (_initialize_appslists_system,
                          _update_appslist,
                          APPSLISTS_CACHE,
                          APPSLISTS_CONF)

logger = getActionLogger('yunohost.migration')

LEGACY_APPSLISTS_CONF = '/etc/yunohost/appslists.json'
LEGACY_APPSLISTS_CONF_BACKUP = LEGACY_APPSLISTS_CONF + ".old"


class MyMigration(Migration):

    "Migrate to the new future-proof appslist system"

    def migrate(self):

        if not os.path.exists(LEGACY_APPSLISTS_CONF):
            logger.info("No need to do anything")

        # Destroy old lecacy cache
        if os.path.exists(APPSLISTS_CACHE):
            shutil.rmtree(APPSLISTS_CACHE)

        # Backup the legacy file
        try:
            legacy_list = read_json(LEGACY_APPSLISTS_CONF)
            # If there's only one list, we assume it's just the old official list
            # Otherwise, warn the (power-?)users that they should migrate their old list manually
            if len(legacy_list) > 1:
                logger.warning("It looks like you had additional appslist in the configuration file %s! YunoHost now uses %s instead, but it won't migrate your custom appslist. You should do this manually. The old file has been backuped in %s." % (LEGACY_APPSLISTS_CONF, APPSLISTS_CONF, LEGACY_APPSLISTS_CONF_BACKUP))
        except Exception as e:
            logger.warning("Unable to parse the legacy conf %s (error : %s) ... migrating anyway" % (LEGACY_APPSLISTS_CONF, str(e)))

        os.rename(LEGACY_APPSLISTS_CONF, LEGACY_APPSLISTS_CONF_BACKUP)

        _initialize_appslists_system()
        _update_appslist()
