
import os
import shutil

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json

from yunohost.tools import Migration
from yunohost.app import (_initialize_apps_catalog_system,
                          _update_apps_catalog,
                          APPS_CATALOG_CACHE,
                          APPS_CATALOG_CONF)

logger = getActionLogger('yunohost.migration')

LEGACY_APPS_CATALOG_CONF = '/etc/yunohost/appslists.json'
LEGACY_APPS_CATALOG_CONF_BACKUP = LEGACY_APPS_CATALOG_CONF + ".old"


class MyMigration(Migration):

    "Migrate to the new future-proof apps catalog system"

    def run(self):

        if not os.path.exists(LEGACY_APPS_CATALOG_CONF):
            logger.info("No need to do anything")

        # Destroy old lecacy cache
        if os.path.exists(APPS_CATALOG_CACHE):
            shutil.rmtree(APPS_CATALOG_CACHE)

        # and legacy cron
        if os.path.exists("/etc/cron.daily/yunohost-fetch-appslists"):
            os.remove("/etc/cron.daily/yunohost-fetch-appslists")

        # Backup the legacy file
        try:
            legacy_catalogs = read_json(LEGACY_APPS_CATALOG_CONF)
            # If there's only one catalog, we assume it's just the old official catalog
            # Otherwise, warn the (power-?)users that they should migrate their old catalogs manually
            if len(legacy_catalogs) > 1:
                logger.warning("It looks like you had additional apps_catalog in the configuration file %s! YunoHost now uses %s instead, but it won't migrate your custom apps_catalog. You should do this manually. The old file has been backuped in %s." % (LEGACY_APPS_CATALOG_CONF, APPS_CATALOG_CONF, LEGACY_APPS_CATALOG_CONF_BACKUP))
        except Exception as e:
            logger.warning("Unable to parse the legacy conf %s (error : %s) ... migrating anyway" % (LEGACY_APPS_CATALOG_CONF, str(e)))

        if os.path.exists(LEGACY_APPS_CATALOG_CONF):
            os.rename(LEGACY_APPS_CATALOG_CONF, LEGACY_APPS_CATALOG_CONF_BACKUP)

        _initialize_apps_catalog_system()
        _update_apps_catalog()
