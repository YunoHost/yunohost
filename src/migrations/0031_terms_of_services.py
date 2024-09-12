from moulinette import Moulinette, m18n
from yunohost.tools import Migration

import logging
logger = logging.getLogger("yunohost.migration")


class MyMigration(Migration):
    "Display new terms of services to admins"

    mode = "manual"

    def run(self):
        pass

    @property
    def disclaimer(self):
        return m18n.n("migration_0031_terms_of_services") + "\n\n" + m18n.n("tos_postinstall_acknowledgement")
