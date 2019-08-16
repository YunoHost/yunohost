import os

from moulinette import m18n
from moulinette.utils.log import getActionLogger

from moulinette.utils.filesystem import read_file
from yunohost.service import _get_services, _save_services
from yunohost.regenconf import _update_conf_hashes, REGEN_CONF_FILE

from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    """
    Decouple the regen conf mechanism from the concept of services
    """

    def migrate(self):

        if "conffiles" not in read_file("/etc/yunohost/services.yml") \
           or os.path.exists(REGEN_CONF_FILE):
            logger.warning(m18n.n("migration_0009_not_needed"))
            return

        # For all services
        services = _get_services()
        for service, infos in services.items():
            # If there are some conffiles (file hashes)
            if "conffiles" in infos.keys():
                # Save them using the new regen conf thingy
                _update_conf_hashes(service, infos["conffiles"])
                # And delete the old conffile key from the service infos
                del services[service]["conffiles"]

        # (Actually save the modification of services)
        _save_services(services)

    def backward(self):

        pass
