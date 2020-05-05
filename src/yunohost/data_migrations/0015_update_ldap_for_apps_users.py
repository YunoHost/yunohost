import time
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_yaml

from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')

class MyMigration(Migration):
    """
        Update the LDAP DB to be able to store apps' user in LDAP
    """

    required = True

    def remove_if_exists(self, target):

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        try:
            objects = ldap.search(target + ",dc=yunohost,dc=org")
        # ldap search will raise an exception if no corresponding object is found >.> ...
        except Exception as e:
            logger.debug("%s does not exist, no need to delete it" % target)
            return

        objects.reverse()
        for o in objects:
            for dn in o["dn"]:
                dn = dn.replace(",dc=yunohost,dc=org", "")
                logger.debug("Deleting old object %s ..." % dn)
                try:
                    ldap.remove(dn)
                except Exception as e:
                    raise YunohostError("migration_0011_failed_to_remove_stale_object", dn=dn, error=e)


    def run(self):

        logger.info(m18n.n("migration_0015_update_LDAP_database"))

        from yunohost.utils.ldap import _get_ldap_interface
        ldap = _get_ldap_interface()

        ldap_map = read_yaml('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml')

        try:
            self.remove_if_exists('ou=apps')

            attr_dict = ldap_map['parents']['ou=apps']
            ldap.add('ou=apps', attr_dict)

            attr_dict = ldap_map['children']['ou=users,ou=apps']
            ldap.add('ou=users,ou=apps', attr_dict)

            attr_dict = ldap_map['children']['ou=groups,ou=apps']
            ldap.add('ou=groups,ou=apps', attr_dict)

        except Exception as e:
            raise YunohostError("migration_0011_LDAP_update_failed", error=e)

        logger.info(m18n.n("migration_0015_done"))
