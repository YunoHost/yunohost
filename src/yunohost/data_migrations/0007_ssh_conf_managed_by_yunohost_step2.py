import re

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.service import service_regen_conf, _get_conf_hashes, \
                             _calculate_hash
from yunohost.settings import settings_set, settings_get

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    """
    In this second step, the admin is asked if it's okay to use
    the recommended SSH configuration - which also implies
    disabling deprecated DSA key.

    This has important implications in the way the user may connect
    to its server (key change, and a spooky warning might be given
    by SSH later)

    A disclaimer explaining the various things to be aware of is
    shown - and the user may also choose to skip this migration.
    """

    def migrate(self):
        settings_set("service.ssh._deprecated_dsa_hostkey", False)
        service_regen_conf(names=['ssh'], force=True)

    def backward(self):

        raise MoulinetteError(m18n.n("migration_0007_backward_impossible"))

    @property
    def mode(self):

        # If the conf is already up to date
        # and no DSA key is used, then we're good to go
        # and the migration can be done automatically
        # (basically nothing shall change)
        ynh_hash = _get_conf_hashes('ssh')
        if '/etc/ssh/sshd_config' in ynh_hash:
            ynh_hash = ynh_hash['/etc/ssh/sshd_config']
        current_hash = _calculate_hash('/etc/ssh/sshd_config')
        dsa = settings_get("service.ssh._deprecated_dsa_hostkey")
        if ynh_hash == current_hash and not dsa:
            return "auto"

        return "manual"

    @property
    def disclaimer(self):

        if self.mode == "auto":
            return None

        # Detect key things to be aware of before enabling the
        # recommended configuration
        dsa = False
        ports = []
        root_login = []
        port_rgx = r'^[ \t]*Port[ \t]+(\d+)[ \t]*(?:#.*)?$'
        root_rgx = r'^[ \t]*PermitRootLogin[ \t]([^# \t]*)[ \t]*(?:#.*)?$'
        dsa_rgx = r'^[ \t]*HostKey[ \t]+/etc/ssh/ssh_host_dsa_key[ \t]*(?:#.*)?$'
        for line in open('/etc/ssh/sshd_config'):

            ports = ports + re.findall(port_rgx, line)

            root_login = root_login + re.findall(root_rgx, line)

            if not dsa and re.match(dsa_rgx, line) is not None:
                dsa = True

        if len(ports) == 0:
            ports = ['22']

        port = ports != ['22']

        root_user = root_login and root_login[-1] != 'no'

        # Build message
        message = m18n.n("migration_0007_general_warning")

        if port:
            message += "\n\n" + m18n.n("migration_0007_port")

        if root_user:
            message += "\n\n" + m18n.n("migration_0007_root")

        if dsa:
            message += "\n\n" + m18n.n("migration_0007_dsa")

        if port or root_user or dsa:
            message += "\n\n" + m18n.n("migration_0007_risk")
        else:
            message += "\n\n" + m18n.n("migration_0007_no_risk")

        return message
