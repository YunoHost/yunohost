import re

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.service import service_regen_conf, _get_conf_hashes, \
                             _calculate_hash

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    "Reset SSH conf to the YunoHost one"

    def migrate(self):
        service_regen_conf(names=['ssh'], force=True)

    def backward(self):

        raise MoulinetteError(m18n.n("migration_0007_backward_impossible"))

    @property
    def mode(self):

        # Avoid having a super long disclaimer
        ynh_hash = _get_conf_hashes('ssh')
        if '/etc/ssh/sshd_config' in ynh_hash:
            ynh_hash = ynh_hash['/etc/ssh/sshd_config']
        current_hash = _calculate_hash('/etc/ssh/sshd_config')
        if ynh_hash == current_hash:
            return "auto"

        return "manual"

    @property
    def disclaimer(self):

        if self.mode == "auto":
            return None

        # Detect major risk to migrate to the new configuration
        dsa = False
        ports = []
        root_login = []
        port_rgx = r'^[ \t]*Port[ \t]+(\d+)[ \t]*(?:#.*)?$'
        root_rgx = r'^[ \t]*PermitRootLogin[ \t]([^# \t]*)[ \t]*(?:#.*)?$'
        dsa_rgx = r'^[ \t]*HostKey[ \t]+/etc/ssh/ssh_host_dsa_key[ \t]*(?:#.*)?$'
        for line in open('/etc/ssh/sshd_config'):

            ports = ports + re.findall(port_rgx, line)

            root_login = root_login + re.findall(root_rgx, line)

            if not dsa and re.match(dsa_rgx, line):
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
