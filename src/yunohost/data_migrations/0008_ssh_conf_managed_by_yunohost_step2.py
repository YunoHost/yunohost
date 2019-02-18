import os
import re

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import chown

from yunohost.tools import Migration
from yunohost.regenconf import _get_conf_hashes, _calculate_hash
from yunohost.regenconf import regen_conf
from yunohost.settings import settings_set, settings_get
from yunohost.utils.error import YunohostError
from yunohost.backup import ARCHIVES_PATH


logger = getActionLogger('yunohost.migration')

SSHD_CONF = '/etc/ssh/sshd_config'


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
        settings_set("service.ssh.allow_deprecated_dsa_hostkey", False)
        regen_conf(names=['ssh'], force=True)

        # Update local archives folder permissions, so that
        # admin can scp archives out of the server
        if os.path.isdir(ARCHIVES_PATH):
            chown(ARCHIVES_PATH, uid="admin", gid="root")

    def backward(self):

        raise YunohostError("migration_0008_backward_impossible")

    @property
    def mode(self):

        # If the conf is already up to date
        # and no DSA key is used, then we're good to go
        # and the migration can be done automatically
        # (basically nothing shall change)
        ynh_hash = _get_conf_hashes('ssh').get(SSHD_CONF, None)
        current_hash = _calculate_hash(SSHD_CONF)
        dsa = settings_get("service.ssh.allow_deprecated_dsa_hostkey")
        if ynh_hash == current_hash and not dsa:
            return "auto"

        return "manual"

    @property
    def disclaimer(self):

        if self.mode == "auto":
            return None

        # Detect key things to be aware of before enabling the
        # recommended configuration
        dsa_key_enabled = False
        ports = []
        root_login = []
        port_rgx = r'^[ \t]*Port[ \t]+(\d+)[ \t]*(?:#.*)?$'
        root_rgx = r'^[ \t]*PermitRootLogin[ \t]([^# \t]*)[ \t]*(?:#.*)?$'
        dsa_rgx = r'^[ \t]*HostKey[ \t]+/etc/ssh/ssh_host_dsa_key[ \t]*(?:#.*)?$'
        for line in open(SSHD_CONF):

            ports = ports + re.findall(port_rgx, line)

            root_login = root_login + re.findall(root_rgx, line)

            if not dsa_key_enabled and re.match(dsa_rgx, line) is not None:
                dsa_key_enabled = True

        custom_port = ports != ['22'] and ports != []
        root_login_enabled = root_login and root_login[-1] != 'no'

        # Build message
        message = m18n.n("migration_0008_general_disclaimer")

        if custom_port:
            message += "\n\n" + m18n.n("migration_0008_port")

        if root_login_enabled:
            message += "\n\n" + m18n.n("migration_0008_root")

        if dsa_key_enabled:
            message += "\n\n" + m18n.n("migration_0008_dsa")

        if custom_port or root_login_enabled or dsa_key_enabled:
            message += "\n\n" + m18n.n("migration_0008_warning")
        else:
            message += "\n\n" + m18n.n("migration_0008_no_warning")

        return message
