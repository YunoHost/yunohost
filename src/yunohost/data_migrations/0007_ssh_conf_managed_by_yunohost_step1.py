import os
import re

from shutil import copyfile

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import mkdir, rm

from yunohost.tools import Migration
from yunohost.service import _run_service_command
from yunohost.regenconf import regen_conf
from yunohost.settings import settings_set
from yunohost.utils.error import YunohostError

logger = getActionLogger('yunohost.migration')

SSHD_CONF = '/etc/ssh/sshd_config'


class MyMigration(Migration):

    """
    This is the first step of a couple of migrations that ensure SSH conf is
    managed by YunoHost (even if the "from_script" flag is present, which was
    previously preventing it from being managed by YunoHost)

    The goal of this first (automatic) migration is to make sure that the
    sshd_config is managed by the regen-conf mechanism.

    If the from_script flag exists, then we keep the current SSH conf such that it
    will appear as "manually modified" to the regenconf.

    In step 2 (manual), the admin will be able to choose wether or not to actually
    use the recommended configuration, with an appropriate disclaimer.
    """

    def migrate(self):

        # Check if deprecated DSA Host Key is in config
        dsa_rgx = r'^[ \t]*HostKey[ \t]+/etc/ssh/ssh_host_dsa_key[ \t]*(?:#.*)?$'
        dsa = False
        for line in open(SSHD_CONF):
            if re.match(dsa_rgx, line) is not None:
                dsa = True
                break
        if dsa:
            settings_set("service.ssh.allow_deprecated_dsa_hostkey", True)

        # Here, we make it so that /etc/ssh/sshd_config is managed
        # by the regen conf (in particular in the case where the
        # from_script flag is present - in which case it was *not*
        # managed by the regenconf)
        # But because we can't be sure the user wants to use the
        # recommended conf, we backup then restore the /etc/ssh/sshd_config
        # right after the regenconf, such that it will appear as
        # "manually modified".
        if os.path.exists('/etc/yunohost/from_script'):
            rm('/etc/yunohost/from_script')
            copyfile(SSHD_CONF, '/etc/ssh/sshd_config.bkp')
            regen_conf(names=['ssh'], force=True)
            copyfile('/etc/ssh/sshd_config.bkp', SSHD_CONF)

        # Restart ssh and backward if it fail
        if not _run_service_command('restart', 'ssh'):
            self.backward()
            raise YunohostError("migration_0007_cancel")

    def backward(self):

        # We don't backward completely but it should be enough
        copyfile('/etc/ssh/sshd_config.bkp', SSHD_CONF)
        if not _run_service_command('restart', 'ssh'):
            raise YunohostError("migration_0007_cannot_restart")
