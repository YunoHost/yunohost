import os
import re

from shutil import copyfile

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import mkdir, rm

from yunohost.tools import Migration
from yunohost.service import service_regen_conf, _get_conf_hashes, \
                             _calculate_hash, _run_service_command
from yunohost.settings import settings_set

logger = getActionLogger('yunohost.migration')

SSHD_CONF = '/etc/ssh/sshd_config'


class MyMigration(Migration):
    """
    Ensure SSH conf is managed by YunoHost, reapply initial change and setup an
    extension dir
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
            settings_set("service.ssh._deprecated_dsa_hostkey", True)

        # Create sshd_config.d dir
        if not os.path.exists(SSHD_CONF + '.d'):
            mkdir(SSHD_CONF + '.d', 0755, uid='root', gid='root')

        # Manage SSHd in all case
        if os.path.exists('/etc/yunohost/from_script'):
            rm('/etc/yunohost/from_script')
            copyfile(SSHD_CONF, '/etc/ssh/sshd_config.bkp')
            service_regen_conf(names=['ssh'], force=True)
            copyfile('/etc/ssh/sshd_config.bkp', SSHD_CONF)

        # If custom conf, add 'Include' instruction
        ynh_hash = _get_conf_hashes('ssh')[SSHD_CONF]
        current_hash = _calculate_hash(SSHD_CONF)
        include_rgx = r'^[ \t]*Include[ \t]+sshd_config\.d/\*[ \t]*(?:#.*)?$'
        if ynh_hash != current_hash:

            add_include = False
            for line in open(SSHD_CONF):
                if re.match(include_rgx, line) is not None:
                    add_include = True
                    break

            if add_include:
                with open(SSHD_CONF, "a") as conf:
                    conf.write('Include sshd_config.d/*')

        # Restart ssh and backward if it fail
        if not _run_service_command('restart', 'ssh'):
            self.backward()
            raise MoulinetteError(m18n.n("migration_0006_cancel"))

    def backward(self):
        # We don't backward completely but it should be enough

        copyfile('/etc/ssh/sshd_config.bkp', SSHD_CONF)
        if not _run_service_command('restart', 'ssh'):
            raise MoulinetteError(m18n.n("migration_0006_cannot_restart"))
