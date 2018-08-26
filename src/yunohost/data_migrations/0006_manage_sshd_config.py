import subprocess
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

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    """
    Ensure SSH conf is managed by YunoHost, reapply initial change and setup an
    extension dir
    """

    def migrate(self):

        # Create sshd_config.d dir
        if not os.path.exists('/etc/ssh/sshd_config.d'):
            mkdir('/etc/ssh/sshd_config.d', 0755, uid='root', gid='root')

        # Manage SSHd in all case
        if os.path.exists('/etc/yunohost/from_script'):
            rm('/etc/yunohost/from_script')
            copyfile('/etc/ssh/sshd_config', '/etc/ssh/sshd_config.bkp')
            service_regen_conf(names=['ssh'], force=True)
            copyfile('/etc/ssh/sshd_config.bkp', '/etc/ssh/sshd_config')

        # If custom conf, add 'Include' instruction
        ynh_hash = _get_conf_hashes('ssh')['/etc/ssh/sshd_config']
        current_hash = _calculate_hash('/etc/ssh/sshd_config')
        if ynh_hash != current_hash:

            add_include = False
            include_rgx = r'^[ \t]*Include[ \t]+sshd_config\.d/\*[ \t]*(?:#.*)?$'
            for line in open('/etc/ssh/sshd_config'):
                if re.match(include_rgx, line) is not None:
                    add_include = True
                    break

            if add_include:
                with open("/etc/ssh/sshd_config", "a") as conf:
                    conf.write('Include sshd_config.d/*')

        # Restart ssh and backward if it fail
        if not _run_service_command('restart', 'ssh'):
            self.backward()
            raise MoulinetteError(m18n.n("migration_0006_cancel"))


    def backward(self):
        # We don't backward completely but it should be enough

        copyfile('/etc/ssh/sshd_config.bkp', '/etc/ssh/sshd_config')
        if not _run_service_command('restart', 'ssh'):
            raise MoulinetteError(m18n.n("migration_0006_cannot_restart"))

