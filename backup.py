# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_backup.py

    Manage backups
"""
import os
import sys
import json
import errno
import time
import shutil

from moulinette.core import MoulinetteError

def backup_backup():
    """
    Create an encrypted backup tarball

    """
    from yunohost.hook import hook_callback

    backup_dirname = int(time.time())
    backup_dir = "/home/yunohost.backup/tmp/%s" % backup_dirname

    # Create directory
    try: os.listdir(backup_dir)
    except OSError: os.makedirs(backup_dir)
    os.system('chmod 755 /home/yunohost.backup /home/yunohost.backup/tmp')
    os.system('chown -hR admin: %s' % backup_dir)

    # Add app's backup hooks
    try:
        for app_id in os.listdir('/etc/yunohost/apps'):
            hook = '/etc/yunohost/apps/'+ app_id +'/scripts/backup'
            with open(hook, 'r') as f:
                hook_add(app_id, hook)
    except IOError:
        pass

    # Run hook
    hook_callback('backup', [backup_dir])

    #TODO: Compress & encrypt

    msignals.display(m18n.n('backup_complete'), 'success')


def backup_restore(path):
    """
    Restore from an encrypted backup tarball

    Keyword argument:
        path -- Path to the restore directory

    """
    from yunohost.tools import tools_postinstall
    from yunohost.hook import hook_add
    from yunohost.hook import hook_callback

    path = os.path.abspath(path)

    try:
        with open("%s/yunohost/current_host" % path, 'r') as f:
            domain = f.readline().rstrip()
    except IOError:
        raise MoulinetteError(errno.EINVAL, m18n.n('invalid_restore_package'))

    #TODO Decrypt & extract tarball

    try:
        with open('/etc/yunohost/installed') as f:
            raise MoulinetteError(errno.EINVAL, m18n.n('yunohost_already_installed'))
    except IOError:
        tools_postinstall(domain, 'yunohost', True)

    # Add app's restore hooks
    try:
        for app_id in os.listdir('/etc/yunohost/apps'):
            hook = '/etc/yunohost/apps/'+ app_id +'/scripts/restore'
            with open(hook, 'r') as f:
                hook_add(app_id, hook)
    except IOError:
        pass

    # Run hook
    hook_callback('restore', [path])

    msignals.display(m18n.n('restore_complete'), 'success')


