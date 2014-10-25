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
import time

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

    # Run hook
    hook_callback('backup', [backup_dir])

    #TODO: Compress & encrypt

    msignals.display(m18n.n('backup_completed'), 'success')
