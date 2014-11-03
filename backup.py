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
import tarfile

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

backup_path   = '/home/yunohost.backup'
archives_path = '%s/archives' % backup_path

logger = getActionLogger('yunohost.backup')


def backup_create(ignore_apps=False):
    """
    Backup and create a local archive

    Keyword arguments:
        ignore_apps -- Do not backup apps

    """
    from yunohost.hook import hook_add
    from yunohost.hook import hook_callback

    timestamp = int(time.time())
    tmp_dir = "%s/tmp/%s" % (backup_path, timestamp)

    # Create temporary directory
    if os.path.isdir(tmp_dir):
        logger.warning("temporary directory for backup '%s' already exists", tmp_dir)
        os.system('rm -rf %s' % tmp_dir)
    try:
        os.mkdir(tmp_dir, 0750)
    except OSError:
        # Create temporary directory recursively
        os.makedirs(tmp_dir, 0750)
        os.system('chown -hR admin: %s' % backup_path)
    else:
        os.system('chown -hR admin: %s' % tmp_dir)

    # Add app's backup hooks
    if not ignore_apps:
        try:
            for app_id in os.listdir('/etc/yunohost/apps'):
                hook = '/etc/yunohost/apps/'+ app_id +'/scripts/backup'
                if os.path.isfile(hook):
                    hook_add(app_id, hook)
                else:
                    logger.warning("unable to find app's backup hook '%s'", hook)
                    msignals.display(m18n.n('unbackup_app', app_id),
                                     'warning')
        except IOError as e:
            logger.info("unable to add app's backup hooks: %s", str(e))

    # Run hooks
    m18n.display(m18n.n('backup_running_hooks'))
    hook_callback('backup', [tmp_dir])

    # TODO: Add a backup info file

    # Create the archive
    m18n.display(m18n.n('backup_creating_archive'))
    archive_file = "%s/%s.tar.gz" % (archives_path, timestamp)
    try:
        tar = tarfile.open(archive_file, "w:gz")
    except:
        tar = None

        # Create the archives directory and retry
        if not os.path.isdir(archives_path):
            os.mkdir(archives_path, 0750)
            try:
                tar = tarfile.open(archive_file, "w:gz")
            except:
                logger.exception("unable to open the archive '%s' for writing " \
                                 "after creating directory '%s'",
                                 archive_file, archive_dir)
                tar = None
        else:
            logger.exception("unable to open the archive '%s' for writing",
                             archive_file)
        if tar is None:
            raise MoulinetteError(errno.EIO, m18n.n('backup_archive_open_failed'))
    tar.add(tmp_dir, arcname='')
    tar.close()

    # Remove temporary directory
    os.system('rm -rf %s' % tmp_dir)

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
            #raise MoulinetteError(errno.EINVAL, m18n.n('yunohost_already_installed'))
            msignals.display(m18n.n('restoring_installed_system'), 'warning')
            time.sleep(5)
            pass
    except IOError:
        tools_postinstall(domain, 'yunohost', True)

    # Add app's restore hooks
    try:
        for app_id in os.listdir('/etc/yunohost/apps'):
            hook = '/etc/yunohost/apps/'+ app_id +'/scripts/restore'
            if os.path.isfile(hook):
                hook_add(app_id, hook)
            else:
                msignals.display(m18n.n('unrestore_app', app_id),
                                 'warning')
    except IOError:
        pass

    # Run hook
    hook_callback('restore', [path])

    msignals.display(m18n.n('restore_complete'), 'success')


