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
    Create a backup local archive

    Keyword arguments:
        ignore_apps -- Do not backup apps

    """
    from yunohost.hook import hook_add
    from yunohost.hook import hook_callback

    timestamp = int(time.time())
    tmp_dir = "%s/tmp/%s" % (backup_path, timestamp)

    # Initialize backup info
    info = {
        'created_at': timestamp,
        'apps': {},
    }

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

    # Add apps backup hook
    if not ignore_apps:
        from yunohost.app import app_info
        try:
            for app_id in os.listdir('/etc/yunohost/apps'):
                hook = '/etc/yunohost/apps/'+ app_id +'/scripts/backup'
                if os.path.isfile(hook):
                    hook_add(app_id, hook)

                    # Add app info
                    i = app_info(app_id)
                    info['apps'][app_id] = {
                        'version': i['version'],
                    }
                else:
                    logger.warning("unable to find app's backup hook '%s'", hook)
                    msignals.display(m18n.n('unbackup_app', app_id),
                                     'warning')
        except IOError as e:
            logger.info("unable to add apps backup hook: %s", str(e))

    # Run hooks
    msignals.display(m18n.n('backup_running_hooks'))
    hook_callback('backup', [tmp_dir])

    # Create backup info file
    with open("%s/info.json" % tmp_dir, 'w') as f:
        f.write(json.dumps(info))

    # Create the archive
    msignals.display(m18n.n('backup_creating_archive'))
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
                                 archive_file, archives_path)
                tar = None
        else:
            logger.exception("unable to open the archive '%s' for writing",
                             archive_file)
        if tar is None:
            raise MoulinetteError(errno.EIO, m18n.n('backup_archive_open_failed'))
    tar.add(tmp_dir, arcname='')
    tar.close()

    # Copy info file and remove temporary directory
    os.system('mv %s/info.json %s/%s.info.json' %
                  (tmp_dir, archives_path, timestamp))
    os.system('rm -rf %s' % tmp_dir)

    msignals.display(m18n.n('backup_complete'), 'success')


def backup_restore(name, ignore_apps=False, force=False):
    """
    Restore from a local backup archive

    Keyword argument:
        name -- Name of the local backup archive
        ignore_apps -- Do not restore apps
        force -- Force restauration on an already installed system

    """
    from yunohost.hook import hook_add
    from yunohost.hook import hook_callback

    # Retrieve and open the archive
    archive_file = backup_info(name)['path']
    try:
        tar = tarfile.open(archive_file, "r:gz")
    except:
        logger.exception("unable to open the archive '%s' for reading",
                         archive_file)
        raise MoulinetteError(errno.EIO, m18n.n('backup_archive_open_failed'))

    # Check temporary directory
    tmp_dir = "%s/tmp/%s" % (backup_path, name)
    if os.path.isdir(tmp_dir):
        logger.warning("temporary directory for restoration '%s' already exists",
                       tmp_dir)
        os.system('rm -rf %s' % tmp_dir)

    # Extract the tarball
    msignals.display(m18n.n('backup_extracting_archive'))
    tar.extractall(tmp_dir)
    tar.close()

    # Retrieve backup info
    try:
        with open("%s/info.json" % tmp_dir, 'r') as f:
            info = json.load(f)
    except IOError:
        logger.error("unable to retrieve backup info from '%s/info.json'",
                     tmp_dir)
        raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))
    else:
        logger.info("restoring from backup '%s' created on %s", name,
                    time.ctime(info['created_at']))

    # Retrieve domain from the backup
    try:
        with open("%s/yunohost/current_host" % tmp_dir, 'r') as f:
            domain = f.readline().rstrip()
    except IOError:
        logger.error("unable to retrieve domain from '%s/yunohost/current_host'",
                     tmp_dir)
        raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))

    # Check if YunoHost is installed
    if os.path.isfile('/etc/yunohost/installed'):
        msignals.display(m18n.n('yunohost_already_installed'), 'warning')
        if not force:
            try:
                # Ask confirmation for restoring
                i = msignals.prompt(m18n.n('restore_confirm_yunohost_installed',
                                           answers='y/N'))
            except NotImplemented:
                pass
            else:
                if i == 'y' or i == 'Y':
                    force = True
            if not force:
                raise MoulinetteError(errno.EEXIST, m18n.n('restore_failed'))
    else:
        from yunohost.tools import tools_postinstall
        logger.info("executing the post-install...")
        tools_postinstall(domain, 'yunohost', True)

    # Add apps restore hook
    if not ignore_apps:
        for app_id in info['apps'].keys():
            hook = "/etc/yunohost/apps/%s/scripts/restore" % app_id
            if os.path.isfile(hook):
                hook_add(app_id, hook)
                logger.info("app '%s' will be restored", app_id)
            else:
                msignals.display(m18n.n('unrestore_app', app_id), 'warning')

    # Run hooks
    msignals.display(m18n.n('restore_running_hooks'))
    hook_callback('restore', [tmp_dir])

    # Remove temporary directory
    os.system('rm -rf %s' % tmp_dir)

    msignals.display(m18n.n('restore_complete'), 'success')


def backup_list():
    """
    List available local backup archives

    """
    result = []

    try:
        # Retrieve local archives
        archives = os.listdir(archives_path)
    except IOError as e:
        logging.info("unable to iterate over local archives: %s", str(e))
    else:
        # Iterate over local archives
        for f in archives:
            try:
                name = f[:f.rindex('.tar.gz')]
            except ValueError:
                continue
            result.append(name)

    return { 'archives': result }

def backup_info(name):
    """
    Get info about a local backup archive

    Keyword arguments:
        name -- Name of the local backup archive

    """
    archive_file = '%s/%s.tar.gz' % (archives_path, name)
    if not os.path.isfile(archive_file):
        logger.error("no local backup archive found at '%s'", archive_file)
        raise MoulinetteError(errno.EIO, m18n.n('backup_archive_name_unknown'))

    info_file = "%s/%s.info.json" % (archives_path, name)
    try:
        with open(info_file) as f:
            # Retrieve backup info
            info = json.load(f)
    except:
        # TODO: Attempt to extract backup info file from tarball
        logger.exception("unable to retrive backup info file '%s'",
                         info_file)
        raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))

    return {
        'path': archive_file,
        'created_at': time.strftime(m18n.n('format_datetime_short'),
                                    time.gmtime(info['created_at'])),
        'apps': info['apps'],
    }
