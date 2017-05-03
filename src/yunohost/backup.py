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
import re
import json
import errno
import time
import tarfile
import shutil
import subprocess
import csv
import tempfile
from glob import glob
from collections import OrderedDict

from moulinette.core import MoulinetteError
from moulinette.utils import filesystem
from moulinette.utils.log import getActionLogger

from yunohost.app import (
    app_info, _is_installed, _parse_app_instance_name
)
from yunohost.hook import (
    hook_info, hook_callback, hook_exec, CUSTOM_HOOK_FOLDER
)
from yunohost.monitor import binary_to_human
from yunohost.tools import tools_postinstall

BACKUP_PATH = '/home/yunohost.backup'
ARCHIVES_PATH = '%s/archives' % BACKUP_PATH
APP_MARGIN_SPACE_SIZE = 100
CONF_MARGIN_SPACE_SIZE = 10
POSTINSTALL_ESTIMATE_SPACE_SIZE = 5
logger = getActionLogger('yunohost.backup')




class BackupManager:
    """
    This class collect files to backup in a list and apply one or several backup
    method on it.

    The list contains dict with source and dest properties. The goal of this csv
    is to list all directories and files which need to be backup in this
    archive.  The `source` property is the path of the source (dir or file).
    The `dest` property is the path where it could be placed in the archive.

    The list is filled by app backup scripts and system/user backup hooks.
    Files located in the work_dir are automatically added.

    With this list, "backup methods" are able to apply their backup strategy on
    data listed in it.  It's possible to tar each path (tar methods), to mount
    each dir into the work_dir, to copy each files (copy method) or to call a
    specific hooks (custom method).

    Note: some future backups methods (like borg) are not able to specify a
    different place than the original path. That's why the ynh_restore_file
    helpers use primarily the SOURCE_PATH as argument.

    usage:
        backup_manager = BackupManager(name="mybackup", description="bkp things")

        # Add backup method to apply
        backup_manager.add(BackupMethod.create('copy','/mnt/local_fs'))
        backup_manager.add(BackupMethod.create('tar','/mnt/remote_fs'))

        # Collect hooks and apps files
        backup_manager.collect_files(["data"], ["wordpress"])

        # Apply backup methods
        backup_manager.backup()

    """

    def __init__(self, name=None, description='', work_dir=None):
        """
        name: string The name of this backup (without spaces)
        description: string A description for this future backup archive
        work_dir: None|string A path where prepare the archive
        """
        self.description = description or ''
        self.created_at = int(time.time())
        self.apps_return = {}
        self.hooks_return = {}
        self.methods = []
        self.paths_to_backup = []
        self.size_details = {
            'hooks':{},
            'apps':{}
        }

        # Define backup name
        if not name:
            name = self._define_backup_name()

        self.name = name
        self.work_dir = work_dir
        if self.work_dir is None:
            self.work_dir = os.path.join(BACKUP_PATH, 'tmp', name)
            self.bindable = True
        else:
            self.bindable = False
        self._init_work_dir()

    @property
    def info(self):
        return {
            'description': self.description,
            'created_at': self.created_at,
            'size': self.size,
            'size_details': self.size_details,
            'apps': self.apps_return,
            'hooks': self.hooks_return
        }

    def __repr__(self):
        return json.dumps(self.info)

    def add(self, method):
        self.methods.append(method)

    def collect_files(self, hooks=[], apps=[]):
        """
        Collect all files to backup
        hooks: list of system part which backup hooks should be executed.
        If hooks is an empty list, it will backup all hooks. If it's None,
        backup nothing

        apps: list of apps which backup script should be executed.
        If apps is an empty list, it will backup all apps. If it's None,
        backup nothing.
        """
        self._collect_hooks_files(hooks)

        self._collect_apps_files(apps)

        # Check if something has been saved
        if not self.hooks_return and not self.apps_return:
            filesystem.rm(self.work_dir, True, True)
            raise MoulinetteError(errno.EINVAL, m18n.n('backup_nothings_done'))

        # Add unlisted files from backup tmp dir
        self._add_to_list_to_backup('backup.csv')
        self._add_to_list_to_backup('info.json')
        if len(self.apps_return) > 0:
            self._add_to_list_to_backup('apps')
        if os.path.isdir(os.path.join(self.work_dir, 'conf')):
            self._add_to_list_to_backup('conf')
        if os.path.isdir(os.path.join(self.work_dir, 'data')):
            self._add_to_list_to_backup('data')

        # Write CSV file
        self._write_csv()

        # Calculate total size
        self._compute_backup_size()

        # Create backup info file
        with open("%s/info.json" % self.work_dir, 'w') as f:
            f.write(json.dumps(self.info))

    def backup(self):
        """
        Apply backup methods
        """

        for method in self.methods:
            logger.info(m18n.n('backup_applying_method_' + method.method_name))
            method.mount_and_backup(self)
            logger.info(m18n.n('backup_method_' + method.method_name + '_finished'))

    def _get_env_var(self):
        """ Define environment variable for hooks call """
        env_var = {}

        _, tmp_csv = tempfile.mkstemp(prefix='backupcsv_')
        env_var['YNH_BACKUP_DIR'] = self.work_dir
        env_var['YNH_BACKUP_CSV'] = tmp_csv
        return env_var

    @property
    def _is_temp_work_dir(self):
        return self.work_dir == os.path.join(BACKUP_PATH, 'tmp', self.name)

    def _define_backup_name(self):
        """ Define backup name """
        # FIXME: case where this name already exist
        return time.strftime('%Y%m%d-%H%M%S')

    def _init_work_dir(self):
        """ Initialize preparation directory """

        if not os.path.isdir(self.work_dir):
            filesystem.mkdir(self.work_dir, 0750, parents=True, uid='admin')
        elif self.bindable:
            logger.debug("temporary directory for backup '%s' already exists",
                         self.work_dir)
            if not self.clean():
                raise MoulinetteError(
                    errno.EIO, m18n.n('backup_output_directory_not_empty'))

    def _write_csv(self):
        """
        Write the backup list into a CSV

        The goal of this csv is to list all directories and files which need to
        be backup in this archive.  For the moment, this CSV contains 2 columns.
        The first column `source` is the path of the source (dir or file).  The
        second `dest` is the path where it could be placed in the archive.

        This CSV is filled by app backup scripts and system/user backup hooks.
        Files in the work_dir are automatically added.

        With this CSV, "backup methods" are able to apply their backup strategy
        on data listed in it.  It's possible to tar each path (tar methods), to
        mount each dir into the work_dir, to copy each files (copy methods) or
        to call a specific hooks.

        Note: some future backups methods (like borg) are not able to specify a
        different place than the original path. That's why the ynh_restore_file
        helpers use primarily the SOURCE_PATH as argument.
        """
        self.csv_path = os.path.join(self.work_dir, 'backup.csv')
        try:
            self.csv_file = open(self.csv_path, 'a')
            self.fieldnames = ['source', 'dest']
            self.csv = csv.DictWriter(self.csv_file, fieldnames=self.fieldnames,
                                      quoting=csv.QUOTE_ALL)
        except (IOError, OSError, csv.Error):
            logger.error(m18n.n('backup_csv_creation_failed'))

        for row in self.paths_to_backup:
            try:
                self.csv.writerow(row)
            except csv.Error:
                logger.error(m18n.n('backup_csv_addition_failed'))
        self.csv_file.close()

    def _import_to_list_to_backup(self, tmp_csv):
        """ Commit collected path from system or app hooks """
        _call_for_each_path(self, BackupManager._add_to_list_to_backup, tmp_csv)

    def _add_to_list_to_backup(self, source, dest=None):
        """
        Mark file or directory to backup

        source: source path to backup
        dest: destination path in the archive. If dest end by a slash the
        basename of source is added

        usage:
        self._add_to_list_to_backup('/var/www/wordpress', 'sources')
        => wordpress dir will be move and rename in sources

        self._add_to_list_to_backup('/var/www/wordpress', 'sources/')
        => wordpress dir will be put inside sources/ dir and won't be renamed

        """
        if dest is None:
            dest = source
            source = os.path.join(self.work_dir, source)
        if dest.endswith("/"):
            dest = os.path.join(dest, os.path.basename(source))
        self.paths_to_backup.append({'source': source, 'dest': dest})

    def _collect_hooks_files(self, hooks=[]):
        """
        Prepare backup for each selected system part
        It concerns hooks in data/hooks/backup/ (system hooks) and in
        /etc/yunohost/hooks.d/backup/ (user hooks)
        """

        if hooks is None:
            return

        # Check hooks availibility
        hooks_filtered = set()
        if hooks:
            for hook in hooks:
                try:
                    hook_info('backup', hook)
                except:
                    logger.error(m18n.n('backup_hook_unknown', hook=hook))
                else:
                    hooks_filtered.add(hook)

        logger.info(m18n.n('backup_running_hooks'))

        # Execute hooks
        env_dict = self._get_env_var()
        ret = hook_callback('backup', hooks_filtered, args=[self.work_dir],
                            env=env_dict, chdir=self.work_dir)

        if len(ret['succeed']) > 0:
            self._import_to_list_to_backup(env_dict["YNH_BACKUP_CSV"])
            self.hooks_return = ret['succeed']

            # Save relevant restoration hooks
            tmp_hooks_dir = 'hooks/restore/'
            filesystem.mkdir(os.path.join(self.work_dir, tmp_hooks_dir),
                             0750, True, uid='admin')
            for h in ret['succeed'].keys():
                try:
                    i = hook_info('restore', h)
                except:
                    logger.warning(m18n.n('restore_hook_unavailable', hook=h),
                                   exc_info=1)
                else:
                    for f in i['hooks']:
                        self._add_to_list_to_backup(f['path'], tmp_hooks_dir)
        else:
            # FIXME: support hooks failure
            pass

    def _collect_apps_files(self, apps=[]):
        """ Prepare backup for each selected apps """

        if apps is None:
            return
        # Filter applications to backup
        apps_list = set(os.listdir('/etc/yunohost/apps'))
        apps_filtered = set()
        if apps:
            for a in apps:
                if a not in apps_list:
                    logger.warning(m18n.n('unbackup_app', app=a))
                else:
                    apps_filtered.add(a)
        else:
            apps_filtered = apps_list

        for app_instance_name in apps_filtered:
            self._collect_app_files(app_instance_name)

    def _collect_app_files(self, app_instance_name):
        app_setting_path = os.path.join('/etc/yunohost/apps/',
                                        app_instance_name)

        # Check if the app has a backup and restore script
        app_script = os.path.join(app_setting_path, 'scripts/backup')
        app_restore_script = os.path.join(app_setting_path, 'scripts/restore')
        if not os.path.isfile(app_script):
            logger.warning(m18n.n('unbackup_app', app=app_instance_name))
            return
        elif not os.path.isfile(app_restore_script):
            logger.warning(m18n.n('unrestore_app', app=app_instance_name))

        tmp_app_dir = os.path.join('apps/', app_instance_name)
        tmp_app_bkp_dir = os.path.join(self.work_dir, tmp_app_dir, 'backup')
        logger.info(m18n.n('backup_running_app_script', app=app_instance_name))
        try:
            # Prepare backup directory for the app
            filesystem.mkdir(tmp_app_bkp_dir, 0750, True, uid='admin')
            settings_dir = os.path.join(tmp_app_dir, 'settings')

            # Copy app backup script in a temporary folder and execute it
            _, tmp_script = tempfile.mkstemp(prefix='backup_')
            subprocess.call(['install', '-Dm555', app_script, tmp_script])

            # Prepare env. var. to pass to script
            app_id, app_instance_nb = _parse_app_instance_name(
                app_instance_name)
            env_dict = self._get_env_var()
            env_dict["YNH_APP_ID"] = app_id
            env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
            env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
            env_dict["YNH_APP_BACKUP_DIR"] = tmp_app_bkp_dir

            hook_exec(tmp_script, args=[tmp_app_bkp_dir, app_instance_name],
                      raise_on_error=True, chdir=tmp_app_bkp_dir, env=env_dict)

            self._import_to_list_to_backup(env_dict["YNH_BACKUP_CSV"])
            self._add_to_list_to_backup(app_setting_path, settings_dir)
        except:
            logger.exception(m18n.n('backup_app_failed', app=app_instance_name))

            # Cleaning app backup directory
            abs_tmp_app_dir = os.path.join(self.work_dir, tmp_app_dir)
            shutil.rmtree(abs_tmp_app_dir, ignore_errors=True)

            # Remove added path from csv
            # TODO
        else:
            # Add app info
            i = app_info(app_instance_name)
            self.apps_return[app_instance_name] = {
                'version': i['version'],
                'name': i['name'],
                'description': i['description'],
            }
        finally:
            filesystem.rm(tmp_script, force=True)
            filesystem.rm(env_dict["YNH_BACKUP_CSV"], force=True)

    def _compute_backup_size(self):
        """
        Compute backup global size and details size for each apps and hooks
        """
        # FIXME Database dump will be loaded, so dump should use almost the
        # double of their space
        # FIXME Some archive will set up dependencies, those are not in this
        # size info
        self.size = 0
        for hook_key in self.hooks_return:
            self.size_details['hooks'][hook_key] = 0
        for app_key in self.apps_return:
            self.size_details['apps'][app_key] = 0

        for row in self.paths_to_backup:
            if row['dest'] != "info.json":
                size = int(subprocess.check_output(['du', '-sb', row['source']])
                           .split()[0].decode('utf-8'))

                # Add size to apps details
                splitted_dest = row['dest'].split('/')
                category = splitted_dest[0]
                if category == 'apps':
                    for app_key in self.apps_return:
                        if row['dest'].startswith('apps/'+app_key):
                            self.size_details['apps'][app_key] += size
                            break
                # OR Add size to the correct hooks details
                elif category == 'data' or category == 'conf':
                    for hook_key in self.hooks_return:
                        if row['dest'].startswith(hook_key.replace('_', '/')):
                            self.size_details['hooks'][hook_key] += size
                            break

                self.size += size

        return self.size


class BackupMethod(object):
    """
    Abstract class
    """
    def __init__(self, repo = None):
        self.repo = ARCHIVES_PATH if repo is None else repo

    @property
    def method_name(self):
        raise MoulinetteError(errno.EINVAL, m18n.n('backup_abstract_method'))

    @property
    def name(self):
        return self.manager.name

    @property
    def work_dir(self):
        return self.manager.work_dir

    def need_mount(self):
        return False

    def mount_and_backup(self, backup_manager):
        self.manager = backup_manager
        if self.need_mount():
            self._mount_csv_listed_files()

        try:
            self.backup()
        finally:
            self.clean()

    def mount(self, restore_manager):
        self.manager = restore_manager

    def clean(self):
        """ Umount subdir of work_dir """
        if self.need_mount():
            if self._recursive_umount(self.work_dir) > 0:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('backup_cleaning_failed'))

        if self.manager._is_temp_work_dir:
            filesystem.rm(self.work_dir, True, True)

    def _recursive_umount(directory):

        mount_lines = subprocess.check_output("mount").split("\n")

        points_to_umount = [ line.split(" ")[2]
                            for line in mount_lines
                                if  len(line) >= 3
                                and line.split(" ")[2].startswith(directory) ]
        ret = 0
        for point in reversed(points_to_umount):
            ret = subprocess.call(["umount", point])
            if ret != 0:
                ret = 1
                logger.warning(m18n.n('backup_cleaning_failed', point))
                continue

        return ret

    def _check_is_enough_free_space(self):
        """ Check free space in output directory at first """
        backup_size = self.manager.size
        cmd = ['df', '--block-size=1', '--output=avail', self.repo]
        avail_output = subprocess.check_output(cmd).split()
        if len(avail_output) < 2 or int(avail_output[1]) < backup_size:
            logger.debug('not enough space at %s (free: %s / needed: %d)',
                         self.repo, avail_output[1], backup_size)
            raise MoulinetteError(errno.EIO, m18n.n(
                'not_enough_disk_space', path=self.repo))

    def _mount_csv_listed_files(self):
        """ Mount all csv src in their related path """
        for path in self.manager.paths_to_backup:
            # FIXME io excpetion
            src = path['src']
            dest = os.path.join(self.work_dir, path['dest'])
            filesystem.mkdir(os.path.dirname(dest), parent=True)
            if self.manager.bindable:
                if os.path.isdir(src):
                    filesystem.mkdir(dest, parent=True)
                    ret = subprocess.call(["mount", "-r", "--rbind", src, dest])
                    if ret == 0:
                        return
                    else:
                        logger.warning(m18n.n("bind_mouting_disable"))
                        subprocess.call(["mountpoint", "-q", dest,
                                        "&&", "umount", "-R", dest])
                elif os.path.isfile(src) or os.path.islink(src):
                    # os.chdir(os.path.dirname(dest))
                    os.link(src, dest)
                    return
            if os.path.isdir(src) or os.path.ismount(src):
                subprocess.call(["cp", "-a", os.path.join(src, "."), dest])
                shutil.copytree(src, dest, symlinks=True)
            else:
                shutil.copy(src, dest)

    @classmethod
    def create(cls, method, **kwargs):

        if not isinstance(method, basestring):
            methods = []
            for m in method:
                methods.append(BackupMethod.create(m))
            return methods

        bm_class = {
            'copy': CopyBackupMethod,
            'tar':  TarBackupMethod,
            'borg': BorgBackupMethod
        }
        if method in ["copy", "tar", "borg"]:
            return bm_class[method](**kwargs)
        else:
            return CustomBackupMethod(**kwargs)


class CopyBackupMethod(BackupMethod):
    def __init__(self, repo = None):
        super(CopyBackupMethod, self).__init__(repo)

    @property
    def method_name(self):
        return 'copy'

    def backup(self):
        """ Copy prepared files into a dir """
        # Check free space in output
        self._check_is_enough_free_space()

        for path in self.manager.paths_to_backup:
            source = path['source']
            dest = os.path.join(self.repo, path['dest'])
            if source == dest:
                logger.debug("Files already copyed")
                return

            dest_parent = os.path.dirname(dest)
            if not os.path.exists(dest_parent):
                filesystem.mkdir(dest_parent, 0750, True, uid='admin')

            if os.path.isdir(source):
                shutil.copytree(source, dest)
            else:
                shutil.copy(source, dest)

    def mount(self):
        super(CopyBackupMethod, self).mount()

        if not os.path.isdir(self.repo):
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_no_uncompress_archive_dir'))

        filesystem.mkdir(self.work_dir, parent=True)
        ret = subprocess.call(["mount", "-r", "--rbind", self.repo,
                              self.work_dir])
        if ret == 0:
            return
        else:
            logger.warning(m18n.n("bind_mouting_disable"))
            subprocess.call(["mountpoint", "-q", dest,
                            "&&", "umount", "-R", dest])
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_cant_mount_uncompress_archive'))


class TarBackupMethod(BackupMethod):

    def __init__(self, repo=None):
        super(TarBackupMethod, self).__init__(repo)

    @property
    def method_name(self):
        return 'tar'

    def backup(self):
        """ Compress prepared files """
        # Check free space in output
        self._check_is_enough_free_space()

        # Open archive file for writing
        try:
            tar = tarfile.open(self._archive_file, "w:gz")
        except:
            logger.debug("unable to open '%s' for writing",
                         self._archive_file, exc_info=1)
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_archive_open_failed'))

        # Add files to the archive
        try:
            for path in self.manager.paths_to_backup:
                # Add the "source" into the archive and transform the path into
                # "dest"
                tar.add(path['source'], arcname=path['dest'])
            tar.close()
        except IOError:
            logger.error(m18n.n('backup_archive_writing_error'), exc_info=1)
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_creation_failed'))

        # Move info file
        shutil.copy(os.path.join(self.work_dir, 'info.json'),
                    os.path.join(ARCHIVES_PATH, self.name + '.info.json'))

        # If backuped to a non-default location, keep a symlink of the archive
        # to that location
        link = os.path.join(ARCHIVES_PATH, self.name + '.tar.gz')
        if not os.path.isfile(link):
            os.symlink(self._archive_file, link)

    def mount(self, restore_manager):
        """
        Mount the archive. We avoid copy to be able to restore on system without
        too many space.
        """
        super(TarBackupMethod, self).mount(restore_manager)

        # Check the archive can be open
        try:
            tar = tarfile.open(self._archive_file, "r:gz")
        except:
            logger.debug("cannot open backup archive '%s'",
                         self._archive_file, exc_info=1)
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_archive_open_failed'))
        tar.close()

        # Mount the tarball
        ret = subprocess.call(['archivemount', '-o', 'readonly',
                               self._archive_file, self.work_dir])
        if ret != 0:
            logger.debug("cannot mount backup archive '%s'",
                         self._archive_file, exc_info=1)
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_archive_mount_failed'))

    @property
    def _archive_file(self):
        return os.path.join(self.repo, self.name + '.tar.gz')


class BorgBackupMethod(BackupMethod):
    @property
    def method_name(self):
        return 'borg'

    def backup(self):
        """ Backup prepared files with borg """
        super(CopyBackupMethod, self).backup()

        # TODO run borg create command
        raise MoulinetteError(
                errno.EIO, m18n.n('backup_borg_not_implemented'))

    def mount(self, mnt_path):
        raise MoulinetteError(
                errno.EIO, m18n.n('backup_borg_not_implemented'))


class CustomBackupMethod(BackupMethod):

    def __init__(self, repo = None, **kwargs):
        super(CustomBackupMethod, self).__init__(repo)
        self.args = kwargs
        self._need_mount = None

    @property
    def method_name(self):
        return 'borg'

    def need_mount(self):
        ret = hook_callback('backup_method', method,
                            args=self._get_args('need_mount'))
        if ret['succeed']:
            return True
        else:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_custom_need_mount_error'))

    def backup(self):
        """ Apply a hook on prepared files """

        ret = hook_callback('backup_method', method,
                            args=self._get_args('backup'))
        if ret['failed']:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_custom_backup_error'))

    def mount(self, restore_manager):
        super(CustomBackupMethod, self).mount(restore_manager)
        ret = hook_callback('backup_method', method,
                            args=self._get_args('mount'))
        if ret['failed']:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_custom_mount_error'))

    def _get_args(self, action):
        return [action, self.work_dir, self.name, self.repo, self.manager.size,
                self.manager.description]

class RestoreManager:
    """
    BackupArchive represent a past backup.
    Currently it's a tar.gz file, but it could be another kind of archive
    """

    def __init__(self, name, repo=None, method='tar'):
        # Retrieve and open the archive
        self.info = backup_info(name)
        self.archive_path = self.info['path']
        self.name = name
        self.method = BackupMethod.create(method)
        self.result = {
            'apps': [],
            'hooks': {},
        }

    def restore(self, hooks=[], apps=[]):
        """ Restore the archive """

        self._mount()

        try:
            self._check_free_space(hooks, apps)
            self._postinstall_if_needed()
            self._restore_hooks(hooks)
            self._restore_apps(apps)
        finally:
            self.clean()

    def _postinstall_if_needed(self):
        # Check if YunoHost is installed
        if not os.path.isfile('/etc/yunohost/installed'):
            # Retrieve the domain from the backup
            try:
                with open("%s/conf/ynh/current_host" % self.work_dir, 'r') as f:
                    domain = f.readline().rstrip()
            except IOError:
                logger.debug("unable to retrieve current_host from the backup",
                            exc_info=1)
                raise MoulinetteError(errno.EIO,
                                    m18n.n('backup_invalid_archive'))

            logger.debug("executing the post-install...")
            tools_postinstall(domain, 'yunohost', True)

    @property
    def success(self):
        return self.result['hooks'] or self.result['apps']

    def _mount(self, mnt_path=None):
        """
        Mount the archive. We avoid copy to be able to restore on system without
        too many space.
        """

        # Check mount directory
        if mnt_path is None:
            self.work_dir = os.path.join(BACKUP_PATH, "tmp", self.name)
        else:
            self.work_dir = mnt_path

        if os.path.ismount(self.work_dir):
            logger.debug("An already mounting point '%s' already exists",
                         self.work_dir)
            ret = subprocess.call(['umount', self.work_dir])
            if ret == 0:
                subprocess.call(['rmdir', self.work_dir])
                logger.debug("Unmount dir: {}".format(self.work_dir))
            else:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('restore_removing_tmp_dir_failed'))
        elif os.path.isdir(self.work_dir):
            logger.debug("temporary restore directory '%s' already exists",
                         self.work_dir)
            ret = subprocess.call(['rm', '-Rf', self.work_dir])
            if ret == 0:
                logger.debug("Delete dir: {}".format(self.work_dir))
            else:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('restore_removing_tmp_dir_failed'))

        filesystem.mkdir(self.work_dir, parents=True)

        self.method.mount(self)

        self._read_info_files()

    def _compute_needed_space(self, hooks, apps):
        """
        Define needed space to be able to backup
        return:
            size - needed space to backup
            margin - margin to be sure the backup don't fail by missing spaces
        """
        margin = CONF_MARGIN_SPACE_SIZE * 1024 * 1024
        if (hooks == [] and apps == []) or 'size_details' not in self.info:
            size = self.info['size']
            if 'size_details' not in self.info or \
               self.info['size_details']['apps'] != {}:
                margin = APP_MARGIN_SPACE_SIZE * 1024 * 1024
        # Partial restore don't need all backup size
        else:
            size = 0
            if hooks is not None:
                for hook in hooks:
                    size += self.info['size_details']['hooks'][hook]

            # TODO how to know the dependencies size ?
            if apps is not None:
                for app in apps:
                    size += self.info['size_details']['apps'][app]
                    margin = APP_MARGIN_SPACE_SIZE * 1024 * 1024

        if not os.path.isfile('/etc/yunohost/installed'):
            size += POSTINSTALL_ESTIMATE_SPACE_SIZE * 1024 * 1024
        return (size, margin)

    def _check_free_space(self, hooks, apps):
        """ Check available disk space """
        statvfs = os.statvfs(BACKUP_PATH)
        free_space = statvfs.f_frsize * statvfs.f_bavail
        (needed_space, margin) = self._compute_needed_space(hooks, apps)
        if free_space >= needed_space + margin:
            return True
        elif free_space > needed_space:
            # TODO Add --force options to avoid the error raising
            raise MoulinetteError(errno.EIO,
                                  m18n.n('restore_may_be_not_enough_disk_space',
                                  free_space=free_space,
                                  needed_space=needed_space,
                                  margin=margin))
        else:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('restore_not_enough_disk_space',
                                  free_space=free_space,
                                  needed_space=needed_space,
                                  margin=margin))

    def _restore_hooks(self, hooks=[]):
        """ Restore user and system hooks """

        if hooks is None:
            return

        # Filter hooks to execute
        hooks_list = set(self.info['hooks'].keys())
        if hooks:
            def _is_hook_to_restore(h):
                if h in hooks_list:
                    return True
                logger.error(m18n.n('backup_archive_hook_not_exec', hook=h))
                return False
        else:
            def _is_hook_to_restore(h):
                return True
            hooks = hooks_list

        # Check hooks availibility
        hooks_filtered = set()
        for h in hooks:
            if not _is_hook_to_restore(h):
                continue
            try:
                hook_info('restore', h)
            except:
                # If this restore hook doesn't exist, we add it in custom hook
                # FIXME: so if the restore hook exist we use the new one and not
                # the one from backup. So hook should not break compatibility...
                tmp_hooks = glob('{:s}/hooks/restore/*-{:s}'.format(
                    self.work_dir, h))
                if not tmp_hooks:
                    logger.exception(m18n.n('restore_hook_unavailable', hook=h))
                    continue
                # Add restoration hook from the backup to the system
                # FIXME: Refactor hook_add and use it instead
                restore_hook_folder = CUSTOM_HOOK_FOLDER + 'restore'
                filesystem.mkdir(restore_hook_folder, 755, True)
                for f in tmp_hooks:
                    logger.debug("adding restoration hook '%s' to the system "
                                 "from the backup archive '%s'", f,
                                 self.archive_path)
                    shutil.copy(f, restore_hook_folder)
            hooks_filtered.add(h)

        if hooks_filtered:
            logger.info(m18n.n('restore_running_hooks'))
            ret = hook_callback('restore', hooks_filtered, args=[self.work_dir])
            self.result['hooks'] = ret['succeed']

    def _restore_apps(self, apps=[]):

        if apps is None:
            return

        # Filter applications to restore
        apps_list = set(self.info['apps'].keys())
        apps_filtered = set()
        if apps:
            for a in apps:
                if a not in apps_list:
                    logger.error(m18n.n('backup_archive_app_not_found', app=a))
                else:
                    apps_filtered.add(a)
        else:
            apps_filtered = apps_list

        for app_instance_name in apps_filtered:
            self._restore_app(app_instance_name)

    def _restore_app(self, app_instance_name):
        def copytree(src, dst, symlinks=False, ignore=None):
            for item in os.listdir(src):
                s = os.path.join(src, item)
                d = os.path.join(dst, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, symlinks, ignore)
                else:
                    shutil.copy2(s, d)

        tmp_app_dir = os.path.join(self.work_dir, 'apps', app_instance_name)
        tmp_app_bkp_dir = os.path.join(tmp_app_dir, 'backup')

        # Parse app instance name and id
        # TODO: Use app_id to check if app is installed?
        app_id, app_instance_nb = _parse_app_instance_name(app_instance_name)

        # Check if the app is not already installed
        if _is_installed(app_instance_name):
            logger.error(m18n.n('restore_already_installed_app',
                                app=app_instance_name))
            return

        # Check if the app has a restore script
        app_script = os.path.join(tmp_app_dir, 'settings/scripts/restore')
        if not os.path.isfile(app_script):
            logger.warning(m18n.n('unrestore_app', app=app_instance_name))
            return

        tmp_settings_dir = os.path.join(tmp_app_dir, 'settings')
        app_setting_path = os.path.join('/etc/yunohost/apps/',
                                        app_instance_name)
        logger.info(m18n.n('restore_running_app_script', app=app_instance_name))
        try:
            # Copy scripts to a writable temporary folder
            tmp_script_dir = tempfile.mkdtemp(prefix='restore')
            copytree(os.path.join(tmp_settings_dir, 'scripts'), tmp_script_dir)
            filesystem.chmod(tmp_script_dir, 0550, 0550, True)
            filesystem.chown(tmp_script_dir, 'admin', None, True)
            app_script = os.path.join(tmp_script_dir, 'restore')

            # Copy app settings and set permissions
            # TODO: Copy app hooks too
            shutil.copytree(tmp_settings_dir, app_setting_path)
            filesystem.chmod(app_setting_path, 0400, 0400, True)
            filesystem.chown(os.path.join(app_setting_path, 'scripts'),
                             'admin', None, True)

            # Prepare env. var. to pass to script
            env_dict = self._get_env_var()
            env_dict["YNH_APP_ID"] = app_id
            env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
            env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
            env_dict["YNH_APP_BACKUP_DIR"] = tmp_app_bkp_dir

            # Execute app restore script
            hook_exec(app_script, args=[tmp_app_bkp_dir, app_instance_name],
                      raise_on_error=True, chdir=tmp_app_bkp_dir, env=env_dict)
        except:
            logger.exception(m18n.n('restore_app_failed',
                                    app=app_instance_name))

            app_script = os.path.join(tmp_script_dir, 'remove')

            # Setup environment for remove script
            env_dict_remove = {}
            env_dict_remove["YNH_APP_ID"] = app_id
            env_dict_remove["YNH_APP_INSTANCE_NAME"] = app_instance_name
            env_dict_remove["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)

            # Execute remove script
            # TODO: call app_remove instead
            if hook_exec(app_script, args=[app_instance_name],
                         env=env_dict_remove) != 0:
                logger.warning(m18n.n('app_not_properly_removed',
                                      app=app_instance_name))

            # Cleaning app directory
            shutil.rmtree(app_setting_path, ignore_errors=True)

            # TODO Cleaning app hooks
        else:
            self.result['apps'].append(app_instance_name)
        finally:
            # Cleaning temporary scripts directory
            shutil.rmtree(tmp_script_dir, ignore_errors=True)

    def clean(self):
        if self.result['apps']:
            # Quickfix: the old app_ssowatconf(auth) instruction failed due to
            # ldap restore hooks
            os.system('sudo yunohost app ssowatconf')

        if os.path.ismount(self.work_dir):
            ret = subprocess.call(["umount", self.work_dir])
            if ret != 0:
                logger.warning(m18n.n('restore_cleaning_failed'))
        filesystem.rm(self.work_dir, True, True)


    def _read_info_files(self):
        # Retrieve backup info
        info_file = os.path.join(self.work_dir, "info.json")
        try:
            with open(info_file, 'r') as f:
                self.info = json.load(f)
        except IOError:
            logger.debug("unable to load '%s'", info_file, exc_info=1)
            raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))
        else:
            logger.debug("restoring from backup '%s' created on %s", self.name,
                         time.ctime(self.info['created_at']))

    def _get_env_var(self):
        """ Define environment variable for hooks call """
        env_var = {}
        env_var['YNH_BACKUP_DIR'] = self.work_dir
        env_var['YNH_BACKUP_CSV'] = os.path.join(self.work_dir, "backup.csv")
        return env_var

def backup_create(name=None, description=None, output_directory=None,
                  no_compress=False, ignore_hooks=False, hooks=[],
                  ignore_apps=False, apps=[], methods=[]):
    """
    Create a backup local archive

    Keyword arguments:
        name -- Name of the backup archive
        description -- Short description of the backup
        output_directory -- Output directory for the backup
        no_compress -- Do not create an archive file
        hooks -- List of backup hooks names to execute
        ignore_hooks -- Do not execute backup hooks
        apps -- List of application names to backup
        ignore_apps -- Do not backup apps

    """

    # TODO: Add a 'clean' argument to clean output directory

    def _prevalidate_backup_call(name, output_directory, no_compress,
                                 ignore_hooks, ignore_apps, methods):
        """ Validate backup request is conform """

        # Validate what to backup
        if ignore_hooks and ignore_apps:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('backup_action_required'))

        # Validate there is no archive with the same name
        if name and name in backup_list()['archives']:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('backup_archive_name_exists'))

        # Validate output_directory option
        if output_directory:
            output_directory = os.path.abspath(output_directory)

            # Check for forbidden folders
            if output_directory.startswith(ARCHIVES_PATH) or \
            re.match(r'^/(|(bin|boot|dev|etc|lib|root|run|sbin|sys|usr|var)(|/.*))$',
                     output_directory):
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('backup_output_directory_forbidden'))

            # Check that output directory is empty
            if os.path.isdir(output_directory) and no_compress and \
                    os.listdir(output_directory):
                raise MoulinetteError(errno.EIO,
                                      m18n.n('backup_output_directory_not_empty'))
        elif no_compress:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('backup_output_directory_required'))


    # Validate backup request is conform
    _prevalidate_backup_call(name, output_directory, no_compress, ignore_hooks,
                             ignore_apps, methods)

    # Create yunohost archives directory if it does not exists
    _create_archive_dir()

    # Define output_directory
    if output_directory:
        output_directory = os.path.abspath(output_directory)

    # Define methods (retro-compat)
    if methods == []:
        if no_compress and not output_directory:
            methods = ['mount']
        elif no_compress:
            methods = ['copy']
        else:
            methods = ['tar']  # In future, borg will be the default actions
    logger.debug(hooks)


    if ignore_hooks:
        hooks = None
    elif hooks is None:
        hooks = []

    if ignore_apps:
        apps = None
    elif apps is None:
        apps = []

    # Prepare files to backup
    if no_compress:
        backup_manager = BackupManager(name, description,
                                       work_dir=output_directory)
    else:
        backup_manager = BackupManager(name, description)

    # Add backup methods
    for method in BackupMethod.create(methods):
        backup_manager.add(method)

    # Collect hooks and apps files
    backup_manager.collect_files(hooks, apps)

    # Apply backup methods on prepared files
    backup_manager.backup()

    logger.success(m18n.n('backup_created'))

    # Return backup info
    info = backup_manager.info
    info['name'] = backup_manager.name
    return {'archive': info}


def backup_restore(auth, name, hooks=[], ignore_hooks=False,
                   apps=[], ignore_apps=False, force=False):
    """
    Restore from a local backup archive

    Keyword argument:
        name -- Name of the local backup archive
        hooks -- List of restoration hooks names to execute
        ignore_hooks -- Do not execute backup hooks
        apps -- List of application names to restore
        ignore_apps -- Do not restore apps
        force -- Force restauration on an already installed system

    """
    # Validate what to restore
    if ignore_hooks and ignore_apps:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('restore_action_required'))

    # TODO don't ask this question for restoring apps only and certain hooks
    # Check if YunoHost is installed
    if os.path.isfile('/etc/yunohost/installed') and not ignore_hooks:
        logger.warning(m18n.n('yunohost_already_installed'))
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

    if ignore_hooks:
        hooks = None
    elif hooks is None:
        hooks = []

    if ignore_apps:
        apps = None
    elif apps is None:
        apps = []

    # TODO Partial app restore could not work if ldap is not restored before
    # TODO repair mysql if broken and it's a complete restore

    restore_manager = RestoreManager(name)

    restore_manager.restore(hooks, apps)

    # Check if something has been restored
    if restore_manager.success:
        logger.success(m18n.n('restore_complete'))
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('restore_nothings_done'))

    return restore_manager.result


def backup_list(with_info=False, human_readable=False):
    """
    List available local backup archives

    Keyword arguments:
        with_info -- Show backup information for each archive
        human_readable -- Print sizes in human readable format

    """
    result = []

    try:
        # Retrieve local archives
        archives = os.listdir(ARCHIVES_PATH)
    except OSError:
        logger.debug("unable to iterate over local archives", exc_info=1)
    else:
        # Iterate over local archives
        for f in archives:
            try:
                name = f[:f.rindex('.tar.gz')]
            except ValueError:
                continue
            result.append(name)
        result.sort()

    if result and with_info:
        d = OrderedDict()
        for a in result:
            d[a] = backup_info(a, human_readable=human_readable)
        result = d

    return {'archives': result}


def backup_info(name, with_details=False, human_readable=False):
    """
    Get info about a local backup archive

    Keyword arguments:
        name -- Name of the local backup archive
        with_details -- Show additional backup information
        human_readable -- Print sizes in human readable format

    """
    archive_file = '%s/%s.tar.gz' % (ARCHIVES_PATH, name)

    # Check file exist (even if it's a broken symlink)
    if not os.path.lexists(archive_file):
        raise MoulinetteError(errno.EIO,
                              m18n.n('backup_archive_name_unknown', name=name))

    # If symlink, retrieve the real path
    if os.path.islink(archive_file):
        archive_file = os.path.realpath(archive_file)

        # Raise exception if link is broken (e.g. on unmounted external storage)
        if not os.path.exists(archive_file):
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_archive_broken_link',
                                         path=archive_file))

    info_file = "%s/%s.info.json" % (ARCHIVES_PATH, name)

    try:
        with open(info_file) as f:
            # Retrieve backup info
            info = json.load(f)
    except:
        # TODO: Attempt to extract backup info file from tarball
        logger.debug("unable to load '%s'", info_file, exc_info=1)
        raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))

    # Retrieve backup size
    size = info.get('size', 0)
    if not size:
        tar = tarfile.open(archive_file, "r:gz")
        size = reduce(lambda x, y: getattr(x, 'size', x) + getattr(y, 'size', y),
                      tar.getmembers())
        tar.close()
    if human_readable:
        size = binary_to_human(size) + 'B'

    result = {
        'path': archive_file,
        'created_at': time.strftime(m18n.n('format_datetime_short'),
                                    time.gmtime(info['created_at'])),
        'description': info['description'],
        'size': size,
    }

    if with_details:
        for d in ['apps', 'hooks']:
            result[d] = info[d]
    return result


def backup_delete(name):
    """
    Delete a backup

    Keyword arguments:
        name -- Name of the local backup archive

    """
    hook_callback('pre_backup_delete', args=[name])

    archive_file = '%s/%s.tar.gz' % (ARCHIVES_PATH, name)

    info_file = "%s/%s.info.json" % (ARCHIVES_PATH, name)
    for backup_file in [archive_file, info_file]:
        if not os.path.isfile(backup_file) and not os.path.islink(backup_file):
            raise MoulinetteError(errno.EIO,
                m18n.n('backup_archive_name_unknown', name=backup_file))
        try:
            os.remove(backup_file)
        except:
            logger.debug("unable to delete '%s'", backup_file, exc_info=1)
            raise MoulinetteError(errno.EIO,
                m18n.n('backup_delete_error', path=backup_file))

    hook_callback('post_backup_delete', args=[name])

    logger.success(m18n.n('backup_deleted'))


def _create_archive_dir():
    """ Create the YunoHost archives directory if doesn't exist """
    if not os.path.isdir(ARCHIVES_PATH):
        os.mkdir(ARCHIVES_PATH, 0750)


def _call_for_each_path(self, callback, csv_path=None):
    """ Call a callback for each path in csv """
    if csv_path is None:
        csv_path = self.csv_path
    with open(csv_path, "r") as backup_file:
        backup_csv = csv.DictReader(backup_file, fieldnames=['source', 'dest'])
        for row in backup_csv:
            callback(self, row['source'], row['dest'])
