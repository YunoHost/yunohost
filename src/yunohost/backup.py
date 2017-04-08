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
    app_info, app_ssowatconf, _is_installed, _parse_app_instance_name
)
from yunohost.hook import (
    hook_info, hook_callback, hook_exec, CUSTOM_HOOK_FOLDER
)
from yunohost.monitor import binary_to_human
from yunohost.tools import tools_postinstall

BACKUP_PATH = '/home/yunohost.backup'
ARCHIVES_PATH = '%s/archives' % BACKUP_PATH

logger = getActionLogger('yunohost.backup')


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

    # Validate backup request is conform
    def _prevalidate_backup_call(name, output_directory, no_compress,
                                 ignore_hooks, ignore_apps):
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

    # Create the YunoHost archives directory if doesn't exist
    def _create_archive_dir():
        if not os.path.isdir(ARCHIVES_PATH):
            os.mkdir(ARCHIVES_PATH, 0750)

    # Initalize properties
    def _init_properties(methods, output_directory, no_compress, name, description):
        # Define backup name
        def _define_backup_name():
            # FIXME: case where this name already exist
            return time.strftime('%Y%m%d-%H%M%S')

        # Define output_directory
        if output_directory:
            output_directory = os.path.abspath(output_directory)
        else:
            output_directory = ARCHIVES_PATH

        # Define preparation_dir
        if no_compress:
            preparation_dir = output_directory
        else:
            preparation_dir = "%s/tmp/%s" % (BACKUP_PATH, name)
        is_tmp_preparation_dir = not no_compress

        # Define backup name
        if not name:
            name = _define_backup_name()

        # Initialize backup info
        info = {
            'description': description or '',
            'created_at': int(time.time()),
            'apps': {},
            'hooks': {},
        }

        backup_csv_path = os.path.join(preparation_dir, 'backup.csv')

        # Define environment variable for hooks call
        env_var = {}
        # FIXME=========================================
        # Do not compress, so set temporary directory to output one and
        # disable bind mounting to prevent data loss in case of a rm
        # See: https://dev.yunohost.org/issues/298
        if no_compress:
            logger.debug('bind mounting will be disabled')
            env_var['CAN_BIND'] = 0

        env_var['YNH_BACKUP_DIR'] = preparation_dir
        env_var['YNH_BACKUP_CSV'] = backup_csv_path

        # Define methods (retro-compat)
        if methods==[]:
            if no_compress and output_directory == ARCHIVES_PATH :
                methods=['mount']
            elif no_compress:
                methods=['copy']
            else:
                methods=['tar'] # In future, borg will be the default actions

        return (methods, output_directory, preparation_dir, is_tmp_preparation_dir, name, \
                info, backup_csv_path, env_var)

    # Call post_backup_create hooks and delete preparation_dir
    def _clean_preparation_dir(retcode=-1):
        ret = hook_callback('post_backup_create', args=[preparation_dir, retcode])
        if not ret['failed']:
            filesystem.rm(preparation_dir, True, True)
            return True
        else:
            logger.warning(m18n.n('backup_cleaning_failed'))
            return False

    def _prepare_files_to_backup():
        # Initialize preparation directory
        def _init_preparation_dir():
            if not os.path.isdir(preparation_dir):
                filesystem.mkdir(preparation_dir, 0750, parents=True, uid='admin')
            elif is_tmp_preparation_dir:
                logger.debug("temporary directory for backup '%s' already exists",
                    preparation_dir)
                if not _clean_preparation_dir():
                    raise MoulinetteError(
                        errno.EIO, m18n.n('backup_output_directory_not_empty'))

        # Initialize backup list
        def _init_backup_csv():
            try:
                backup_file = open(backup_csv_path, 'w')
                field_names = ['source', 'dest']
                backup_csv = csv.DictWriter(backup_file, fieldnames=field_names, \
                                            quoting=csv.QUOTE_ALL)
            except (IOError, OSError, csv.Error):
                logger.error(m18n.n('backup_csv_creation_failed'))
            return backup_csv

        # Mark file or directory to backup
        def _mark_for_backup(source,dest):
            try:
                if dest.endswith("/"):
                    dest = os.path.join(dest,os.path.basename(source))
                backup_csv.writerow({'source': source, 'dest': dest})
            except csv.Error:
                logger.error(m18n.n('backup_csv_addition_failed'))

        # Prepare backup for each selected system part
        def _backup_hooks():
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

            if not hooks or hooks_filtered:
                logger.info(m18n.n('backup_running_hooks'))
                ret = hook_callback('backup', hooks_filtered, args=[preparation_dir],
                                    env=env_var)
                if ret['succeed']:
                    info['hooks'] = ret['succeed']

                    # Save relevant restoration hooks
                    tmp_hooks_dir = 'hooks/restore/'
                    filesystem.mkdir(os.path.join(preparation_dir,tmp_hooks_dir),
                                    0750, True, uid='admin')
                    for h in ret['succeed'].keys():
                        try:
                            i = hook_info('restore', h)
                        except:
                            logger.warning(m18n.n('restore_hook_unavailable',
                                    hook=h), exc_info=1)
                        else:
                            for f in i['hooks']:
                                _mark_for_backup(f['path'],tmp_hooks_dir)
                #FIXME: support hooks failure

        # Prepare backup for each selected apps
        def _backup_apps ():
            def _backup_app(app_instance_name):
                app_setting_path = '/etc/yunohost/apps/' + app_instance_name

                # Check if the app has a backup and restore script
                app_script = app_setting_path + '/scripts/backup'
                app_restore_script = app_setting_path + '/scripts/restore'
                if not os.path.isfile(app_script):
                    logger.warning(m18n.n('unbackup_app', app=app_instance_name))
                    continue
                elif not os.path.isfile(app_restore_script):
                    logger.warning(m18n.n('unrestore_app', app=app_instance_name))

                tmp_app_dir = 'apps/{:s}'.format(app_instance_name)
                tmp_app_bkp_dir = os.path.join(preparation_dir ,tmp_app_dir, 'backup')
                logger.info(m18n.n('backup_running_app_script', app=app_instance_name))
                try:
                    # Prepare backup directory for the app
                    filesystem.mkdir(tmp_app_bkp_dir, 0750, True, uid='admin')
                    _mark_for_backup(app_setting_path, os.path.join(tmp_app_dir,'settings'))

                    # Copy app backup script in a temporary folder and execute it
                    subprocess.call(['install', '-Dm555', app_script, tmp_script])

                    # Prepare env. var. to pass to script
                    app_id, app_instance_nb = _parse_app_instance_name(
                        app_instance_name)
                    env_dict = env_var.copy()
                    env_dict["YNH_APP_ID"] = app_id
                    env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
                    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
                    env_dict["YNH_APP_BACKUP_DIR"] = tmp_app_bkp_dir

                    hook_exec(tmp_script, args=[tmp_app_bkp_dir, app_instance_name],
                            raise_on_error=True, chdir=tmp_app_bkp_dir, env=env_dict)
                except:
                    logger.exception(m18n.n('backup_app_failed', app=app_instance_name))
                    # Cleaning app backup directory
                    shutil.rmtree(os.path.join(preparation_dir, tmp_app_dir), ignore_errors=True)
                else:
                    # Add app info
                    i = app_info(app_instance_name)
                    info['apps'][app_instance_name] = {
                        'version': i['version'],
                        'name': i['name'],
                        'description': i['description'],
                    }
                finally:
                    filesystem.rm(tmp_script, force=True)

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

            # Run apps backup scripts
            tmp_script, _ = tempfile.mkstemp(prefix='backup_')
            for app_instance_name in apps_filtered:
                _backup_app(app_instance_name)

    # Prepare files to backup
    def _prepare_files_to_backup():
        # Initialize preparation directory
        _init_preparation_dir()

        # Initialize backup list
        backup_csv=_init_backup_csv()

        # Prepare files from user and system hooks
        if not ignore_hooks:
            _backup_hooks(hooks, env_var, preparation_dir,backup_csv_path, preparation_dir)

        # Prepare files from apps
        if not ignore_apps:
            _backup_apps()

        # Check if something has been saved
        if not info['hooks'] and not info['apps']:
            _clean_preparation_dir(1)
            raise MoulinetteError(errno.EINVAL, m18n.n('backup_nothings_done'))

        # Add unlisted files from backup tmp dir
        _mark_for_backup(backup_csv_path,'backup.csv')
        _mark_for_backup(os.path.join(preparation_dir,'info.json'),'info.json')
        if len(info['apps']) > 0:
            _mark_for_backup(os.path.join(preparation_dir,'apps'),'apps')
        if os.path.isdir(os.path.join(preparation_dir,'conf')):
            _mark_for_backup(os.path.join(preparation_dir,'conf'),'conf')
        if os.path.isdir(os.path.join(preparation_dir,'data')):
            _mark_for_backup(os.path.join(preparation_dir,'data'),'data')
        backup_file.close()
        os.system("cp "+preparation_dir+"/backup.csv ~/")

    def _call_for_each_path(callback):
        with open(backup_csv_path, "r") as backup_file:
            backup_csv = csv.DictReader(backup_file, fieldnames=field_names)
            for row in backup_csv:
                callback(row['source'],row['dest'])

    # Compute backup size
    def _compute_backup_size():
        backup_size = 0
        def _compte_path_size(source, dest):
            if source != os.path.join(preparation_dir,'info.json'):
                backup_size += int(subprocess.check_output(
                    ['du', '-sb', source]).split()[0].decode('utf-8'))
        _call_for_each_path(_compute_path_size)
        return backup_size

    # Check free space in output directory at first
    def _check_is_enough_free_space():
        avail_output = subprocess.check_output(
            ['df', '--block-size=1', '--output=avail', preparation_dir]).split()
        if len(avail_output) < 2 or int(avail_output[1]) < backup_size:
            logger.debug('not enough space at %s (free: %s / needed: %d)',
                        output_directory, avail_output[1], backup_size)
            _clean_preparation_dir(3)
            raise MoulinetteError(errno.EIO, m18n.n(
                'not_enough_disk_space', path=output_directory))

    # Apply backup methods
    def _apply_backup_method(method):

        # Copy prepared files into a dir
        def _copy_prepared_files():
            def _copy_path(source, dest):
                dest = os.path.join(preparation_dir, dest)
                if source == dest:
                    continue

                dest_parent = os.path.dirname(dest)
                if not os.path.exists(dest_parent):
                    filesystem.mkdir(dest_parent, 0750, True, uid='admin')

                if os.path.isdir(source):
                    shutil.copytree(source, os.path.join(preparation_dir, dest))
                else:
                    shutil.copy(source, os.path.join(preparation_dir, dest))
            _call_for_each_path(_copy_path)

        # Compress prepared files
        def _tar_prepared_files():
            # Open archive file for writing
            archive_file = "%s/%s.tar.gz" % (output_directory, name)
            try:
                tar = tarfile.open(archive_file, "w:gz")
            except:
                logger.debug("unable to open '%s' for writing",
                            archive_file, exc_info=1)
                _clean_preparation_dir(2)
                raise MoulinetteError(errno.EIO,
                                    m18n.n('backup_archive_open_failed'))

            # Add files to the archive
            def _tar_path(source, dest):
                tar.add(source, arcname=dest)
            try:
                _call_for_each_path(_tar_path)
                tar.close()
            except IOError:
                logger.error(m18n.n('backup_archive_writing_error'), exc_info=1)
                _clean_preparation_dir(3)
                raise MoulinetteError(errno.EIO,
                                    m18n.n('backup_creation_failed'))

            # Move info file
            shutil.move(preparation_dir + '/info.json',
                '{:s}/{:s}.info.json'.format(ARCHIVES_PATH, name))

            # If backuped to a non-default location, keep a symlink of the archive
            # to that location
            if output_directory != ARCHIVES_PATH:
                link = "%s/%s.tar.gz" % (ARCHIVES_PATH, name)
                os.symlink(archive_file, link)

        def _mount_csv_listed_files():
            pass

        # Backup prepared files with borg
        def _borg_prepared_files():
            _mount_csv_listed_files()
            #TODO run borg create command
            raise MoulinetteError(
                    errno.EIO, m18n.n('backup_borg_not_implemented'))

        # Apply a hook on prepared files
        def _hook_prepared_files():
            if method.startwith('mount_'):
                _mount_csv_listed_files()
            ret = hook_callback('method_backup_create', method, args=[preparation_dir, retcode])
            if ret['failed']:
                _clean_preparation_dir()


        if method in ["copy", "tar", "borg"]:
            logger.info(m18n.n('backup_applying_method_' + method))
            _copy_prepared_files()
            _tar_prepared_files()
            _borg_prepared_files()
            logger.info(m18n.n('backup_method_' + method + '_finished'))
        else:
            logger.info(m18n.n('backup_applying_method_custom'))
            _hook_prepared_files(method)
            logger.info(m18n.n('backup_method_custom_finished'))

    # Validate backup request is conform
    _prevalidate_backup_call(name, output_directory, no_compress, ignore_hooks, \
                            ignore_apps)

    # Create yunohost archives directory if it does not exists
    _create_archive_dir()

    # Initalize properties
    output_directory, preparation_dir, is_tmp_preparation_dir, name, info, \
        backup_csv_path, env_var = _init_properties()

    # Prepare files to backup
    _prepare_files_to_backup()

    # Calculate total size
    info['size'] = _compute_backup_size()

    # Create backup info file
    with open("%s/info.json" % preparation_dir, 'w') as f:
        f.write(json.dumps(info))

    # Check free space in output
    _check_is_enough_free_space()

    # Apply backup methods on prepared filesi
    for method in methods:
        _apply_backup_method(method)

    # Clean temporary directory
    if is_tmp_preparation_dir:
        _clean_preparation_dir()

    logger.success(m18n.n('backup_created'))

    # Return backup info
    info['name'] = name
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

    # Retrieve and open the archive
    info = backup_info(name)
    archive_file = info['path']
    try:
        tar = tarfile.open(archive_file, "r:gz")
    except:
        logger.debug("cannot open backup archive '%s'",
            archive_file, exc_info=1)
        raise MoulinetteError(errno.EIO, m18n.n('backup_archive_open_failed'))

    # Check temporary directory
    tmp_dir = "%s/tmp/%s" % (BACKUP_PATH, name)
    if os.path.isdir(tmp_dir):
        logger.debug("temporary directory for restoration '%s' already exists",
            tmp_dir)
        os.system('rm -rf %s' % tmp_dir)

    # Check available disk space
    statvfs = os.statvfs(BACKUP_PATH)
    free_space = statvfs.f_frsize * statvfs.f_bavail
    if free_space < info['size']:
        logger.debug("%dB left but %dB is needed", free_space, info['size'])
        raise MoulinetteError(
            errno.EIO, m18n.n('not_enough_disk_space', path=BACKUP_PATH))

    def _clean_tmp_dir(retcode=0):
        ret = hook_callback('post_backup_restore', args=[tmp_dir, retcode])
        if not ret['failed']:
            filesystem.rm(tmp_dir, True, True)
        else:
            logger.warning(m18n.n('restore_cleaning_failed'))

    # Extract the tarball
    logger.info(m18n.n('backup_extracting_archive'))
    tar.extractall(tmp_dir)
    tar.close()

    # Retrieve backup info
    info_file = "%s/info.json" % tmp_dir
    try:
        with open(info_file, 'r') as f:
            info = json.load(f)
    except IOError:
        logger.debug("unable to load '%s'", info_file, exc_info=1)
        raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))
    else:
        logger.debug("restoring from backup '%s' created on %s", name,
            time.ctime(info['created_at']))

    # Initialize restauration summary result
    result = {
        'apps': [],
        'hooks': {},
    }

    # Check if YunoHost is installed
    if os.path.isfile('/etc/yunohost/installed'):
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
                _clean_tmp_dir()
                raise MoulinetteError(errno.EEXIST, m18n.n('restore_failed'))
    else:
        # Retrieve the domain from the backup
        try:
            with open("%s/conf/ynh/current_host" % tmp_dir, 'r') as f:
                domain = f.readline().rstrip()
        except IOError:
            logger.debug("unable to retrieve current_host from the backup",
                         exc_info=1)
            raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))

        logger.debug("executing the post-install...")
        tools_postinstall(domain, 'yunohost', True)

    # Run system hooks
    if not ignore_hooks:
        # Filter hooks to execute
        hooks_list = set(info['hooks'].keys())
        _is_hook_in_backup = lambda h: True
        if hooks:
            def _is_hook_in_backup(h):
                if h in hooks_list:
                    return True
                logger.error(m18n.n('backup_archive_hook_not_exec', hook=h))
                return False
        else:
            hooks = hooks_list

        # Check hooks availibility
        hooks_filtered = set()
        for h in hooks:
            if not _is_hook_in_backup(h):
                continue
            try:
                hook_info('restore', h)
            except:
                tmp_hooks = glob('{:s}/hooks/restore/*-{:s}'.format(tmp_dir, h))
                if not tmp_hooks:
                    logger.exception(m18n.n('restore_hook_unavailable', hook=h))
                    continue
                # Add restoration hook from the backup to the system
                # FIXME: Refactor hook_add and use it instead
                restore_hook_folder = CUSTOM_HOOK_FOLDER + 'restore'
                filesystem.mkdir(restore_hook_folder, 755, True)
                for f in tmp_hooks:
                    logger.debug("adding restoration hook '%s' to the system "
                        "from the backup archive '%s'", f, archive_file)
                    shutil.copy(f, restore_hook_folder)
            hooks_filtered.add(h)

        if hooks_filtered:
            logger.info(m18n.n('restore_running_hooks'))
            ret = hook_callback('restore', hooks_filtered, args=[tmp_dir])
            result['hooks'] = ret['succeed']

    # Add apps restore hook
    if not ignore_apps:
        # Filter applications to restore
        apps_list = set(info['apps'].keys())
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
            tmp_app_dir = '{:s}/apps/{:s}'.format(tmp_dir, app_instance_name)
            tmp_app_bkp_dir = tmp_app_dir + '/backup'

            # Parse app instance name and id
            # TODO: Use app_id to check if app is installed?
            app_id, app_instance_nb = _parse_app_instance_name(app_instance_name)

            # Check if the app is not already installed
            if _is_installed(app_instance_name):
                logger.error(m18n.n('restore_already_installed_app',
                        app=app_instance_name))
                continue

            # Check if the app has a restore script
            app_script = tmp_app_dir + '/settings/scripts/restore'
            if not os.path.isfile(app_script):
                logger.warning(m18n.n('unrestore_app', app=app_instance_name))
                continue

            tmp_settings_dir = tmp_app_dir + '/settings'
            app_setting_path = '/etc/yunohost/apps/' + app_instance_name
            logger.info(m18n.n('restore_running_app_script', app=app_instance_name))
            try:
                # Copy app settings and set permissions
                # TODO: Copy app hooks too
                shutil.copytree(tmp_settings_dir, app_setting_path)
                filesystem.chmod(app_setting_path, 0400, 0400, True)
                filesystem.chown(app_setting_path + '/scripts', 'admin', None, True)

                # Set correct right to the temporary settings folder
                filesystem.chmod(tmp_settings_dir, 0550, 0550, True)
                filesystem.chown(tmp_settings_dir, 'admin', None, True)

                # Prepare env. var. to pass to script
                env_dict = {}
                env_dict["YNH_APP_ID"] = app_id
                env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
                env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
                env_dict["YNH_APP_BACKUP_DIR"] = tmp_app_bkp_dir

                # Execute app restore script
                hook_exec(app_script, args=[tmp_app_bkp_dir, app_instance_name],
                          raise_on_error=True, chdir=tmp_app_bkp_dir, env=env_dict)
            except:
                logger.exception(m18n.n('restore_app_failed', app=app_instance_name))

                app_script = tmp_app_dir + '/settings/scripts/remove'

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
            else:
                result['apps'].append(app_instance_name)

    # Check if something has been restored
    if not result['hooks'] and not result['apps']:
        _clean_tmp_dir(1)
        raise MoulinetteError(errno.EINVAL, m18n.n('restore_nothings_done'))
    if result['apps']:
        # Quickfix: the old app_ssowatconf(auth) instruction failed due to ldap
        # restore hooks
        os.system('sudo yunohost app ssowatconf')

    _clean_tmp_dir()
    logger.success(m18n.n('restore_complete'))

    return result


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
                m18n.n('backup_archive_broken_link', path=archive_file))

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
        if not os.path.isfile(backup_file):
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
