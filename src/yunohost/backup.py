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
    hook_list, hook_info, hook_callback, hook_exec, CUSTOM_HOOK_FOLDER
)
from yunohost.monitor import binary_to_human
from yunohost.tools import tools_postinstall

BACKUP_PATH = '/home/yunohost.backup'
ARCHIVES_PATH = '%s/archives' % BACKUP_PATH
APP_MARGIN_SPACE_SIZE = 100  # In MB
CONF_MARGIN_SPACE_SIZE = 10  # IN MB
POSTINSTALL_ESTIMATE_SPACE_SIZE = 5  # In MB
MB_ALLOWED_TO_ORGANIZE = 10
logger = getActionLogger('yunohost.backup')




class BackupManager:
    """This class collect files to backup in a list and apply one or several
    backup method on it.

    The list contains dict with source and dest properties. The goal of this csv
    is to list all directories and files which need to be backup in this
    archive.  The `source` property is the path of the source (dir or file).
    The `dest` property is the path where it could be placed in the archive.

    The list is filled by app backup scripts and system/user backup hooks.
    Files located in the work_dir are automatically added.

    With this list, "backup methods" are able to apply their backup strategy on
    data listed in it.  It's possible to tar each path (tar methods), to mount
    each dir into the work_dir, to copy each files (copy method) or to call a
    custom method (via a custom script).

    Note: some future backups methods (like borg) are not able to specify a
    different place than the original path. That's why the ynh_restore_file
    helpers use primarily the SOURCE_PATH as argument.

    Public properties:
        info (getter)
        work_dir (getter) # FIXME currently it's not a getter
        is_tmp_work_dir (getter)
        paths_to_backup (getter) # FIXME not a getter and list is not protected
        name (getter) # FIXME currently it's not a getter
        size (getter) # FIXME currently it's not a getter

    Public methods:
        add(self, method)
        set_targets(self, system_parts=[], apps=[])
        collect_files(self)
        backup(self)

    Usage:
        backup_manager = BackupManager(name="mybackup", description="bkp things")

        # Add backup method to apply
        backup_manager.add(BackupMethod.create('copy','/mnt/local_fs'))
        backup_manager.add(BackupMethod.create('tar','/mnt/remote_fs'))

        # Define targets to be backuped
        backup_manager.set_targets(system=["data"],
                                   apps=["wordpress"])

        # Collect files to backup from targets
        backup_manager.collect_files()

        # Apply backup methods
        backup_manager.backup()
    """

    def __init__(self, name=None, description='', work_dir=None):
        """ BackupManager constructor

        Args:
        name        -- (string) The name of this backup (without spaces). If
                        None, the name will be generated (default: None)

        description -- (string) A description for this future backup archive
                        (default: '')

        work_dir    -- (None|string) A path where prepare the archive. If None,
                        temporary work_dir will be created (default: None)
        """
        self.description = description or ''
        self.created_at = int(time.time())
        self.apps_return = {}
        self.system_return = {}
        self.methods = []
        self.paths_to_backup = []
        self.size_details = {
            'system': {},
            'apps': {}
        }
        self.results = {
            "system": {},
            "apps": {}
        }

        # Define backup name if needed
        if not name:
            name = self._define_backup_name()
        self.name = name

        # Define working directory if needed and initialize it
        self.work_dir = work_dir
        if self.work_dir is None:
            self.work_dir = os.path.join(BACKUP_PATH, 'tmp', name)
        self._init_work_dir()

    ###########################################################################
    #   Misc helpers                                                          #
    ###########################################################################

    @property
    def info(self):
        """(Getter) Dict containing info about the archive being created"""
        return {
            'description': self.description,
            'created_at': self.created_at,
            'size': self.size,
            'size_details': self.size_details,
            'apps': self.apps_return,
            'system': self.system_return
        }

    @property
    def is_tmp_work_dir(self):
        """(Getter) Return true if the working directory is temporary and should
        be clean at the end of the backup"""
        return self.work_dir == os.path.join(BACKUP_PATH, 'tmp', self.name)

    def __repr__(self):
        return json.dumps(self.info)

    def _define_backup_name(self):
        """Define backup name

        Return:
            (string) A backup name created from current date 'YYMMDD-HHMMSS'
        """
        # FIXME: case where this name already exist
        return time.strftime('%Y%m%d-%H%M%S')

    def _init_work_dir(self):
        """Initialize preparation directory

        Ensure the working directory exists and is empty

        exception:
        backup_output_directory_not_empty -- (MoulinetteError) Raised if the
            directory was given by the user and isn't empty

        (TODO) backup_cant_clean_tmp_working_directory -- (MoulinetteError)
            Raised if the working directory isn't empty, is temporary and can't
            be automaticcaly cleaned

        (TODO) backup_cant_create_working_directory -- (MoulinetteError) Raised
            if iyunohost can't create the working directory
        """

        # FIXME replace isdir by exists ? manage better the case where the path
        # exists
        if not os.path.isdir(self.work_dir):
            filesystem.mkdir(self.work_dir, 0750, parents=True, uid='admin')
        elif self.is_tmp_work_dir:
            logger.debug("temporary directory for backup '%s' already exists",
                         self.work_dir)
            # FIXME May be we should clean the workdir here
            raise MoulinetteError(
                    errno.EIO, m18n.n('backup_output_directory_not_empty'))

    ###########################################################################
    #   Backup target management                                              #
    ###########################################################################

    def set_result(self, category, element, value):

        levels = [ "Unknown", "Success", "Warning", "Error", "Skipped" ]

        assert value in levels

        if element not in self.results[category].keys():
            self.results[category][element] = value
        else:
            currentValue = self.results[category][element]
            if (levels.index(currentValue) > levels.index(value)):
                return
            else:
                self.results[category][element] = value


    def set_targets(self, system_parts=[], apps=[]):
        """
        Define and validate targets to be backuped (list of system parts,
        apps..)

        Args:
        system_parts -- (list) list of system parts which should be backuped. If
        it's an empty list, it will backup all system. If it's None, nothing
        will be backuped.

        apps         -- (list) list of apps which should be backuped. If apps is
        an empty list, all apps will be backuped. If it's None, no apps will be
        backuped.
        """

        self.targets = {}

        #
        # System
        #

        available_system_backup_hooks = hook_list('backup')["hooks"]

        # No system parts to backup
        if system_parts is None:
            self.targets["system"] = []
        # Backup all system parts
        elif system_parts == []:
            self.targets["system"] = available_system_backup_hooks
        # If the user manually specified which parts to backuped, we need to
        # check that each part actually has a backup script available
        else:
            self.targets["system"] = [ part for part in system_parts
                                       if part in available_system_backup_hooks ]

            # Display an error for each part asked by the user but which is
            # unknown
            unknown_parts = [ part for part in system_parts
                              if part not in available_system_backup_hooks ]

            for part in unknown_parts :
                logger.error(m18n.n('backup_hook_unknown', hook=part))
                self.set_result("system", part, "Skipped")

        #
        # Apps
        #

        apps_installed = os.listdir('/etc/yunohost/apps')

        # No apps to backup
        if apps is None:
            self.targets["apps"] = []
        # Backup all apps installed
        elif apps == []:
            self.targets["apps"] = apps_installed
        # If the user manually specified which apps to backup, we need to
        # check that each app is actually installed
        else:
            self.targets["apps"] = [ app for app in apps
                                     if app in apps_installed ]

            # Display an error for each app asked by the user but which is
            # unknown
            unknown_apps = [ app for app in apps
                             if app not in apps_installed ]
            for app in unknown_apps:
                logger.error(m18n.n('unbackup_app', app=app))
                self.set_result("apps", app, "Skipped")


        # Additionnaly, we need to check that each targetted app has a
        # backup and restore scripts

        if self.targets["apps"] is not None:
            for app in self.targets["apps"]:
                app_script_folder = "/etc/yunohost/apps/%s/scripts" % app
                backup_script_path = os.path.join(app_script_folder, "backup")
                restore_script_path = os.path.join(app_script_folder, "restore")

                if not os.path.isfile(backup_script_path):
                    logger.warning(m18n.n('backup_with_no_backup_script_for_app', app=app))
                    self.targets["apps"].remove(app)
                    self.set_result("apps", app, "Skipped")

                elif not os.path.isfile(restore_script_path):
                    logger.warning(m18n.n('backup_with_no_restore_script_for_app', app=app))
                    self.set_result("apps", app, "Warning")

        #
        # Init result
        #

        # For target with no result yet (like 'Skipped'), set it as unknown
        for category in [ "apps", "system" ]:
            for target in self.targets[category]:
                self.set_result(category, target, "Unknown")

    ###########################################################################
    #   Management of files to backup / "The CSV"                             #
    ###########################################################################

    def _import_to_list_to_backup(self, tmp_csv):
        """Commit collected path from system hooks or app scripts

        Args:
        tmp_csv -- (string) Path to a temporary csv file with source and
                   destinations column to add to the list of paths to backup
        """
        _call_for_each_path(self, BackupManager._add_to_list_to_backup, tmp_csv)

    def _add_to_list_to_backup(self, source, dest=None):
        """
        Mark file or directory to backup

        This method add source/dest couple to the "paths_to_backup" list.

        Args:
        source -- (string) Source path to backup

        dest   -- (string) Destination path in the archive. If it ends by a
                  slash the basename of the source path will be added. If None,
                  the source path will be used, so source files will be set up
                  at the same place and with same name than on the system.
                  (default: None)

        Usage:
        self._add_to_list_to_backup('/var/www/wordpress', 'sources')
        # => "wordpress" dir will be move and rename as "sources"

        self._add_to_list_to_backup('/var/www/wordpress', 'sources/')
        # => "wordpress" dir will be put inside "sources/" and won't be renamed

        """
        if dest is None:
            # TODO check if this code works. It seems strange to add the work
            # dir. Take care dest shouldn't start with a / .
            dest = source
            source = os.path.join(self.work_dir, source)
        if dest.endswith("/"):
            dest = os.path.join(dest, os.path.basename(source))
        self.paths_to_backup.append({'source': source, 'dest': dest})


    def _write_csv(self):
        """Write the backup list into a CSV

        The goal of this csv is to list all directories and files which need to
        be backup in this archive.  For the moment, this CSV contains 2 columns.
        The first column `source` is the path of the source (dir or file).  The
        second `dest` is the path where it could be placed in the archive.

        This CSV is filled by app backup scripts and system/user hooks.
        Files in the work_dir are automatically added.

        With this CSV, "backup methods" are able to apply their backup strategy
        on data listed in it.  It's possible to tar each path (tar methods), to
        mount each dir into the work_dir, to copy each files (copy methods) or
        a custom method (via a custom script).

        Note: some future backups methods (like borg) are not able to specify a
        different place than the original path. That's why the ynh_restore_file
        helpers use primarily the SOURCE_PATH as argument.

        Error:
        backup_csv_creation_failed -- Raised if the CSV couldn't be created
        backup_csv_addition_failed -- Raised if we can't write in the CSV
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



    ###########################################################################
    #   File collection from system parts and apps                            #
    ###########################################################################

    def collect_files(self):
        """Collect all files to backup, write its into a CSV and create a
        info.json file

        Files to backup are listed by system parts backup hooks and by backup
        app scripts that have been defined with the set_targets() method.

        Some files or directories inside the working directory are added by
        default:

        info.json  -- info about the archive
        backup.csv -- a list of paths to backup
        apps/      -- some apps generate here temporary files to backup (like
                      database dump)
        conf/      -- system configuration backup scripts could generate here
                      temporary files to backup
        data/      -- system data backup scripts could generate here temporary
                      files to backup
        hooks/     -- restore scripts associated to system backup scripts are
                      copied here

        Exceptions:
        "backup_nothings_done" -- (MoulinetteError) This exception is raised if
        nothing has been listed.
        """
        self._collect_system_files()

        self._collect_apps_files()

        # Check if something has been saved ('success' or 'warning')
        all_results = self.results["system"].values() + \
                      self.results["apps"].values()

        if (not "Success" in all_results) and \
           (not "Warning" in all_results):
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


    def _get_env_var(self, app=None):
        """ Define environment variables for apps or system backup scripts.

        Args:
        app -- (string|None) The instance name of the app we want the variable
        environment. If you want a variable environment for a system backup
        script keep None. (default: None)

        Return:
            (Dictionnary) The environment variables to apply to the script
        """
        env_var = {}

        _, tmp_csv = tempfile.mkstemp(prefix='backupcsv_')
        env_var['YNH_BACKUP_DIR'] = self.work_dir
        env_var['YNH_BACKUP_CSV'] = tmp_csv

        if app is not None:
            app_id, app_instance_nb = _parse_app_instance_name(app)
            env_var["YNH_APP_ID"] = app_id
            env_var["YNH_APP_INSTANCE_NAME"] = app
            env_var["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
            tmp_app_dir = os.path.join('apps/', app)
            tmp_app_bkp_dir = os.path.join(self.work_dir, tmp_app_dir, 'backup')
            env_var["YNH_APP_BACKUP_DIR"] = tmp_app_bkp_dir

        return env_var


    def _collect_system_files(self):
        """
        List file to backup for each selected system part

        This corresponds to scripts in data/hooks/backup/ (system hooks) and
        to those in /etc/yunohost/hooks.d/backup/ (user hooks)

        Environment variables:
        YNH_BACKUP_DIR -- The backup working directory (in
                          "/home/yunohost.backup/tmp/BACKUPNAME" or could be
                          defined by the user)
        YNH_BACKUP_CSV -- A temporary CSV where the script whould list paths toi
                          backup
        """

        # If nothing to backup, return immediately
        if self.targets["system"] == []:
            return

        logger.info(m18n.n('backup_running_hooks'))

        # Prepare environnement
        env_dict = self._get_env_var()

        # Actual call to backup scripts/hooks

        ret = hook_callback('backup',
                            self.targets["system"],
                            args=[self.work_dir],
                            env=env_dict,
                            chdir=self.work_dir)

        if ret["succeed"] != []:
            self.system_return = ret["succeed"]

        # Add files from targets (which they put in the CSV) to the list of
        # files to backup
        self._import_to_list_to_backup(env_dict["YNH_BACKUP_CSV"])

        # Save restoration hooks for each part that suceeded (and which have
        # a restore hook available)

        restore_hooks_dir = os.path.join(self.work_dir, "hooks", "restore")
        if not os.path.exists(restore_hooks_dir):
            filesystem.mkdir(restore_hooks_dir, mode=0750,
                             parents=True, uid='admin')

        restore_hooks = hook_list("restore")["hooks"]

        for part in ret['succeed'].keys():
            if part in restore_hooks:
                part_restore_hooks = hook_info("restore", part)["hooks"]
                for hook in part_restore_hooks:
                    self._add_to_list_to_backup(hook["path"], "hooks/restore/")
                self.set_result("system", part, "Success")
            else:
                logger.warning(m18n.n('restore_hook_unavailable', hook=part))
                self.set_result("system", part, "Warning")

        for part in ret['failed'].keys():
            logger.error(m18n.n('backup_system_part_failed', part=part))
            self.set_result("system", part, "Error")


    def _collect_apps_files(self, apps=[]):
        """ Prepare backup for each selected apps """

        for app_instance_name in self.targets["apps"]:
            self._collect_app_files(app_instance_name)

    def _collect_app_files(self, app):
        """
        List files to backup for the app into the paths_to_backup dict.

        If the app backup script fails, paths from this app already listed for
        backup aren't added to the general list and will be ignored

        Environment variables:
        YNH_BACKUP_DIR -- The backup working directory (in
                          "/home/yunohost.backup/tmp/BACKUPNAME" or could be
                          defined by the user)
        YNH_BACKUP_CSV -- A temporary CSV where the script whould list paths toi
                          backup
        YNH_APP_BACKUP_DIR -- The directory where the script should put
                              temporary files to backup like database dump,
                              files in this directory don't need to be added to
                              the temporary CSV.
        YNH_APP_ID     -- The app id (eg wordpress)
        YNH_APP_INSTANCE_NAME -- The app instance name (eg wordpress__3)
        YNH_APP_INSTANCE_NUMBER  -- The app instance number (eg 3)


        Args:
        app -- (string) an app instance name (already installed) to backup

        Exceptions:
        backup_app_failed -- Raised at the end if the app backup script
                             execution failed
        """
        app_setting_path = os.path.join('/etc/yunohost/apps/', app)

        # Prepare environment
        env_dict = self._get_env_var(app)
        tmp_app_bkp_dir = env_dict["YNH_APP_BACKUP_DIR"]

        logger.info(m18n.n('backup_running_app_script', app=app))
        try:
            # Prepare backup directory for the app
            filesystem.mkdir(tmp_app_bkp_dir, 0750, True, uid='admin')

            # Copy app backup script in a temporary folder and execute it
            _, tmp_script = tempfile.mkstemp(prefix='backup_')
            app_script = os.path.join(app_setting_path, 'scripts/backup')
            subprocess.call(['install', '-Dm555', app_script, tmp_script])

            hook_exec(tmp_script, args=[tmp_app_bkp_dir, app],
                      raise_on_error=True, chdir=tmp_app_bkp_dir, env=env_dict, user="root")

            self._import_to_list_to_backup(env_dict["YNH_BACKUP_CSV"])
        except:
            self._clean_app_backup_env(app)
            logger.exception(m18n.n('backup_app_failed', app=app))
            self.set_result("apps", app, "Error")
        else:
            # Add settings of the app to the list
            tmp_app_dir = os.path.join('apps/', app)
            settings_dir = os.path.join(tmp_app_dir, 'settings')
            self._add_to_list_to_backup(app_setting_path, settings_dir)

            # Add app info
            i = app_info(app)
            self.apps_return[app] = {
                'version': i['version'],
                'name': i['name'],
                'description': i['description'],
            }
            self.set_result("apps", app, "Success")

        # Remove tmp files in all situations
        finally:
            filesystem.rm(tmp_script, force=True)
            filesystem.rm(env_dict["YNH_BACKUP_CSV"], force=True)

    def _clean_app_backup_env(self, app):
        """ Cleaning app backup directory

        Args:
        app -- The app instance name which fail and which the dir in the archive
               need to be removed
        """
        abs_tmp_app_dir = os.path.join(self.work_dir, 'apps/', app)
        shutil.rmtree(abs_tmp_app_dir, ignore_errors=True)

    ###########################################################################
    #   Actual backup archive creation / method management                    #
    ###########################################################################

    def add(self, method):
        """Add a backup method that will be applyed after the files collection step

        Args:
        method -- (BackupMethod) A backup method. Currently, you can use those:
                  TarBackupMethod
                  CopyBackupMethod
                  CustomBackupMethod
        """
        self.methods.append(method)


    def backup(self):
        """Apply backup methods"""

        for method in self.methods:
            logger.info(m18n.n('backup_applying_method_' + method.method_name))
            method.mount_and_backup(self)
            logger.info(m18n.n('backup_method_' + method.method_name + '_finished'))


    def _compute_backup_size(self):
        """Compute backup global size and details size for each apps and system
        parts

        Update self.size and self.size_details

        Note: currently, these sizes are the size in this archive, not really
        the size of needed to restore the archive. To know the size needed to
        restore we should consider apt/npm/pip dependencies space and database
        dump restore operations.

        Return:
            (int) The global size of the archive in bytes
        """
        # FIXME Database dump will be loaded, so dump should use almost the
        # double of their space
        # FIXME Some archive will set up dependencies, those are not in this
        # size info
        self.size = 0
        for system_key in self.system_return:
            self.size_details['system'][system_key] = 0
        for app_key in self.apps_return:
            self.size_details['apps'][app_key] = 0

        for row in self.paths_to_backup:
            if row['dest'] != "info.json":
                # We don't do this in python with os.stat because we don't want
                # to follow symlinks
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
                # OR Add size to the correct system element
                elif category == 'data' or category == 'conf':
                    for system_key in self.system_return:
                        if row['dest'].startswith(system_key.replace('_', '/')):
                            self.size_details['system'][system_key] += size
                            break

                self.size += size

        return self.size


class BackupMethod(object):
    """BackupMethod is an abstract class that represents a way to backup and
    restore a list of files.

    Those kind of object could be used by a BackupManager or by a
    RestoreManager. Some methods are reserved for BackupManager and others for
    RestoreManager.

    BackupMethod has a factory method "create" let you create backup methods
    instances. Currently, there are 3 BackupMethods implemented:

    CopyBackupMethod -- This method just do an uncompress copy of each file in a
    location, and could be the inverse for restoring

    TarBackupMethod -- This method compress all files to backup in archive. To
    restore it try to mount the archive with archivemount (fuse). Some system
    don't support fuse.

    CustomBackupMethod -- This one use a bash hook "backup_method" to do the
    backup/restore operations. A user can add his own hook inside
    /etc/yunohost/hooks.d/backup_method/

    Public properties:
        method_name
    Public methods:
        mount_and_backup(self, backup_manager)
        mount(self, restore_manager)
        create(cls, method, **kwargs)

    Usage:
        method = BackupMethod.create("tar")
        method.mount_and_backup(backup_manager)
        #or
        method = BackupMethod.create("copy")
        method.mount(restore_manager)
    """
    def __init__(self, repo = None):
        """BackupMethod constructors

        Note it is an abstract class. You should use the "create" class method
        to create instance.

        Args:
        repo -- (string|None) A string that represent the repo where put or get
        the backup. It could be a path, and in future a BackupRepository object.
        If None, the default repo is used /home/yunohost.backup/archives/
        """
        self.repo = ARCHIVES_PATH if repo is None else repo

    @property
    def method_name(self):
        """Return the string name of a BackupMethod (eg "tar" or "copy")"""
        raise MoulinetteError(errno.EINVAL, m18n.n('backup_abstract_method'))

    @property
    def name(self):
        """Return the backup name"""
        return self.manager.name

    @property
    def work_dir(self):
        """Return the working directory

        For a BackupManager, it is the directory where we prepare the files to
        backup

        For a RestoreManager, it is the directory where we mount the archive
        before restoring"""
        return self.manager.work_dir

    def need_mount(self):
        """Return True if this backup method need to organize path to backup by
        binding its in the working directory before to backup its.

        Indeed, some methods like tar or copy method don't need to organize
        files before to add it inside the archive, but others like borgbackup
        are not able to organize directly the files. In this case we have the
        choice to organize in the working directory before to put in the archive
        or to organize after mounting the archive before the restoring
        operation.

        The default behaviour is to return False. To change it override the
        method.

        Note it's not a property because some overrided methods could do long
        treatment to get this info
        """
        return False

    def mount_and_backup(self, backup_manager):
        """Run the backup on files listed by  the BackupManager instance

        This method shouldn't be overrided, prefer overriding self.backup() and
        self.clean()

        Args:
        backup_manager -- (BackupManager) A backup manager instance that has
        already done the files collection step.
        """
        self.manager = backup_manager
        if self.need_mount():
            self._organize_files()

        try:
            self.backup()
        finally:
            self.clean()

    def mount(self, restore_manager):
        """Mount the archive from RestoreManager instance in the working
        directory

        This method should be extended.

        Args:
        restore_manager -- (RestoreManager) A restore manager instance contains
        an archive to restore.
        """
        self.manager = restore_manager

    def clean(self):
        """Umount sub directories of working dirextories and delete it if
        temporary

        Exceptions:
        backup_cleaning_failed -- Raise if we were not able to unmount sub
        directories of the working directories
        """
        if self.need_mount():
            if self._recursive_umount(self.work_dir) > 0:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('backup_cleaning_failed'))

        if self.manager.is_tmp_work_dir:
            filesystem.rm(self.work_dir, True, True)

    def _recursive_umount(directory):
        """Recursively umount sub directories of a directory

        Args:
        directory -- a directory path
        """
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
        """Check free space in repository or output directory before to backup

        Exceptions:
        not_enough_disk_space -- Raise if there isn't enough space.
        """
        # TODO How to do with distant repo or with deduplicated backup ?
        backup_size = self.manager.size
        cmd = ['df', '--block-size=1', '--output=avail', self.repo]
        avail_output = subprocess.check_output(cmd).split()
        if len(avail_output) < 2 or int(avail_output[1]) < backup_size:
            free_space = avail_output[1] if len(avail_output)>= 2 else '?'
            logger.debug('not enough space at %s (free: %s / needed: %d)',
                         self.repo, free_space, backup_size)
            raise MoulinetteError(errno.EIO, m18n.n(
                'not_enough_disk_space', path=self.repo))

    def _organize_files(self):
        """Mount all csv src in their related path

        The goal is to organize the files app by app and hook by hook, before
        custom backup method or before the restore operation (in the case of an
        unorganize archive).

        The usage of binding could be strange for a user because the du -sb
        command will return that the working directory is big.

        Exceptions:
        backup_unable_to_organize_files
        """
        paths_needed_to_be_copied = []
        for path in self.manager.paths_to_backup:
            src = path['src']

            if self.manager is RestoreManager:
                # TODO Support to run this before a restore (and not only before
                # backup). To do that RestoreManager.unorganized_work_dir should
                # be implemented
                src = os.path.join(self.unorganized_work_dir, src)

            dest = os.path.join(self.work_dir, path['dest'])
            dest_dir = os.path.dirname(dest)

            # Be sure the parent dir of destination exists
            filesystem.mkdir(dest_dir, parent=True)

            # Try to bind files
            if os.path.isdir(src):
                filesystem.mkdir(dest, parent=True)
                ret = subprocess.call(["mount", "-r", "--rbind", src, dest])
                if ret == 0:
                    continue
                else:
                    logger.warning(m18n.n("bind_mouting_disable"))
                    subprocess.call(["mountpoint", "-q", dest,
                                    "&&", "umount", "-R", dest])
            elif os.path.isfile(src) or os.path.islink(src):
                # Create a hardlink if src and dest are on the filesystem
                if os.stat(src).st_dev == os.stat(dest_dir).st_dev:
                    os.link(src, dest)
                    continue

            # Add to the list to copy
            paths_needed_to_be_copied.append(path)

        if len(paths_needed_to_be_copied) == 0:
            return

        # Manage the case where we are not able to use mount bind abilities
        # It could be just for some small files on different filesystems or due
        # to mounting error

        # Compute size to copy
        size = 0
        for path in paths_needed_to_be_copied:
                # We don't do this in python with os.stat because we don't want
                # to follow symlinks
                size += int(subprocess.check_output(['du', '-sb', path['src']])
                           .split()[0].decode('utf-8'))
        size = size / 1024 / 1024

        # Ask confirmation for copying
        if size > MB_ALLOWED_TO_ORGANIZE:
            try:
                i = msignals.prompt(m18n.n('backup_ask_for_copying_if_needed',
                                        answers='y/N', size=size))
            except NotImplemented:
                logger.error(m18n.n('backup_unable_to_organize_files'))
            else:
                if i != 'y' and i != 'Y':
                    logger.error(m18n.n('backup_unable_to_organize_files'))

        # Copy unbinded path
        logger.info(m18n.n('backup_copying_to_organize_the_archive', size=size))
        for path in paths_needed_to_be_copied:
            if os.path.isdir(src):
                shutil.copytree(src, dest, symlinks=True)
            else:
                shutil.copy(src, dest)

    @classmethod
    def create(cls, method, **kwargs):
        """ Factory method to create instance of BackupMethod

        Args:
        method -- (string) The method name of an existing BackupMethod. If the
        name is unknown the CustomBackupMethod will be tried

        ...    -- Specific args for the method, could be the repo target by the
        method

        Return a BackupMethod instance
        """
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
    """This class just do an uncompress copy of each file in a
    location, and could be the inverse for restoring
    """
    def __init__(self, repo = None):
        super(CopyBackupMethod, self).__init__(repo)

    @property
    def method_name(self):
        return 'copy'

    def backup(self):
        """ Copy prepared files into a the repo """
        # Check free space in output
        self._check_is_enough_free_space()

        for path in self.manager.paths_to_backup:
            source = path['source']
            dest = os.path.join(self.manager.work_dir, path['dest'])
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
        """ Mount the uncompress backup in readonly mode to the working
        directory

        Exceptions:
        backup_no_uncompress_archive_dir -- Raised if the repo doesn't exists
        backup_cant_mount_uncompress_archive -- Raised if the binding failed
        """
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
    """This class compress all files to backup in archive. To
    restore it try to mount the archive with archivemount (fuse). Some system
    don't support fuse.
    """

    def __init__(self, repo=None):
        super(TarBackupMethod, self).__init__(repo)

    @property
    def method_name(self):
        return 'tar'

    def backup(self):
        """ Compress prepared files

        It adds the info.json in /home/yunohost.backup/archives and if the
        compress archive isn't located here, add a symlink to the archive to.

        Exceptions:
        backup_archive_open_failed -- Raised if we can't open the archive
        backup_creation_failed -- Raised if we can't write in the compress
            archive
        """
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

        Exceptions:
        backup_archive_open_failed -- Raised if the archive can't be open
        backup_archive_mount_failed -- Raised if the system don't support
        archivemount
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
            # FIXME in this case we should ask the user if we could make an
            # extraction (with a warning about disk space and waiting time
            logger.debug("cannot mount backup archive '%s'",
                         self._archive_file, exc_info=1)
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_archive_mount_failed'))

    @property
    def _archive_file(self):
        """Return the compress archive path"""
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
    """This class use a bash hook "backup_method" to do the
    backup/restore operations. A user can add his own hook inside
    /etc/yunohost/hooks.d/backup_method/
    """
    def __init__(self, repo = None, **kwargs):
        super(CustomBackupMethod, self).__init__(repo)
        self.args = kwargs
        self._need_mount = None

    @property
    def method_name(self):
        return 'borg'

    def need_mount(self):
        """Call the backup_method hook to know if we need to organize files

        Exceptions:
        backup_custom_need_mount_error -- Raised if the hook failed
        """
        ret = hook_callback('backup_method', method,
                            args=self._get_args('need_mount'))
        if ret['succeed']:
            return True
        else:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_custom_need_mount_error'))

    def backup(self):
        """Launch a custom script to backup

        Exceptions:
        backup_custom_backup_error -- Raised if the custom script failed
        """

        ret = hook_callback('backup_method', method,
                            args=self._get_args('backup'))
        if ret['failed']:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_custom_backup_error'))

    def mount(self, restore_manager):
        """Launch a custom script to mount the custom archive

        Exceptions:
        backup_custom_mount_error -- Raised if the custom script failed
        """
        super(CustomBackupMethod, self).mount(restore_manager)
        ret = hook_callback('backup_method', method,
                            args=self._get_args('mount'))
        if ret['failed']:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('backup_custom_mount_error'))

    def _get_args(self, action):
        """Return the arguments to give to the custom script"""
        return [action, self.work_dir, self.name, self.repo, self.manager.size,
                self.manager.description]


class RestoreManager:
    """RestoreManager allow to restore a past backup archive

    Currently it's a tar.gz file, but it could be another kind of archive

    Public properties:
        info (getter)i # FIXME
        work_dir (getter) # FIXME currently it's not a getter
        name (getter) # FIXME currently it's not a getter
        success (getter)
        result (getter) # FIXME

    Public methods:
        set_targets(self, system_parts=[], apps=[])
        restore(self)

    Usage:
        restore_manager = RestoreManager(name)

        restore_manager.set_targets(None, ['wordpress__3'])

        restore_manager.restore()

        if restore_manager.success:
            logger.success(m18n.n('restore_complete'))

        return restore_manager.result
    """

    def __init__(self, name, repo=None, method='tar'):
        """RestoreManager constructor

        Args:
        name -- (string) Archive name
        repo -- (string|None) Repository where is this archive, it could be a
                path (default: /home/yunohost.backup/archives)
        method -- (string) Method name to use to mount the archive
        """
        # Retrieve and open the archive
        self.info = backup_info(name, with_details=True)
        self.archive_path = self.info['path']
        self.name = name
        self.method = BackupMethod.create(method)
        self.results = {
            "system": {},
            "apps": {}
        }

    ###########################################################################
    #   Misc helpers                                                          #
    ###########################################################################

    @property
    def success(self):

        all_results = self.results["system"].values() + \
                      self.results["apps"].values()

        return "Success" in all_results \
            or "Warning" in all_results

    def _read_info_files(self):
        """Read the info containing in an archive

        Exceptions:
        backup_invalid_archive -- Raised if we can't read the info
        """
        # Retrieve backup info
        info_file = os.path.join(self.work_dir, "info.json")
        try:
            with open(info_file, 'r') as f:
                self.info = json.load(f)

            # Historically, "system" was "hooks"
            if "system" not in self.info.keys():
                self.info["system"] = self.info["hooks"]
        except IOError:
            logger.debug("unable to load '%s'", info_file, exc_info=1)
            raise MoulinetteError(errno.EIO, m18n.n('backup_invalid_archive'))
        else:
            logger.debug("restoring from backup '%s' created on %s", self.name,
                         time.ctime(self.info['created_at']))


    def _postinstall_if_needed(self):
        """Post install yunohost if needed

        Exceptions:
        backup_invalid_archive -- Raised if the current_host isn't in the
        archive
        """
        # Check if YunoHost is installed
        if not os.path.isfile('/etc/yunohost/installed'):
            # Retrieve the domain from the backup
            try:
                with open("%s/conf/ynh/current_host" % self.work_dir, 'r') as f:
                    domain = f.readline().rstrip()
            except IOError:
                logger.debug("unable to retrieve current_host from the backup",
                            exc_info=1)
                # FIXME include the current_host by default ?
                raise MoulinetteError(errno.EIO,
                                    m18n.n('backup_invalid_archive'))

            logger.debug("executing the post-install...")
            tools_postinstall(domain, 'yunohost', True)

    def clean(self):
        """End a restore operations by cleaning the working directory and
        regenerate ssowat conf"""

        if "Success" in self.results["apps"].values() \
        or "Warning" in self.results["apps"].values():
            # Quickfix: the old app_ssowatconf(auth) instruction failed due to
            # ldap restore hooks
            os.system('sudo yunohost app ssowatconf')

        if os.path.ismount(self.work_dir):
            ret = subprocess.call(["umount", self.work_dir])
            if ret != 0:
                logger.warning(m18n.n('restore_cleaning_failed'))
        filesystem.rm(self.work_dir, True, True)



    ###########################################################################
    #   Restore target manangement                                            #
    ###########################################################################

    def set_result(self, category, element, value):

        levels = [ "Unknown", "Success", "Warning", "Error", "Skipped" ]

        assert value in levels

        if element not in self.results[category].keys():
            self.results[category][element] = value
        else:
            currentValue = self.results[category][element]
            if (levels.index(currentValue) > levels.index(value)):
                return
            else:
                self.results[category][element] = value

    def set_targets(self, system_parts=[], apps=[]):
        """
        Define and validate targets to be restored (list of system parts,
        apps..)

        Args:
        system_parts -- (list) list of system parts which should be restored. If
        it's an empty list, it will restore all system part in the archive.
        If it's None, nothing will be restored.

        apps         -- (list) list of apps which should be restored. If apps is
        an empty list, all apps in the archive will be restored. If it's None,
        no apps will be restored.

        Exceptions:
        backup_archive_system_part_not_availablei -- Raised if the system part
        isn't in the archive
        backup_archive_app_not_found -- Raised if the app isn't in the archive
        """

        self.targets = {}

        #
        # System
        #

        # Look for the list of system parts available in the archive
        system_parts_in_archive = self.info['system'].keys()

        # If asked to restore nothing
        if system_parts is None:
            self.targets["system"] = []
        # If asked to restore everything
        elif system_parts == []:
            self.targets["system"] = system_parts_in_archive
        # Otherwise, we need to check that each part asked to restore are
        # available
        else:
            self.targets["system"] = [ part for part in system_parts
                                       if part in system_parts_in_archive ]

            unavailable_parts = [ part for part in system_parts
                                  if part in system_parts_in_archive ]

            # Display an error for each part that the user want to restore
            # but is not available in the archive
            for system_part in unavailable_parts:
                logger.error(m18n.n("backup_archive_system_part_not_available",
                                    part=system_part))
                self.set_result("system", system_part, "Skipped")

        # Now we need to check that the restore hook is actually available for
        # all targets we want to restore

        # These are the hooks on the current installation
        available_restore_system_hooks = hook_list("restore")["hooks"]

        for system_part in self.targets["system"]:
            # By default, we'll use the restore hooks on the current install
            # if available

            # FIXME: so if the restore hook exist we use the new one and not
            # the one from backup. So hook should not break compatibility..

            if system_part in available_restore_system_hooks:
                continue

            # Otherwise, attempt to find it (or them?) in the archive
            hook_paths = '{:s}/hooks/restore/*-{:s}'.format(self.work_dir, system_part)
            hook_paths = glob(hook_paths)

            # If we didn't find it, we ain't gonna be able to restore it
            if len(hook_paths) == 0:
                logger.exception(m18n.n('restore_hook_unavailable', part=system_part))
                self.targets["system"].remove(system_part)
                self.set_result("system", system_part, "Skipped")
                continue

            # Otherwise, add it from the archive to the system
            # FIXME: Refactor hook_add and use it instead
            custom_restore_hook_folder = os.path.join(CUSTOM_HOOK_FOLDER, 'restore')
            filesystem.mkdir(custom_restore_hook_folder, 755, True)
            for hook_path in hook_paths:
                logger.debug("Adding restoration script '%s' to the system "
                             "from the backup archive '%s'", hook_path,
                             self.archive_path)
            shutil.copy(hook_path, custom_restore_hook_folder)

        #
        # Apps
        #

        # List apps available in the archive
        apps_in_archive = self.info['apps'].keys()

        # None means "restore no apps"
        if apps is None:
            self.targets["apps"] = []
        # Empty list means "everything available in archive"
        elif apps == []:
            self.targets["apps"] = apps_in_archive
        # Otherwise, we need to check that the apps choosen by the user are
        # effectively in the archive
        else:
            self.targets["apps"] = [ app for app in apps
                                         if app in apps_in_archive]

            unavailable_apps = [ app for app in apps
                                     if app not in apps_in_archive ]

            # Display an error for each app that the user want to restore
            # but is not available in the archive
            for app in unavailable_apps:
                    logger.error(m18n.n('backup_archive_app_not_found', app=app))
                    self.set_result("apps", app, "Skipped")

        #
        # Init result
        #

        # For target with no result yet (like 'Skipped'), set it as unknown
        for category in [ "apps", "system" ]:
            for target in self.targets[category]:
                self.set_result(category, target, "Unknown")

    ###########################################################################
    #   Archive mounting                                                      #
    ###########################################################################

    def _mount(self):
        """
        Mount the archive. We avoid copy to be able to restore on system without
        too many space.

        Use the mount method from the BackupMethod instance and read info about
        this archive

        Exceptions:
        restore_removing_tmp_dir_failed -- Raised if it's not possible to remove
        the working directory
        """

        self.work_dir = os.path.join(BACKUP_PATH, "tmp", self.name)

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

    ###########################################################################
    #   Space computation / checks                                            #
    ###########################################################################

    def _compute_needed_space(self):
        """Compute needed space to be able to restore

        Return:
        size   -- (int) needed space to backup in bytes
        margin -- (int) margin to be sure the backup don't fail by missing space
                  in bytes
        """
        system = self.targets["system"]
        apps = self.targets["apps"]
        restore_all_system = (system == self.info['system'].keys())
        restore_all_apps = (apps == self.info['apps'].keys())

        # If complete restore operations (or legacy archive)
        margin = CONF_MARGIN_SPACE_SIZE * 1024 * 1024
        if (restore_all_system and restore_all_apps) or 'size_details' not in self.info:
            size = self.info['size']
            if 'size_details' not in self.info or \
               self.info['size_details']['apps'] != {}:
                margin = APP_MARGIN_SPACE_SIZE * 1024 * 1024
        # Partial restore don't need all backup size
        else:
            size = 0
            if system is not None:
                for system_element in system:
                    size += self.info['size_details']['system'][system_element]

            # TODO how to know the dependencies size ?
            if apps is not None:
                for app in apps:
                    size += self.info['size_details']['apps'][app]
                    margin = APP_MARGIN_SPACE_SIZE * 1024 * 1024

        if not os.path.isfile('/etc/yunohost/installed'):
            size += POSTINSTALL_ESTIMATE_SPACE_SIZE * 1024 * 1024
        return (size, margin)

    def _check_free_space(self):
        """ Check available disk space

        Exceptions:
        restore_may_be_not_enough_disk_space -- Raised if there isn't enough
        space to cover the security margin space
        restore_not_enough_disk_space -- Raised if there isn't enough space
        """
        statvfs = os.statvfs(BACKUP_PATH)
        free_space = statvfs.f_frsize * statvfs.f_bavail
        (needed_space, margin) = self._compute_needed_space()
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

    ###########################################################################
    #   "Actual restore" (reverse step of the backup collect part)            #
    ###########################################################################

    def restore(self):
        """Restore the archive

        Restore system parts and apps after mounting the archive, checking free
        space and postinstall if needed
        """

        self._mount()

        try:
            self._check_free_space()
            self._postinstall_if_needed()
            self._restore_system()
            self._restore_apps()
        finally:
            self.clean()


    def _restore_system(self):
        """ Restore user and system parts """

        # If nothing to restore, return immediately
        if self.targets["system"] == []:
            return

        logger.info(m18n.n('restore_running_hooks'))

        # FIXME Add environment variables !!!!
        ret = hook_callback('restore',
                            self.targets["system"],
                            args=[self.work_dir])

        for part in ret['succeed'].keys():
            self.set_result("system", part, "Success")

        for part in ret['failed'].keys():
            logger.error(m18n.n('restore_system_part_failed', part=part))
            self.set_result("system", part, "Error")

    def _restore_apps(self):
        """Restore all apps targeted"""
        for app in self.targets["apps"]:
            self._restore_app(app)

    def _restore_app(self, app_instance_name):
        """Restore an app

        Environment variables:
        YNH_BACKUP_DIR -- The backup working directory (in
                          "/home/yunohost.backup/tmp/BACKUPNAME" or could be
                          defined by the user)
        YNH_BACKUP_CSV -- A temporary CSV where the script whould list paths toi
                          backup
        YNH_APP_BACKUP_DIR -- The directory where the script should put
                              temporary files to backup like database dump,
                              files in this directory don't need to be added to
                              the temporary CSV.
        YNH_APP_ID     -- The app id (eg wordpress)
        YNH_APP_INSTANCE_NAME -- The app instance name (eg wordpress__3)
        YNH_APP_INSTANCE_NUMBER  -- The app instance number (eg 3)

        Args:
        app_instance_name -- (string) The app name to restore (no app with this
        name should be already install)

        Exceptions:
        restore_already_installed_app -- Raised if an app with this app instance
        name already exists
        restore_app_failed -- Raised if the restore bash script failed
        """
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
                      raise_on_error=True, chdir=tmp_app_bkp_dir, env=env_dict, user="root")
        except:
            logger.exception(m18n.n('restore_app_failed',
                                    app=app_instance_name))
            self.set_result("apps", app_instance_name, "Error")

            app_script = os.path.join(tmp_script_dir, 'remove')

            # Setup environment for remove script
            env_dict_remove = {}
            env_dict_remove["YNH_APP_ID"] = app_id
            env_dict_remove["YNH_APP_INSTANCE_NAME"] = app_instance_name
            env_dict_remove["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)

            # Execute remove script
            # TODO: call app_remove instead
            if hook_exec(app_script, args=[app_instance_name],
                         env=env_dict_remove, user="root") != 0:
                logger.warning(m18n.n('app_not_properly_removed',
                                      app=app_instance_name))

            # Cleaning app directory
            shutil.rmtree(app_setting_path, ignore_errors=True)


            # TODO Cleaning app hooks
        else:
            self.set_result("apps", app_instance_name, "Success")
        finally:
            # Cleaning temporary scripts directory
            shutil.rmtree(tmp_script_dir, ignore_errors=True)

    def _get_env_var(self):
        """ Define environment variable for hooks call """
        env_var = {}
        env_var['YNH_BACKUP_DIR'] = self.work_dir
        env_var['YNH_BACKUP_CSV'] = os.path.join(self.work_dir, "backup.csv")
        return env_var


###############################################################################
#   "Front-end"                                                               #
###############################################################################

def backup_create(name=None, description=None, methods=[],
                  output_directory=None, no_compress=False,
                  ignore_system=False, system=[],
                  ignore_apps=False, apps=[],
                  ignore_hooks=False, hooks=[]):
    """
    Create a backup local archive

    Keyword arguments:
        name -- Name of the backup archive
        description -- Short description of the backup
        method -- Method of backup to use
        output_directory -- Output directory for the backup
        no_compress -- Do not create an archive file
        system -- List of system elements to backup
        ignore_system -- Ignore system elements
        apps -- List of application names to backup
        ignore_apps -- Do not backup apps

        hooks -- (Deprecated) Renamed to "system"
        ignore_hooks -- (Deprecated) Renamed to "ignore_system"
    """

    # TODO: Add a 'clean' argument to clean output directory

    # Historical, deprecated options
    if ignore_hooks != False:
        logger.warning("--ignore-hooks is deprecated and will be removed in the"
                       "future. Please use --ignore-system instead.")
        ignore_system = ignore_hooks

    if hooks != [] and hooks is not None:
        logger.warning("--hooks is deprecated and will be removed in the"
                       "future. Please use --system instead.")
        system = hooks


    def _prevalidate_backup_call(name, output_directory, no_compress,
                                 ignore_system, ignore_apps, methods):
        """ Validate backup request is conform """

        # Validate what to backup
        if ignore_system and ignore_apps:
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
    _prevalidate_backup_call(name, output_directory, no_compress, ignore_system,
                             ignore_apps, methods)

    # Create yunohost archives directory if it does not exists
    _create_archive_dir()

    # Define output_directory
    if output_directory:
        output_directory = os.path.abspath(output_directory)

    # Define methods (retro-compat)
    if methods == []:
        if no_compress:
            methods = ['copy']
        else:
            methods = ['tar']  # In future, borg will be the default actions

    if ignore_system:
        system = None
    elif system is None:
        system = []

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

    # Add backup targets (system and apps)
    backup_manager.set_targets(system, apps)

    # Collect files to be backup (by calling app backup script / system hooks)
    backup_manager.collect_files()

    # Apply backup methods on prepared files
    backup_manager.backup()

    logger.success(m18n.n('backup_created'))

    # Return backup info
    #info = backup_manager.info
    #info['name'] = backup_manager.name
    #return {'archive': info}
    return backup_manager.results


def backup_restore(auth, name,
                   system=[], ignore_system=False,
                   apps=[], ignore_apps=False,
                   hooks=[], ignore_hooks=False,
                   force=False):
    """
    Restore from a local backup archive

    Keyword argument:
        name -- Name of the local backup archive
        force -- Force restauration on an already installed system
        system -- List of system parts to restore
        ignore_system -- Do not restore any system parts
        apps -- List of application names to restore
        ignore_apps -- Do not restore apps

        hooks -- (Deprecated) Renamed to "system"
        ignore_hooks -- (Deprecated) Renamed to "ignore_system"
    """

    # Historical, deprecated options
    if ignore_hooks != False:
        logger.warning("--ignore-hooks is deprecated and will be removed in the"
                       "future. Please use --ignore-system instead.")
        ignore_system = ignore_hooks
    if hooks != []:
        logger.warning("--hooks is deprecated and will be removed in the"
                       "future. Please use --system instead.")
        system = hooks

    # Validate what to restore
    if ignore_system and ignore_apps:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('restore_action_required'))

    # TODO don't ask this question when restoring apps only and certain system
    # parts

    # Check if YunoHost is installed
    if os.path.isfile('/etc/yunohost/installed') and not ignore_system:
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

    if ignore_system:
        system = None
    elif system is None:
        system = []

    if ignore_apps:
        apps = None
    elif apps is None:
        apps = []

    # TODO Partial app restore could not work if ldap is not restored before
    # TODO repair mysql if broken and it's a complete restore

    restore_manager = RestoreManager(name)

    restore_manager.set_targets(system, apps)
    restore_manager.restore()

    # Check if something has been restored
    if restore_manager.success:
        logger.success(m18n.n('restore_complete'))
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('restore_nothings_done'))

    return restore_manager.results


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

    if not os.path.exists(info_file):
        tar = tarfile.open(archive_file, "r:gz")
        info_dir = info_file + '.d'
        tar.extract('info.json', path=info_dir)
        tar.close()
        shutil.move(os.path.join(info_dir, 'info.json'), info_file)
        os.rmdir(info_dir)

    try:
        with open(info_file) as f:
            # Retrieve backup info
            info = json.load(f)
    except:
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
        system_key = "system"
        # Historically 'system' was 'hooks'
        if "hooks" in info.keys():
            system_key = "hooks"

        result["apps"] = info["apps"]
        result["system"] = info[system_key]
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
