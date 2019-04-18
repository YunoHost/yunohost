# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2019 YunoHost

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

import os
import yaml
import json
import subprocess
import shutil
import hashlib

from difflib import unified_diff
from datetime import datetime

from moulinette import m18n
from moulinette.utils import log, filesystem
from moulinette.utils.filesystem import read_file

from yunohost.utils.error import YunohostError
from yunohost.log import is_unit_operation
from yunohost.hook import hook_callback, hook_list

BASE_CONF_PATH = '/home/yunohost.conf'
BACKUP_CONF_DIR = os.path.join(BASE_CONF_PATH, 'backup')
PENDING_CONF_DIR = os.path.join(BASE_CONF_PATH, 'pending')
REGEN_CONF_FILE = '/etc/yunohost/regenconf.yml'

logger = log.getActionLogger('yunohost.regenconf')


# FIXME : those ain't just services anymore ... what are we supposed to do with this ...
# FIXME : check for all reference of 'service' close to operation_logger stuff
@is_unit_operation([('names', 'configuration')])
def regen_conf(operation_logger, names=[], with_diff=False, force=False, dry_run=False,
                       list_pending=False):
    """
    Regenerate the configuration file(s)

    Keyword argument:
        names -- Categories to regenerate configuration of
        with_diff -- Show differences in case of configuration changes
        force -- Override all manual modifications in configuration files
        dry_run -- Show what would have been regenerated
        list_pending -- List pending configuration files and exit

    """

    # Legacy code to automatically run the migration
    # This is required because regen_conf is called before the migration call
    # in debian's postinst script
    if os.path.exists("/etc/yunohost/installed") \
       and ("conffiles" in read_file("/etc/yunohost/services.yml") \
            or not os.path.exists(REGEN_CONF_FILE)):
        from yunohost.tools import _get_migration_by_name
        migration = _get_migration_by_name("decouple_regenconf_from_services")
        migration.migrate()

    result = {}

    # Return the list of pending conf
    if list_pending:
        pending_conf = _get_pending_conf(names)

        if not with_diff:
            return pending_conf

        for category, conf_files in pending_conf.items():
            for system_path, pending_path in conf_files.items():

                pending_conf[category][system_path] = {
                    'pending_conf': pending_path,
                    'diff': _get_files_diff(
                        system_path, pending_path, True),
                }

        return pending_conf

    if not dry_run:
        operation_logger.related_to = [('configuration', x) for x in names]
        if not names:
            operation_logger.name_parameter_override = 'all'
        elif len(names) != 1:
            operation_logger.name_parameter_override = str(len(operation_logger.related_to)) + '_categories'
        operation_logger.start()

    # Clean pending conf directory
    if os.path.isdir(PENDING_CONF_DIR):
        if not names:
            shutil.rmtree(PENDING_CONF_DIR, ignore_errors=True)
        else:
            for name in names:
                shutil.rmtree(os.path.join(PENDING_CONF_DIR, name),
                              ignore_errors=True)
    else:
        filesystem.mkdir(PENDING_CONF_DIR, 0o755, True)

    # Format common hooks arguments
    common_args = [1 if force else 0, 1 if dry_run else 0]

    # Execute hooks for pre-regen
    pre_args = ['pre', ] + common_args

    def _pre_call(name, priority, path, args):
        # create the pending conf directory for the category
        category_pending_path = os.path.join(PENDING_CONF_DIR, name)
        filesystem.mkdir(category_pending_path, 0o755, True, uid='root')

        # return the arguments to pass to the script
        return pre_args + [category_pending_path, ]

    # Don't regen SSH if not specifically specified
    if not names:
        names = hook_list('conf_regen', list_by='name',
                          show_info=False)['hooks']
        names.remove('ssh')

    pre_result = hook_callback('conf_regen', names, pre_callback=_pre_call)

    # Keep only the hook names with at least one success
    names = [hook for hook, infos in pre_result.items()
             if any(result["state"] == "succeed" for result in infos.values())]

    # FIXME : what do in case of partial success/failure ...
    if not names:
        ret_failed = [hook for hook, infos in pre_result.items()
                      if any(result["state"] == "failed" for result in infos.values())]
        raise YunohostError('regenconf_failed',
                            categories=', '.join(ret_failed))

    # Set the processing method
    _regen = _process_regen_conf if not dry_run else lambda *a, **k: True

    operation_logger.related_to = []

    # Iterate over categories and process pending conf
    for category, conf_files in _get_pending_conf(names).items():
        if not dry_run:
            operation_logger.related_to.append(('configuration', category))

        logger.debug(m18n.n(
            'regenconf_pending_applying' if not dry_run else
            'regenconf_dry_pending_applying',
            category=category))

        conf_hashes = _get_conf_hashes(category)
        succeed_regen = {}
        failed_regen = {}

        for system_path, pending_path in conf_files.items():
            logger.debug("processing pending conf '%s' to system conf '%s'",
                         pending_path, system_path)
            conf_status = None
            regenerated = False

            # Get the diff between files
            conf_diff = _get_files_diff(
                system_path, pending_path, True) if with_diff else None

            # Check if the conf must be removed
            to_remove = True if os.path.getsize(pending_path) == 0 else False

            # Retrieve and calculate hashes
            system_hash = _calculate_hash(system_path)
            saved_hash = conf_hashes.get(system_path, None)
            new_hash = None if to_remove else _calculate_hash(pending_path)

            # -> system conf does not exists
            if not system_hash:
                if to_remove:
                    logger.debug("> system conf is already removed")
                    os.remove(pending_path)
                    continue
                if not saved_hash or force:
                    if force:
                        logger.debug("> system conf has been manually removed")
                        conf_status = 'force-created'
                    else:
                        logger.debug("> system conf does not exist yet")
                        conf_status = 'created'
                    regenerated = _regen(
                        system_path, pending_path, save=False)
                else:
                    logger.info(m18n.n(
                        'regenconf_file_manually_removed',
                        conf=system_path))
                    conf_status = 'removed'

            # -> system conf is not managed yet
            elif not saved_hash:
                logger.debug("> system conf is not managed yet")
                if system_hash == new_hash:
                    logger.debug("> no changes to system conf has been made")
                    conf_status = 'managed'
                    regenerated = True
                elif not to_remove:
                    # If the conf exist but is not managed yet, and is not to be removed,
                    # we assume that it is safe to regen it, since the file is backuped
                    # anyway (by default in _regen), as long as we warn the user
                    # appropriately.
                    logger.info(m18n.n('regenconf_now_managed_by_yunohost',
                                       conf=system_path, category=category))
                    regenerated = _regen(system_path, pending_path)
                    conf_status = 'new'
                elif force:
                    regenerated = _regen(system_path)
                    conf_status = 'force-removed'
                else:
                    logger.info(m18n.n('regenconf_file_kept_back',
                                       conf=system_path, category=category))
                    conf_status = 'unmanaged'

            # -> system conf has not been manually modified
            elif system_hash == saved_hash:
                if to_remove:
                    regenerated = _regen(system_path)
                    conf_status = 'removed'
                elif system_hash != new_hash:
                    regenerated = _regen(system_path, pending_path)
                    conf_status = 'updated'
                else:
                    logger.debug("> system conf is already up-to-date")
                    os.remove(pending_path)
                    continue

            else:
                logger.debug("> system conf has been manually modified")
                if system_hash == new_hash:
                    logger.debug("> new conf is as current system conf")
                    conf_status = 'managed'
                    regenerated = True
                elif force:
                    regenerated = _regen(system_path, pending_path)
                    conf_status = 'force-updated'
                else:
                    logger.warning(m18n.n(
                        'regenconf_file_manually_modified',
                        conf=system_path))
                    conf_status = 'modified'

            # Store the result
            conf_result = {'status': conf_status}
            if conf_diff is not None:
                conf_result['diff'] = conf_diff
            if regenerated:
                succeed_regen[system_path] = conf_result
                conf_hashes[system_path] = new_hash
                if os.path.isfile(pending_path):
                    os.remove(pending_path)
            else:
                failed_regen[system_path] = conf_result

        # Check for category conf changes
        if not succeed_regen and not failed_regen:
            logger.debug(m18n.n('regenconf_up_to_date', category=category))
            continue
        elif not failed_regen:
            logger.success(m18n.n(
                'regenconf_updated' if not dry_run else
                'regenconf_would_be_updated',
                category=category))

        if succeed_regen and not dry_run:
            _update_conf_hashes(category, conf_hashes)

        # Append the category results
        result[category] = {
            'applied': succeed_regen,
            'pending': failed_regen
        }

    # Return in case of dry run
    if dry_run:
        return result

    # Execute hooks for post-regen
    post_args = ['post', ] + common_args

    def _pre_call(name, priority, path, args):
        # append coma-separated applied changes for the category
        if name in result and result[name]['applied']:
            regen_conf_files = ','.join(result[name]['applied'].keys())
        else:
            regen_conf_files = ''
        return post_args + [regen_conf_files, ]

    hook_callback('conf_regen', names, pre_callback=_pre_call)

    operation_logger.success()

    return result


def _get_regenconf_infos():
    """
    Get a dict of regen conf informations
    """
    try:
        with open(REGEN_CONF_FILE, 'r') as f:
            return yaml.load(f)
    except:
        return {}


def _save_regenconf_infos(infos):
    """
    Save the regen conf informations
    Keyword argument:
        categories -- A dict containing the regenconf infos
    """
    try:
        with open(REGEN_CONF_FILE, 'w') as f:
            yaml.safe_dump(infos, f, default_flow_style=False)
    except Exception as e:
        logger.warning('Error while saving regenconf infos, exception: %s', e, exc_info=1)
        raise


def _get_files_diff(orig_file, new_file, as_string=False, skip_header=True):
    """Compare two files and return the differences

    Read and compare two files. The differences are returned either as a delta
    in unified diff format or a formatted string if as_string is True. The
    header can also be removed if skip_header is True.

    """

    if os.path.exists(orig_file):
        with open(orig_file, 'r') as orig_file:
            orig_file = orig_file.readlines()
    else:
        orig_file = []

    if os.path.exists(new_file):
        with open(new_file, 'r') as new_file:
            new_file = new_file.readlines()
    else:
        new_file = []

    # Compare files and format output
    diff = unified_diff(orig_file, new_file)

    if skip_header:
        try:
            next(diff)
            next(diff)
        except:
            pass

    if as_string:
        return ''.join(diff).rstrip()

    return diff


def _calculate_hash(path):
    """Calculate the MD5 hash of a file"""

    if not os.path.exists(path):
        return None

    hasher = hashlib.md5()

    try:
        with open(path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    except IOError as e:
        logger.warning("Error while calculating file '%s' hash: %s", path, e, exc_info=1)
        return None


def _get_pending_conf(categories=[]):
    """Get pending configuration for categories

    Iterate over the pending configuration directory for given categories - or
    all if empty - and look for files inside. Each file is considered as a
    pending configuration file and therefore must be in the same directory
    tree than the system file that it replaces.
    The result is returned as a dict of categories with pending configuration as
    key and a dict of `system_conf_path` => `pending_conf_path` as value.

    """
    result = {}

    if not os.path.isdir(PENDING_CONF_DIR):
        return result

    if not categories:
        categories = os.listdir(PENDING_CONF_DIR)

    for name in categories:
        category_pending_path = os.path.join(PENDING_CONF_DIR, name)

        if not os.path.isdir(category_pending_path):
            continue

        path_index = len(category_pending_path)
        category_conf = {}

        for root, dirs, files in os.walk(category_pending_path):
            for filename in files:
                pending_path = os.path.join(root, filename)
                category_conf[pending_path[path_index:]] = pending_path

        if category_conf:
            result[name] = category_conf
        else:
            # remove empty directory
            shutil.rmtree(category_pending_path, ignore_errors=True)

    return result


def _get_conf_hashes(category):
    """Get the registered conf hashes for a category"""

    categories = _get_regenconf_infos()

    if category not in categories:
        logger.debug("category %s is not in categories.yml yet.", category)
        return {}

    elif categories[category] is None or 'conffiles' not in categories[category]:
        logger.debug("No configuration files for category %s.", category)
        return {}

    else:
        return categories[category]['conffiles']


def _update_conf_hashes(category, hashes):
    """Update the registered conf hashes for a category"""
    logger.debug("updating conf hashes for '%s' with: %s",
                 category, hashes)

    categories = _get_regenconf_infos()
    category_conf = categories.get(category, {})

    # Handle the case where categories[category] is set to null in the yaml
    if category_conf is None:
        category_conf = {}

    category_conf['conffiles'] = hashes
    categories[category] = category_conf
    _save_regenconf_infos(categories)


def _process_regen_conf(system_conf, new_conf=None, save=True):
    """Regenerate a given system configuration file

    Replace a given system configuration file by a new one or delete it if
    new_conf is None. A backup of the file - keeping its directory tree - will
    be done in the backup conf directory before any operation if save is True.

    """
    if save:
        backup_path = os.path.join(BACKUP_CONF_DIR, '{0}-{1}'.format(
            system_conf.lstrip('/'), datetime.utcnow().strftime("%Y%m%d.%H%M%S")))
        backup_dir = os.path.dirname(backup_path)

        if not os.path.isdir(backup_dir):
            filesystem.mkdir(backup_dir, 0o755, True)

        shutil.copy2(system_conf, backup_path)
        logger.debug(m18n.n('regenconf_file_backed_up',
                            conf=system_conf, backup=backup_path))

    try:
        if not new_conf:
            os.remove(system_conf)
            logger.debug(m18n.n('regenconf_file_removed',
                                conf=system_conf))
        else:
            system_dir = os.path.dirname(system_conf)

            if not os.path.isdir(system_dir):
                filesystem.mkdir(system_dir, 0o755, True)

            shutil.copyfile(new_conf, system_conf)
            logger.debug(m18n.n('regenconf_file_updated',
                                conf=system_conf))
    except Exception as e:
        logger.warning("Exception while trying to regenerate conf '%s': %s", system_conf, e, exc_info=1)
        if not new_conf and os.path.exists(system_conf):
            logger.warning(m18n.n('regenconf_file_remove_failed',
                                  conf=system_conf),
                           exc_info=1)
            return False

        elif new_conf:
            try:
                # From documentation:
                # Raise an exception if an os.stat() call on either pathname fails.
                # (os.stats returns a series of information from a file like type, size...)
                copy_succeed = os.path.samefile(system_conf, new_conf)
            except:
                copy_succeed = False
            finally:
                if not copy_succeed:
                    logger.warning(m18n.n('regenconf_file_copy_failed',
                                          conf=system_conf, new=new_conf),
                                   exc_info=1)
                    return False

    return True


def manually_modified_files():

    # We do this to have --quiet, i.e. don't throw a whole bunch of logs
    # just to fetch this...
    # Might be able to optimize this by looking at what the regen conf does
    # and only do the part that checks file hashes...
    cmd = "yunohost tools regen-conf --dry-run --output-as json --quiet"
    j = json.loads(subprocess.check_output(cmd.split()))

    # j is something like :
    # {"postfix": {"applied": {}, "pending": {"/etc/postfix/main.cf": {"status": "modified"}}}

    output = []
    for app, actions in j.items():
        for action, files in actions.items():
            for filename, infos in files.items():
                if infos["status"] == "modified":
                    output.append(filename)

    return output


def manually_modified_files_compared_to_debian_default():

    # from https://serverfault.com/a/90401
    r = subprocess.check_output("dpkg-query -W -f='${Conffiles}\n' '*' \
                                | awk 'OFS=\"  \"{print $2,$1}' \
                                | md5sum -c 2>/dev/null \
                                | awk -F': ' '$2 !~ /OK/{print $1}'", shell=True)
    return r.strip().split("\n")
