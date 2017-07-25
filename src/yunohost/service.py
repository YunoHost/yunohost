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

""" yunohost_service.py

    Manage services
"""
import os
import time
import yaml
import glob
import subprocess
import errno
import shutil
import hashlib
from difflib import unified_diff

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils import log, filesystem

from yunohost.hook import hook_callback


BASE_CONF_PATH = '/home/yunohost.conf'
BACKUP_CONF_DIR = os.path.join(BASE_CONF_PATH, 'backup')
PENDING_CONF_DIR = os.path.join(BASE_CONF_PATH, 'pending')

logger = log.getActionLogger('yunohost.service')


def service_add(name, status=None, log=None, runlevel=None):
    """
    Add a custom service

    Keyword argument:
        name -- Service name to add
        status -- Custom status command
        log -- Absolute path to log file to display
        runlevel -- Runlevel priority of the service

    """
    services = _get_services()

    if not status:
        services[name] = {'status': 'service'}
    else:
        services[name] = {'status': status}

    if log is not None:
        services[name]['log'] = log

    if runlevel is not None:
        services[name]['runlevel'] = runlevel

    try:
        _save_services(services)
    except:
        raise MoulinetteError(errno.EIO, m18n.n('service_add_failed', service=name))

    logger.success(m18n.n('service_added', service=name))


def service_remove(name):
    """
    Remove a custom service

    Keyword argument:
        name -- Service name to remove

    """
    services = _get_services()

    try:
        del services[name]
    except KeyError:
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', service=name))

    try:
        _save_services(services)
    except:
        raise MoulinetteError(errno.EIO, m18n.n('service_remove_failed', service=name))

    logger.success(m18n.n('service_removed', service=name))


def service_start(names):
    """
    Start one or more services

    Keyword argument:
        names -- Services name to start

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('start', name):
            logger.success(m18n.n('service_started', service=name))
        else:
            if service_status(name)['status'] != 'running':
                raise MoulinetteError(errno.EPERM,
                                      m18n.n('service_start_failed', service=name))
            logger.info(m18n.n('service_already_started', service=name))


def service_stop(names):
    """
    Stop one or more services

    Keyword argument:
        name -- Services name to stop

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('stop', name):
            logger.success(m18n.n('service_stopped', service=name))
        else:
            if service_status(name)['status'] != 'inactive':
                raise MoulinetteError(errno.EPERM,
                                      m18n.n('service_stop_failed', service=name))
            logger.info(m18n.n('service_already_stopped', service=name))


def service_enable(names):
    """
    Enable one or more services

    Keyword argument:
        names -- Services name to enable

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('enable', name):
            logger.success(m18n.n('service_enabled', service=name))
        else:
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('service_enable_failed', service=name))


def service_disable(names):
    """
    Disable one or more services

    Keyword argument:
        names -- Services name to disable

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('disable', name):
            logger.success(m18n.n('service_disabled', service=name))
        else:
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('service_disable_failed', service=name))


def service_status(names=[]):
    """
    Show status information about one or more services (all by default)

    Keyword argument:
        names -- Services name to show

    """
    services = _get_services()
    check_names = True
    result = {}

    if isinstance(names, str):
        names = [names]
    elif len(names) == 0:
        names = services.keys()
        check_names = False

    for name in names:
        if check_names and name not in services.keys():
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('service_unknown', service=name))

        status = None
        if services[name].get('status') == 'service':
            status = 'service %s status' % name
        elif "status" in services[name]:
            status = str(services[name]['status'])
        else:
            continue

        runlevel = 5
        if 'runlevel' in services[name].keys():
            runlevel = int(services[name]['runlevel'])

        result[name] = {'status': 'unknown', 'loaded': 'unknown'}

        # Retrieve service status
        try:
            ret = subprocess.check_output(status, stderr=subprocess.STDOUT,
                                          shell=True)
        except subprocess.CalledProcessError as e:
            if 'usage:' in e.output.lower():
                logger.warning(m18n.n('service_status_failed', service=name))
            else:
                result[name]['status'] = 'inactive'
        else:
            result[name]['status'] = 'running'

        # Retrieve service loading
        rc_path = glob.glob("/etc/rc%d.d/S[0-9][0-9]%s" % (runlevel, name))
        if len(rc_path) == 1 and os.path.islink(rc_path[0]):
            result[name]['loaded'] = 'enabled'
        elif os.path.isfile("/etc/init.d/%s" % name):
            result[name]['loaded'] = 'disabled'
        else:
            result[name]['loaded'] = 'not-found'

    if len(names) == 1:
        return result[names[0]]
    return result


def service_log(name, number=50):
    """
    Log every log files of a service

    Keyword argument:
        name -- Service name to log
        number -- Number of lines to display

    """
    services = _get_services()

    if name not in services.keys():
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', service=name))

    if 'log' in services[name]:
        log_list = services[name]['log']
        result = {}
        if not isinstance(log_list, list):
            log_list = [log_list]

        for log_path in log_list:
            if os.path.isdir(log_path):
                for log in [f for f in os.listdir(log_path) if os.path.isfile(os.path.join(log_path, f)) and f[-4:] == '.log']:
                    result[os.path.join(log_path, log)] = _tail(os.path.join(log_path, log), int(number))
            else:
                result[log_path] = _tail(log_path, int(number))
    else:
        raise MoulinetteError(errno.EPERM, m18n.n('service_no_log', service=name))

    return result


def service_regen_conf(names=[], with_diff=False, force=False, dry_run=False,
                       list_pending=False):
    """
    Regenerate the configuration file(s) for a service

    Keyword argument:
        names -- Services name to regenerate configuration of
        with_diff -- Show differences in case of configuration changes
        force -- Override all manual modifications in configuration files
        dry_run -- Show what would have been regenerated
        list_pending -- List pending configuration files and exit

    """
    result = {}

    # Return the list of pending conf
    if list_pending:
        pending_conf = _get_pending_conf(names)
        if with_diff:
            for service, conf_files in pending_conf.items():
                for system_path, pending_path in conf_files.items():
                    pending_conf[service][system_path] = {
                        'pending_conf': pending_path,
                        'diff': _get_files_diff(
                            system_path, pending_path, True),
                    }
        return pending_conf

    # Clean pending conf directory
    if os.path.isdir(PENDING_CONF_DIR):
        if not names:
            shutil.rmtree(PENDING_CONF_DIR, ignore_errors=True)
        else:
            for name in names:
                shutil.rmtree(os.path.join(PENDING_CONF_DIR, name),
                              ignore_errors=True)
    else:
        filesystem.mkdir(PENDING_CONF_DIR, 0755, True)

    # Format common hooks arguments
    common_args = [1 if force else 0, 1 if dry_run else 0]

    # Execute hooks for pre-regen
    pre_args = ['pre', ] + common_args

    def _pre_call(name, priority, path, args):
        # create the pending conf directory for the service
        service_pending_path = os.path.join(PENDING_CONF_DIR, name)
        filesystem.mkdir(service_pending_path, 0755, True, uid='admin')
        # return the arguments to pass to the script
        return pre_args + [service_pending_path, ]
    pre_result = hook_callback('conf_regen', names, pre_callback=_pre_call)

    # Update the services name
    names = pre_result['succeed'].keys()
    if not names:
        raise MoulinetteError(errno.EIO,
                              m18n.n('service_regenconf_failed',
                                     services=', '.join(pre_result['failed'])))

    # Set the processing method
    _regen = _process_regen_conf if not dry_run else lambda *a, **k: True

    # Iterate over services and process pending conf
    for service, conf_files in _get_pending_conf(names).items():
        logger.info(m18n.n(
            'service_regenconf_pending_applying' if not dry_run else
            'service_regenconf_dry_pending_applying',
            service=service))

        conf_hashes = _get_conf_hashes(service)
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
                    logger.warning(m18n.n(
                        'service_conf_file_manually_removed',
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
                    logger.warning(m18n.n('service_conf_new_managed_file',
                                          conf=system_path, service=service))
                    regenerated = _regen(system_path, pending_path)
                    conf_status = 'new'
                elif force:
                    regenerated = _regen(system_path)
                    conf_status = 'force-removed'
                else:
                    logger.warning(m18n.n('service_conf_file_kept_back',
                                          conf=system_path, service=service))
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
                        'service_conf_file_manually_modified',
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

        # Check for service conf changes
        if not succeed_regen and not failed_regen:
            logger.info(m18n.n('service_conf_up_to_date', service=service))
            continue
        elif not failed_regen:
            logger.success(m18n.n(
                'service_conf_updated' if not dry_run else
                'service_conf_would_be_updated',
                service=service))
        if succeed_regen and not dry_run:
            _update_conf_hashes(service, conf_hashes)

        # Append the service results
        result[service] = {
            'applied': succeed_regen,
            'pending': failed_regen
        }

    # Return in case of dry run
    if dry_run:
        return result

    # Execute hooks for post-regen
    post_args = ['post', ] + common_args

    def _pre_call(name, priority, path, args):
        # append coma-separated applied changes for the service
        if name in result and result[name]['applied']:
            regen_conf_files = ','.join(result[name]['applied'].keys())
        else:
            regen_conf_files = ''
        return post_args + [regen_conf_files, ]
    hook_callback('conf_regen', names, pre_callback=_pre_call)

    return result


def _run_service_command(action, service):
    """
    Run services management command (start, stop, enable, disable, restart, reload)

    Keyword argument:
        action -- Action to perform
        service -- Service name

    """
    if service not in _get_services().keys():
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', service=service))

    cmd = None
    if action in ['start', 'stop', 'restart', 'reload']:
        cmd = 'service %s %s' % (service, action)
    elif action in ['enable', 'disable']:
        arg = 'defaults' if action == 'enable' else 'remove'
        cmd = 'update-rc.d %s %s' % (service, arg)
    else:
        raise ValueError("Unknown action '%s'" % action)

    try:
        ret = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        # TODO: Log output?
        logger.warning(m18n.n('service_cmd_exec_failed', command=' '.join(e.cmd)))
        return False
    return True


def _get_services():
    """
    Get a dict of managed services with their parameters

    """
    try:
        with open('/etc/yunohost/services.yml', 'r') as f:
            services = yaml.load(f)
    except:
        return {}
    else:
        return services


def _save_services(services):
    """
    Save managed services to files

    Keyword argument:
        services -- A dict of managed services with their parameters

    """
    # TODO: Save to custom services.yml
    with open('/etc/yunohost/services.yml', 'w') as f:
        yaml.safe_dump(services, f, default_flow_style=False)


def _tail(file, n, offset=None):
    """
    Reads a n lines from f with an offset of offset lines.  The return
    value is a tuple in the form ``(lines, has_more)`` where `has_more` is
    an indicator that is `True` if there are more lines in the file.

    """
    avg_line_length = 74
    to_read = n + (offset or 0)

    try:
        with open(file, 'r') as f:
            while 1:
                try:
                    f.seek(-(avg_line_length * to_read), 2)
                except IOError:
                    # woops.  apparently file is smaller than what we want
                    # to step back, go to the beginning instead
                    f.seek(0)
                pos = f.tell()
                lines = f.read().splitlines()
                if len(lines) >= to_read or pos == 0:
                    return lines[-to_read:offset and -offset or None]
                avg_line_length *= 1.3

    except IOError:
        return []


def _get_files_diff(orig_file, new_file, as_string=False, skip_header=True):
    """Compare two files and return the differences

    Read and compare two files. The differences are returned either as a delta
    in unified diff format or a formatted string if as_string is True. The
    header can also be removed if skip_header is True.

    """
    contents = [[], []]
    for i, path in enumerate((orig_file, new_file)):
        try:
            with open(path, 'r') as f:
                contents[i] = f.readlines()
        except IOError:
            pass

    # Compare files and format output
    diff = unified_diff(contents[0], contents[1])
    if skip_header:
        for i in range(2):
            try:
                next(diff)
            except:
                break
    if as_string:
        result = ''.join(line for line in diff)
        return result.rstrip()
    return diff


def _calculate_hash(path):
    """Calculate the MD5 hash of a file"""
    hasher = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except IOError:
        return None


def _get_pending_conf(services=[]):
    """Get pending configuration for service(s)

    Iterate over the pending configuration directory for given service(s) - or
    all if empty - and look for files inside. Each file is considered as a
    pending configuration file and therefore must be in the same directory
    tree than the system file that it replaces.
    The result is returned as a dict of services with pending configuration as
    key and a dict of `system_conf_path` => `pending_conf_path` as value.

    """
    result = {}
    if not os.path.isdir(PENDING_CONF_DIR):
        return result
    if not services:
        services = os.listdir(PENDING_CONF_DIR)
    for name in services:
        service_pending_path = os.path.join(PENDING_CONF_DIR, name)
        if not os.path.isdir(service_pending_path):
            continue
        path_index = len(service_pending_path)
        service_conf = {}
        for root, dirs, files in os.walk(service_pending_path):
            for filename in files:
                pending_path = os.path.join(root, filename)
                service_conf[pending_path[path_index:]] = pending_path
        if service_conf:
            result[name] = service_conf
        else:
            # remove empty directory
            shutil.rmtree(service_pending_path, ignore_errors=True)
    return result


def _get_conf_hashes(service):
    """Get the registered conf hashes for a service"""

    services = _get_services()

    if service not in services:
        logger.debug("Service %s is not in services.yml yet.", service)
        return {}
    elif services[service] is None or 'conffiles' not in services[service]:
        logger.debug("No configuration files for service %s.", service)
        return {}
    else:
        return services[service]['conffiles']


def _update_conf_hashes(service, hashes):
    """Update the registered conf hashes for a service"""
    logger.debug("updating conf hashes for '%s' with: %s",
                 service, hashes)
    services = _get_services()
    service_conf = services.get(service, {})

    # Handle the case where services[service] is set to null in the yaml
    if service_conf is None:
        service_conf = {}

    service_conf['conffiles'] = hashes
    services[service] = service_conf
    _save_services(services)


def _process_regen_conf(system_conf, new_conf=None, save=True):
    """Regenerate a given system configuration file

    Replace a given system configuration file by a new one or delete it if
    new_conf is None. A backup of the file - keeping its directory tree - will
    be done in the backup conf directory before any operation if save is True.

    """
    if save:
        backup_path = os.path.join(BACKUP_CONF_DIR, '{0}-{1}'.format(
            system_conf.lstrip('/'), time.strftime("%Y%m%d.%H%M%S")))
        backup_dir = os.path.dirname(backup_path)
        if not os.path.isdir(backup_dir):
            filesystem.mkdir(backup_dir, 0755, True)
        shutil.copy2(system_conf, backup_path)
        logger.info(m18n.n('service_conf_file_backed_up',
                           conf=system_conf, backup=backup_path))
    try:
        if not new_conf:
            os.remove(system_conf)
            logger.info(m18n.n('service_conf_file_removed',
                               conf=system_conf))
        else:
            system_dir = os.path.dirname(system_conf)
            if not os.path.isdir(system_dir):
                filesystem.mkdir(system_dir, 0755, True)
            shutil.copyfile(new_conf, system_conf)
            logger.info(m18n.n('service_conf_file_updated',
                               conf=system_conf))
    except:
        if not new_conf and os.path.exists(system_conf):
            logger.warning(m18n.n('service_conf_file_remove_failed',
                                  conf=system_conf),
                           exc_info=1)
            return False
        elif new_conf:
            try:
                copy_succeed = os.path.samefile(system_conf, new_conf)
            except:
                copy_succeed = False
            finally:
                if not copy_succeed:
                    logger.warning(m18n.n('service_conf_file_copy_failed',
                                          conf=system_conf, new=new_conf),
                                   exc_info=1)
                    return False
    return True
