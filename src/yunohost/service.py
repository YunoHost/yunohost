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
import json
import subprocess
import errno
import shutil
import hashlib

from difflib import unified_diff
from datetime import datetime

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils import log, filesystem

from yunohost.hook import hook_callback

BASE_CONF_PATH = '/home/yunohost.conf'
BACKUP_CONF_DIR = os.path.join(BASE_CONF_PATH, 'backup')
PENDING_CONF_DIR = os.path.join(BASE_CONF_PATH, 'pending')
MOULINETTE_LOCK = "/var/run/moulinette_yunohost.lock"

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
        # we'll get a logger.warning with more details in _save_services
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
        # we'll get a logger.warning with more details in _save_services
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
                                      m18n.n('service_start_failed',
                                             service=name,
                                             logs=_get_journalctl_logs(name)))
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
                                      m18n.n('service_stop_failed',
                                             service=name,
                                             logs=_get_journalctl_logs(name)))
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
                                  m18n.n('service_enable_failed',
                                         service=name,
                                         logs=_get_journalctl_logs(name)))


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
                                  m18n.n('service_disable_failed',
                                         service=name,
                                         logs=_get_journalctl_logs(name)))


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

        # this "service" isn't a service actually so we skip it
        #
        # the historical reason is because regenconf has been hacked into the
        # service part of YunoHost will in some situation we need to regenconf
        # for things that aren't services
        # the hack was to add fake services...
        # we need to extract regenconf from service at some point, also because
        # some app would really like to use it
        if "status" in services[name] and services[name]["status"] is None:
            continue

        status = _get_service_information_from_systemd(name)

        result[name] = {
            'status': str(status.get("SubState", "unknown")),
            'loaded': "enabled" if str(status.get("LoadState", "unknown")) == "loaded" else str(status.get("LoadState", "unknown")),
            'active': str(status.get("ActiveState", "unknown")),
            'active_at': {
                "timestamp": str(status.get("ActiveEnterTimestamp", "unknown")),
                "human": datetime.fromtimestamp(status.get("ActiveEnterTimestamp") / 1000000).strftime("%F %X"),
            },
            'description': str(status.get("Description", "")),
            'service_file_path': str(status.get("FragmentPath", "unknown")),
        }

    if len(names) == 1:
        return result[names[0]]
    return result


def _get_service_information_from_systemd(service):
    "this is the equivalent of 'systemctl status $service'"
    import dbus

    d = dbus.SystemBus()

    systemd = d.get_object('org.freedesktop.systemd1','/org/freedesktop/systemd1')
    manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')

    service_path = manager.GetUnit(service + ".service")
    service_proxy = d.get_object('org.freedesktop.systemd1', service_path)

    # unit_proxy = dbus.Interface(service_proxy, 'org.freedesktop.systemd1.Unit',)
    properties_interface = dbus.Interface(service_proxy, 'org.freedesktop.DBus.Properties')

    return properties_interface.GetAll('org.freedesktop.systemd1.Unit')


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

    if 'log' not in services[name]:
        raise MoulinetteError(errno.EPERM, m18n.n('service_no_log', service=name))

    log_list = services[name]['log']

    if not isinstance(log_list, list):
        log_list = [log_list]

    result = {}

    for log_path in log_list:
        # log is a file, read it
        if not os.path.isdir(log_path):
            result[log_path] = _tail(log_path, int(number))
            continue

        for log_file in os.listdir(log_path):
            log_file_path = os.path.join(log_path, log_file)
            # not a file : skip
            if not os.path.isfile(log_file_path):
                continue

            if not log_file.endswith(".log"):
                continue

            result[log_file_path] = _tail(log_file_path, int(number))

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

        if not with_diff:
            return pending_conf

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
        filesystem.mkdir(service_pending_path, 0755, True, uid='root')

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
    services = _get_services()
    if service not in services.keys():
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', service=service))

    possible_actions = ['start', 'stop', 'restart', 'reload', 'enable', 'disable']
    if action not in possible_actions:
        raise ValueError("Unknown action '%s', available actions are: %s" % (action, ", ".join(possible_actions)))

    cmd = 'systemctl %s %s' % (action, service)

    need_lock = services[service].get('need_lock', False) \
                and action in ['start', 'stop', 'restart', 'reload']

    try:
        # Launch the command
        logger.debug("Running '%s'" % cmd)
        p = subprocess.Popen(cmd.split(), stderr=subprocess.STDOUT)
        # If this command needs a lock (because the service uses yunohost
        # commands inside), find the PID and add a lock for it
        if need_lock:
            PID = _give_lock(action, service, p)
        # Wait for the command to complete
        p.communicate()

    except subprocess.CalledProcessError as e:
        # TODO: Log output?
        logger.warning(m18n.n('service_cmd_exec_failed', command=' '.join(e.cmd)))
        return False

    finally:
        # Remove the lock if one was given
        if need_lock and PID != 0:
            _remove_lock(PID)

    return True


def _give_lock(action, service, p):

    # Depending of the action, systemctl calls the PID differently :/
    if action == "start" or action == "restart":
        systemctl_PID_name = "MainPID"
    else:
        systemctl_PID_name = "ControlPID"

    cmd_get_son_PID ="systemctl show %s -p %s" % (service, systemctl_PID_name)
    son_PID = 0
    # As long as we did not found the PID and that the command is still running
    while son_PID == 0 and p.poll() == None:
        # Call systemctl to get the PID
        # Output of the command is e.g. ControlPID=1234
        son_PID = subprocess.check_output(cmd_get_son_PID.split()) \
                            .strip().split("=")[1]
        son_PID = int(son_PID)
        time.sleep(1)

    # If we found a PID
    if son_PID != 0:
        # Append the PID to the lock file
        logger.debug("Giving a lock to PID %s for service %s !"
                     % (str(son_PID), service))
        filesystem.append_to_file(MOULINETTE_LOCK, "\n%s" % str(son_PID))

    return son_PID

def _remove_lock(PID_to_remove):
    # FIXME ironically not concurrency safe because it's not atomic...

    PIDs = filesystem.read_file(MOULINETTE_LOCK).split("\n")
    PIDs_to_keep = [ PID for PID in PIDs if int(PID) != PID_to_remove ]
    filesystem.write_to_file(MOULINETTE_LOCK, '\n'.join(PIDs_to_keep))


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
        # some services are marked as None to remove them from YunoHost
        # filter this
        for key, value in services.items():
            if value is None:
                del services[key]

        return services


def _save_services(services):
    """
    Save managed services to files

    Keyword argument:
        services -- A dict of managed services with their parameters

    """
    try:
        with open('/etc/yunohost/services.yml', 'w') as f:
            yaml.safe_dump(services, f, default_flow_style=False)
    except Exception as e:
        logger.warning('Error while saving services, exception: %s', e, exc_info=1)
        raise


def _tail(file, n):
    """
    Reads a n lines from f with an offset of offset lines.  The return
    value is a tuple in the form ``(lines, has_more)`` where `has_more` is
    an indicator that is `True` if there are more lines in the file.

    """
    avg_line_length = 74
    to_read = n

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
                    return lines[-to_read]

                avg_line_length *= 1.3

    except IOError as e:
        logger.warning("Error while tailing file '%s': %s", file, e, exc_info=1)
        return []


def _get_files_diff(orig_file, new_file, as_string=False, skip_header=True):
    """Compare two files and return the differences

    Read and compare two files. The differences are returned either as a delta
    in unified diff format or a formatted string if as_string is True. The
    header can also be removed if skip_header is True.

    """
    with open(orig_file, 'r') as orig_file:
        orig_file = orig_file.readlines()

    with open(new_file, 'r') as new_file:
        new_file.readlines()

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
    hasher = hashlib.md5()

    try:
        with open(path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    except IOError as e:
        logger.warning("Error while calculating file '%s' hash: %s", path, e, exc_info=1)
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
    except Exception as e:
        logger.warning("Exception while trying to regenerate conf '%s': %s", system_conf, e, exc_info=1)
        if not new_conf and os.path.exists(system_conf):
            logger.warning(m18n.n('service_conf_file_remove_failed',
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
                    logger.warning(m18n.n('service_conf_file_copy_failed',
                                          conf=system_conf, new=new_conf),
                                   exc_info=1)
                    return False

    return True


def manually_modified_files():

    # We do this to have --quiet, i.e. don't throw a whole bunch of logs
    # just to fetch this...
    # Might be able to optimize this by looking at what service_regenconf does
    # and only do the part that checks file hashes...
    cmd = "yunohost service regen-conf --dry-run --output-as json --quiet"
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


def _get_journalctl_logs(service):
    try:
        return subprocess.check_output("journalctl -xn -u %s" % service, shell=True)
    except:
        import traceback
        return "error while get services logs from journalctl:\n%s" % traceback.format_exc()


def manually_modified_files_compared_to_debian_default():

    # from https://serverfault.com/a/90401
    r = subprocess.check_output("dpkg-query -W -f='${Conffiles}\n' '*' \
                                | awk 'OFS=\"  \"{print $2,$1}' \
                                | md5sum -c 2>/dev/null \
                                | awk -F': ' '$2 !~ /OK/{print $1}'", shell=True)
    return r.strip().split("\n")
