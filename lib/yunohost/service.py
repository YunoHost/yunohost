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
import difflib
import hashlib

from moulinette.core import MoulinetteError

template_dir = os.getenv(
    'YUNOHOST_TEMPLATE_DIR',
    '/usr/share/yunohost/templates'
)
conf_backup_dir = os.getenv(
    'YUNOHOST_CONF_BACKUP_DIR',
    '/home/yunohost.backup/conffiles'
)

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
        services[name] = { 'status': 'service' }
    else:
        services[name] = { 'status': status }

    if log is not None:
        services[name]['log'] = log

    if runlevel is not None:
        services[name]['runlevel'] = runlevel

    try:
        _save_services(services)
    except:
        raise MoulinetteError(errno.EIO, m18n.n('service_add_failed', name))

    msignals.display(m18n.n('service_added'), 'success')


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
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', name))

    try:
        _save_services(services)
    except:
        raise MoulinetteError(errno.EIO, m18n.n('service_remove_failed', name))

    msignals.display(m18n.n('service_removed'), 'success')


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
            msignals.display(m18n.n('service_started', name), 'success')
        else:
            if service_status(name)['status'] != 'running':
                raise MoulinetteError(errno.EPERM,
                                      m18n.n('service_start_failed', name))
            msignals.display(m18n.n('service_already_started', name))


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
            msignals.display(m18n.n('service_stopped', name), 'success')
        else:
            if service_status(name)['status'] != 'inactive':
                raise MoulinetteError(errno.EPERM,
                                      m18n.n('service_stop_failed', name))
            msignals.display(m18n.n('service_already_stopped', name))


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
            msignals.display(m18n.n('service_enabled', name), 'success')
        else:
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('service_enable_failed', name))


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
            msignals.display(m18n.n('service_disabled', name), 'success')
        else:
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('service_disable_failed', name))


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
                                  m18n.n('service_unknown', name))

        status = None
        if services[name]['status'] == 'service':
            status = 'service %s status' % name
        else:
            status = str(services[name]['status'])

        runlevel = 5
        if 'runlevel' in services[name].keys():
            runlevel = int(services[name]['runlevel'])

        result[name] = { 'status': 'unknown', 'loaded': 'unknown' }

        # Retrieve service status
        try:
            ret = subprocess.check_output(status, stderr=subprocess.STDOUT,
                                          shell=True)
        except subprocess.CalledProcessError as e:
            if 'usage:' in e.output.lower():
                msignals.display(m18n.n('service_status_failed', name),
                                 'warning')
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
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', name))

    if 'log' in services[name]:
        log_list = services[name]['log']
        result = {}
        if not isinstance(log_list, list):
            log_list = [log_list]

        for log_path in log_list:
            if os.path.isdir(log_path):
                for log in [ f for f in os.listdir(log_path) if os.path.isfile(os.path.join(log_path, f)) and f[-4:] == '.log' ]:
                    result[os.path.join(log_path, log)] = _tail(os.path.join(log_path, log), int(number))
            else:
                result[log_path] = _tail(log_path, int(number))
    else:
        raise MoulinetteError(errno.EPERM, m18n.n('service_no_log', name))

    return result


def service_regenconf(service=None, force=False):
    """
    Regenerate the configuration file(s) for a service and compare the result
    with the existing configuration file.
    Prints the differences between files if any.

    Keyword argument:
        service -- Regenerate configuration for a specfic service
        force -- Override the current configuration with the newly generated
                 one, even if it has been modified

    """
    from yunohost.hook import hook_callback

    if force:
        arg_force = 0
    else:
        arg_force = 1

    if service is None:
        # Regen ALL THE CONFIGURATIONS
        hook_callback('conf_regen', args=[arg_force])

        msignals.display(m18n.n('services_configured'), 'success')
    else:
        if service not in _get_services().keys():
            raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown', service))

        hook_callback('conf_regen', [service] , args=[arg_force])

        msignals.display(m18n.n('service_configured', service), 'success')


def _run_service_command(action, service):
    """
    Run services management command (start, stop, enable, disable, restart, reload)

    Keyword argument:
        action -- Action to perform
        service -- Service name

    """
    if service not in _get_services().keys():
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown',
                                                   service))

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
        msignals.display(m18n.n('service_cmd_exec_failed', ' '.join(e.cmd)),
                         'warning')
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

    except IOError: return []


def _get_diff(string, filename):
    """
    Show differences between a string and a file's content

    Keyword argument:
        string -- The string
        filename -- The file to compare with

    """
    try:
        with open(filename, 'r') as f:
            file_lines = f.readlines()

        string = string + '\n'
        new_lines = string.splitlines(1)
        return difflib.unified_diff(file_lines, new_lines)
    except IOError: return []


def _hash(filename):
    """
    Calculate a MD5 hash of a file

    Keyword argument:
        filename -- The file to hash

    """
    hasher = hashlib.md5()
    try:
        with open(filename, 'rb') as f:
            buf = f.read()
            hasher.update(buf)

        return hasher.hexdigest()
    except IOError:
        return 'no hash yet'


def service_saferemove(service, conf_file, force=False):
    """
    Check if the specific file has been modified before removing it.
    Backup the file in /home/yunohost.backup

    Keyword argument:
        service -- Service name of the file to delete
        conf_file -- The file to write
        force -- Force file deletion

    """
    deleted = False

    if not os.path.exists(conf_file):
        try:
            del services[service]['conffiles'][conf_file]
        except KeyError: pass
        return True

    services = _get_services()

    # Backup existing file
    date = time.strftime("%Y%m%d.%H%M%S")
    conf_backup_file = conf_backup_dir + conf_file +'-'+ date
    process = subprocess.Popen(
        ['install', '-D', conf_file, conf_backup_file]
    )
    process.wait()

    # Retrieve hashes
    if not 'conffiles' in services[service]:
        services[service]['conffiles'] = {}

    if conf_file in services[service]['conffiles']:
        previous_hash = services[service]['conffiles'][conf_file]
    else:
        previous_hash = 'no hash yet'

    current_hash = _hash(conf_file)

    # Handle conflicts
    if force or previous_hash == current_hash:
	os.remove(conf_file)
        try:
            del services[service]['conffiles'][conf_file]
        except KeyError: pass
        deleted = True
        msignals.display(m18n.n('service_configuration_backup', conf_backup_file),
                         'info')
    elif keep:
        services[service]['conffiles'][conf_file] = \
            previous_hash[0:32] + ', but keep ' + current_hash
        msignals.display(m18n.n('service_configuration_backup', conf_backup_file),
                         'info')
    else:
        services[service]['conffiles'][conf_file] = previous_hash
        os.remove(conf_backup_file)
        if os.isatty(1) and \
           (len(previous_hash) == 32 or previous_hash[-32:] != current_hash):
            msignals.display(
                m18n.n('service_configuration_changed', conf_file),
                'warning'
            )

    _save_services(services)

    return deleted


def service_safecopy(service, new_conf_file, conf_file, force=False):
    """
    Check if the specific file has been modified and display differences.
    Stores the file hash in the services.yml file

    Keyword argument:
        service -- Service name attached to the conf file
        new_conf_file -- Path to the desired conf file
        conf_file -- Path to the targeted conf file
        force -- Force file overriding

    """
    regenerated = False
    services = _get_services()

    if not os.path.exists(new_conf_file):
        raise MoulinetteError(errno.EIO, m18n.n('no_such_conf_file', new_conf_file))

    with open(new_conf_file, 'r') as f:
        new_conf = ''.join(f.readlines()).rstrip()

    # Backup existing file
    date = time.strftime("%Y%m%d.%H%M%S")
    conf_backup_file = conf_backup_dir + conf_file +'-'+ date
    if os.path.exists(conf_file):
        process = subprocess.Popen(
            ['install', '-D', conf_file, conf_backup_file]
        )
        process.wait()
    else:
        msignals.display(m18n.n('service_add_configuration', conf_file),
                         'info')

    # Add the service if it does not exist
    if service not in services.keys():
        services[service] = {}

    # Retrieve hashes
    if not 'conffiles' in services[service]:
        services[service]['conffiles'] = {}

    if conf_file in services[service]['conffiles']:
        previous_hash = services[service]['conffiles'][conf_file]
    else:
        previous_hash = 'no hash yet'

    current_hash = _hash(conf_file)
    diff = list(_get_diff(new_conf, conf_file))

    # Handle conflicts
    if force or previous_hash == current_hash:
        with open(conf_file, 'w') as f: f.write(new_conf)
        regenerated = True
        new_hash = _hash(conf_file)
    elif len(diff) == 0:
        new_hash = _hash(conf_file)
    else:
        new_hash = previous_hash
        if os.isatty(1) and \
           (len(previous_hash) == 32 or previous_hash[-32:] != current_hash):
            msignals.display(
                m18n.n('service_configuration_conflict', conf_file),
                'warning'
            )
            print('\n' + conf_file)
            for line in diff:
                print(line.strip())
            print('')
      
    # Remove the backup file if the configuration has not changed
    if new_hash == previous_hash:
        os.remove(conf_backup_file)
    elif os.path.exists(conf_backup_file):
        msignals.display(m18n.n('service_configuration_backup', conf_backup_file),
                         'info')

    services[service]['conffiles'][conf_file] = new_hash
    _save_services(services)

    return regenerated
