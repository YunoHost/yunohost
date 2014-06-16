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
import yaml
import glob
import subprocess
import errno
import os.path

from moulinette.core import MoulinetteError


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
            ret = subprocess.check_output(status.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            if 'usage:' not in e.output.lower():
                result[name]['status'] = 'inactive'
            else:
                # TODO: Log output?
                msignals.display(m18n.n('service_status_failed', name),
                                 'warning')
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


def _run_service_command(action, service):
    """
    Run services management command (start, stop,  enable, disable)

    Keyword argument:
        action -- Action to perform
        service -- Service name

    """
    if service not in _get_services().keys():
        raise MoulinetteError(errno.EINVAL, m18n.n('service_unknown',
                                                   service))

    cmd = None
    if action in ['start', 'stop']:
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
