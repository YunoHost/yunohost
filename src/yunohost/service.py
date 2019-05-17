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
import subprocess

from glob import glob
from datetime import datetime

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils import log, filesystem

from yunohost.log import is_unit_operation

MOULINETTE_LOCK = "/var/run/moulinette_yunohost.lock"

logger = log.getActionLogger('yunohost.service')


def service_add(name, status=None, log=None, runlevel=None, need_lock=False, description=None, log_type="file"):
    """
    Add a custom service

    Keyword argument:
        name -- Service name to add
        status -- Custom status command
        log -- Absolute path to log file to display
        runlevel -- Runlevel priority of the service
        need_lock -- Use this option to prevent deadlocks if the service does invoke yunohost commands.
        description -- description of the service
        log_type -- Precise if the corresponding log is a file or a systemd log
    """
    services = _get_services()

    if not status:
        services[name] = {'status': 'service'}
    else:
        services[name] = {'status': status}

    if log is not None:
        if not isinstance(log, list):
            log = [log]

        services[name]['log'] = log

        if not isinstance(log_type, list):
            log_type = [log_type]

        if len(log_type) < len(log):
            log_type.extend([log_type[-1]] * (len(log) - len(log_type))) # extend list to have the same size as log

        if len(log_type) == len(log):
            services[name]['log_type'] = log_type
        else:
            raise YunohostError('service_add_failed', service=name)


    if runlevel is not None:
        services[name]['runlevel'] = runlevel

    if need_lock:
        services[name]['need_lock'] = True

    if description is not None:
        services[name]['description'] = description

    try:
        _save_services(services)
    except:
        # we'll get a logger.warning with more details in _save_services
        raise YunohostError('service_add_failed', service=name)

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
        raise YunohostError('service_unknown', service=name)

    try:
        _save_services(services)
    except:
        # we'll get a logger.warning with more details in _save_services
        raise YunohostError('service_remove_failed', service=name)

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
                raise YunohostError('service_start_failed', service=name, logs=_get_journalctl_logs(name))
            logger.debug(m18n.n('service_already_started', service=name))


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
                raise YunohostError('service_stop_failed', service=name, logs=_get_journalctl_logs(name))
            logger.debug(m18n.n('service_already_stopped', service=name))


def service_reload(names):
    """
    Reload one or more services

    Keyword argument:
        name -- Services name to reload

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('reload', name):
            logger.success(m18n.n('service_reloaded', service=name))
        else:
            if service_status(name)['status'] != 'inactive':
                raise YunohostError('service_reload_failed', service=name, logs=_get_journalctl_logs(name))


def service_restart(names):
    """
    Restart one or more services. If the services are not running yet, they will be started.

    Keyword argument:
        name -- Services name to restart

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('restart', name):
            logger.success(m18n.n('service_restarted', service=name))
        else:
            if service_status(name)['status'] != 'inactive':
                raise YunohostError('service_restart_failed', service=name, logs=_get_journalctl_logs(name))


def service_reload_or_restart(names):
    """
    Reload one or more services if they support it. If not, restart them instead. If the services are not running yet, they will be started.

    Keyword argument:
        name -- Services name to reload or restart

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('reload-or-restart', name):
            logger.success(m18n.n('service_reloaded_or_restarted', service=name))
        else:
            if service_status(name)['status'] != 'inactive':
                raise YunohostError('service_reload_or_restart_failed', service=name, logs=_get_journalctl_logs(name))


@is_unit_operation()
def service_enable(operation_logger, names):
    """
    Enable one or more services

    Keyword argument:
        names -- Services name to enable

    """
    operation_logger.start()
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command('enable', name):
            logger.success(m18n.n('service_enabled', service=name))
        else:
            raise YunohostError('service_enable_failed', service=name, logs=_get_journalctl_logs(name))


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
            raise YunohostError('service_disable_failed', service=name, logs=_get_journalctl_logs(name))


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
            raise YunohostError('service_unknown', service=name)

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

        # try to get status using alternative version if they exists
        # this is for mariadb/mysql but is generic in case of
        alternates = services[name].get("alternates", [])
        while status is None and alternates:
            status = _get_service_information_from_systemd(alternates.pop())

        if status is None:
            logger.error("Failed to get status information via dbus for service %s, systemctl didn't recognize this service ('NoSuchUnit')." % name)
            result[name] = {
                'status': "unknown",
                'loaded': "unknown",
                'active': "unknown",
                'active_at': "unknown",
                'description': "Error: failed to get information for this service, it doesn't exists for systemd",
                'service_file_path': "unknown",
            }

        else:
            translation_key = "service_description_%s" % name
            if "description" in services[name] is not None:
                description = services[name].get("description")
            else:
                description = m18n.n(translation_key)

            # that mean that we don't have a translation for this string
            # that's the only way to test for that for now
            # if we don't have it, uses the one provided by systemd
            if description == translation_key:
                description = str(status.get("Description", ""))

            result[name] = {
                'status': str(status.get("SubState", "unknown")),
                'loaded': str(status.get("UnitFileState", "unknown")),
                'active': str(status.get("ActiveState", "unknown")),
                'description': description,
                'service_file_path': str(status.get("FragmentPath", "unknown")),
            }

            # Fun stuff™ : to obtain the enabled/disabled status for sysv services,
            # gotta do this ... cf code of /lib/systemd/systemd-sysv-install
            if result[name]["loaded"] == "generated":
                result[name]["loaded"] = "enabled" if glob("/etc/rc[S5].d/S??"+name) else "disabled"

            if "ActiveEnterTimestamp" in status:
                result[name]['active_at'] = datetime.utcfromtimestamp(status["ActiveEnterTimestamp"] / 1000000)
            else:
                result[name]['active_at'] = "unknown"

    if len(names) == 1:
        return result[names[0]]
    return result


def _get_service_information_from_systemd(service):
    "this is the equivalent of 'systemctl status $service'"
    import dbus

    d = dbus.SystemBus()

    systemd = d.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
    manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')

    # c.f. https://zignar.net/2014/09/08/getting-started-with-dbus-python-systemd/
    # Very interface, much intuitive, wow
    service_unit = manager.LoadUnit(service + '.service')
    service_proxy = d.get_object('org.freedesktop.systemd1', str(service_unit))
    properties_interface = dbus.Interface(service_proxy, 'org.freedesktop.DBus.Properties')

    properties = properties_interface.GetAll('org.freedesktop.systemd1.Unit')

    if properties.get("LoadState", "not-found") == "not-found":
        # Service doesn't really exist
        return None
    else:
        return properties


def service_log(name, number=50):
    """
    Log every log files of a service

    Keyword argument:
        name -- Service name to log
        number -- Number of lines to display

    """
    services = _get_services()

    if name not in services.keys():
        raise YunohostError('service_unknown', service=name)

    if 'log' not in services[name]:
        raise YunohostError('service_no_log', service=name)

    log_list = services[name]['log']
    log_type_list = services[name].get('log_type', [])

    if not isinstance(log_list, list):
        log_list = [log_list]
    if len(log_type_list) < len(log_list):
        log_type_list.extend(["file"] * (len(log_list)-len(log_type_list)))

    result = {}

    for index, log_path in enumerate(log_list):
        log_type = log_type_list[index]

        if log_type == "file":
            # log is a file, read it
            if not os.path.isdir(log_path):
                result[log_path] = _tail(log_path, int(number)) if os.path.exists(log_path) else []
                continue

            for log_file in os.listdir(log_path):
                log_file_path = os.path.join(log_path, log_file)
                # not a file : skip
                if not os.path.isfile(log_file_path):
                    continue

                if not log_file.endswith(".log"):
                    continue

                result[log_file_path] = _tail(log_file_path, int(number)) if os.path.exists(log_file_path) else []
        else:
            # get log with journalctl
            result[log_path] = _get_journalctl_logs(log_path, int(number)).splitlines()

    return result


def service_regen_conf(names=[], with_diff=False, force=False, dry_run=False,
                       list_pending=False):

    services = _get_services()

    if isinstance(names, str):
        names = [names]

    for name in names:
        if name not in services.keys():
            raise YunohostError('service_unknown', service=name)

    if names is []:
        names = services.keys()

    logger.warning(m18n.n("service_regen_conf_is_deprecated"))

    from yunohost.regenconf import regen_conf
    return regen_conf(names, with_diff, force, dry_run, list_pending)


def _run_service_command(action, service):
    """
    Run services management command (start, stop, enable, disable, restart, reload)

    Keyword argument:
        action -- Action to perform
        service -- Service name

    """
    services = _get_services()
    if service not in services.keys():
        raise YunohostError('service_unknown', service=service)

    possible_actions = ['start', 'stop', 'restart', 'reload', 'reload-or-restart', 'enable', 'disable']
    if action not in possible_actions:
        raise ValueError("Unknown action '%s', available actions are: %s" % (action, ", ".join(possible_actions)))

    cmd = 'systemctl %s %s' % (action, service)

    need_lock = services[service].get('need_lock', False) \
        and action in ['start', 'stop', 'restart', 'reload', 'reload-or-restart']

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

        if p.returncode != 0:
            logger.warning(m18n.n('service_cmd_exec_failed', command=cmd))
            return False

    except Exception as e:
        logger.warning(m18n.n("unexpected_error", error=str(e)))
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

    cmd_get_son_PID = "systemctl show %s -p %s" % (service, systemctl_PID_name)
    son_PID = 0
    # As long as we did not found the PID and that the command is still running
    while son_PID == 0 and p.poll() is None:
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
    PIDs_to_keep = [PID for PID in PIDs if int(PID) != PID_to_remove]
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

    This function works even with splitted logs (gz compression, log rotate...)
    """
    avg_line_length = 74
    to_read = n

    try:
        if file.endswith(".gz"):
            import gzip
            f = gzip.open(file)
            lines = f.read().splitlines()
        else:
            f = open(file)
            pos = 1
            lines = []
            while len(lines) < to_read and pos > 0:
                try:
                    f.seek(-(avg_line_length * to_read), 2)
                except IOError:
                    # woops.  apparently file is smaller than what we want
                    # to step back, go to the beginning instead
                    f.seek(0)

                pos = f.tell()
                lines = f.read().splitlines()

                if len(lines) >= to_read:
                    return lines[-to_read:]

                avg_line_length *= 1.3
        f.close()

    except IOError as e:
        logger.warning("Error while tailing file '%s': %s", file, e, exc_info=1)
        return []

    if len(lines) < to_read:
        previous_log_file = _find_previous_log_file(file)
        if previous_log_file is not None:
            lines = _tail(previous_log_file, to_read - len(lines)) + lines

    return lines


def _find_previous_log_file(file):
    """
    Find the previous log file
    """
    import re

    splitext = os.path.splitext(file)
    if splitext[1] == '.gz':
        file = splitext[0]
    splitext = os.path.splitext(file)
    ext = splitext[1]
    i = re.findall(r'\.(\d+)', ext)
    i = int(i[0]) + 1 if len(i) > 0 else 1

    previous_file = file if i == 1 else splitext[0]
    previous_file = previous_file + '.%d' % (i)
    if os.path.exists(previous_file):
        return previous_file

    previous_file = previous_file + ".gz"
    if os.path.exists(previous_file):
        return previous_file

    return None


def _get_journalctl_logs(service, number="all"):
    try:
        return subprocess.check_output("journalctl -xn -u {0} -n{1}".format(service, number), shell=True)
    except:
        import traceback
        return "error while get services logs from journalctl:\n%s" % traceback.format_exc()
