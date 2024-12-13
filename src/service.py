#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
import re
import subprocess
import time
from datetime import datetime
from glob import glob
from logging import getLogger

import yaml
from moulinette import m18n
from moulinette.utils.filesystem import (
    append_to_file,
    read_file,
    read_yaml,
    write_to_file,
    write_to_yaml,
)
from moulinette.utils.process import check_output

from yunohost.log import is_unit_operation
from yunohost.diagnosis import diagnosis_ignore, diagnosis_unignore
from yunohost.utils.error import YunohostError, YunohostValidationError

MOULINETTE_LOCK = "/var/run/moulinette_yunohost.lock"

SERVICES_CONF = "/etc/yunohost/services.yml"
SERVICES_CONF_BASE = "/usr/share/yunohost/conf/yunohost/services.yml"

logger = getLogger("yunohost.service")


def service_add(
    name,
    description=None,
    log=None,
    test_status=None,
    test_conf=None,
    needs_exposed_ports=None,
    need_lock=False,
):
    """
    Add a custom service

    Keyword argument:
        name -- Service name to add
        description -- description of the service
        log -- Absolute path to log file to display
        test_status -- Specify a custom bash command to check the status of the service. N.B. : it only makes sense to specify this if the corresponding systemd service does not return the proper information.
        test_conf -- Specify a custom bash command to check if the configuration of the service is valid or broken, similar to nginx -t.
        needs_exposed_ports -- A list of ports that needs to be publicly exposed for the service to work as intended.
        need_lock -- Use this option to prevent deadlocks if the service does invoke yunohost commands.
    """
    services = _get_services()

    services[name] = service = {}

    if log is not None:
        if not isinstance(log, list):
            log = [log]

        service["log"] = log

    if not description:
        # Try to get the description from systemd service
        unit, _ = _get_service_information_from_systemd(name)
        description = str(unit.get("Description", "")) if unit is not None else ""
        # If the service does not yet exists or if the description is empty,
        # systemd will anyway return foo.service as default value, so we wanna
        # make sure there's actually something here.
        if description == name + ".service":
            description = ""

    if description:
        service["description"] = description
    else:
        logger.warning(
            "/!\\ Packagers! You added a custom service without specifying a description. Please add a proper Description in the systemd configuration, or use --description to explain what the service does in a similar fashion to existing services."
        )

    if need_lock:
        service["need_lock"] = True

    if test_status:
        service["test_status"] = test_status
    else:
        # Try to get the description from systemd service
        _, systemd_info = _get_service_information_from_systemd(name)
        type_ = systemd_info.get("Type") if systemd_info is not None else ""
        if type_ == "oneshot":
            logger.warning(
                "/!\\ Packagers! Please provide a --test_status when adding oneshot-type services in Yunohost, such that it has a reliable way to check if the service is running or not."
            )

    if test_conf:
        service["test_conf"] = test_conf

    if needs_exposed_ports:
        service["needs_exposed_ports"] = needs_exposed_ports

    try:
        _save_services(services)
    except Exception as e:
        logger.warning(e)
        # we'll get a logger.warning with more details in _save_services
        raise YunohostError("service_add_failed", service=name)

    logger.success(m18n.n("service_added", service=name))


def service_remove(name):
    """
    Remove a custom service

    Keyword argument:
        name -- Service name to remove

    """
    services = _get_services()

    if name not in services:
        raise YunohostValidationError("service_unknown", service=name)

    del services[name]
    try:
        _save_services(services)
    except Exception:
        # we'll get a logger.warning with more details in _save_services
        raise YunohostError("service_remove_failed", service=name)

    logger.success(m18n.n("service_removed", service=name))


@is_unit_operation(flash=True)
def service_start(names):
    """
    Start one or more services

    Keyword argument:
        names -- Services name to start

    """
    if isinstance(names, str):
        names = [names]

    for name in names:
        if _run_service_command("start", name):
            logger.success(m18n.n("service_started", service=name))
        else:
            if service_status(name)["status"] != "running":
                raise YunohostError(
                    "service_start_failed",
                    service=name,
                    logs=_get_journalctl_logs(name),
                )
            logger.debug(m18n.n("service_already_started", service=name))


@is_unit_operation(flash=True)
def service_stop(names):
    """
    Stop one or more services

    Keyword argument:
        name -- Services name to stop

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command("stop", name):
            logger.success(m18n.n("service_stopped", service=name))
        else:
            if service_status(name)["status"] != "inactive":
                raise YunohostError(
                    "service_stop_failed", service=name, logs=_get_journalctl_logs(name)
                )
            logger.debug(m18n.n("service_already_stopped", service=name))


def service_reload(names):
    """
    Reload one or more services

    Keyword argument:
        name -- Services name to reload

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command("reload", name):
            logger.success(m18n.n("service_reloaded", service=name))
        else:
            if service_status(name)["status"] != "inactive":
                raise YunohostError(
                    "service_reload_failed",
                    service=name,
                    logs=_get_journalctl_logs(name),
                )


def service_restart(names):
    """
    Restart one or more services. If the services are not running yet, they will be started.

    Keyword argument:
        name -- Services name to restart

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command("restart", name):
            logger.success(m18n.n("service_restarted", service=name))
        else:
            if service_status(name)["status"] != "inactive":
                raise YunohostError(
                    "service_restart_failed",
                    service=name,
                    logs=_get_journalctl_logs(name),
                )


def service_reload_or_restart(names, test_conf=True):
    """
    Reload one or more services if they support it. If not, restart them instead. If the services are not running yet, they will be started.

    Keyword argument:
        name -- Services name to reload or restart

    """
    if isinstance(names, str):
        names = [names]

    services = _get_services()

    for name in names:
        logger.debug(f"Reloading service {name}")

        test_conf_cmd = services.get(name, {}).get("test_conf")
        if test_conf and test_conf_cmd:
            p = subprocess.Popen(
                test_conf_cmd,
                shell=True,
                executable="/bin/bash",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            out, _ = p.communicate()
            if p.returncode != 0:
                errors = out.decode().strip().split("\n")
                logger.error(
                    m18n.n(
                        "service_not_reloading_because_conf_broken",
                        name=name,
                        errors=errors,
                    )
                )
                continue

        if _run_service_command("reload-or-restart", name):
            logger.success(m18n.n("service_reloaded_or_restarted", service=name))
        else:
            if service_status(name)["status"] != "inactive":
                raise YunohostError(
                    "service_reload_or_restart_failed",
                    service=name,
                    logs=_get_journalctl_logs(name),
                )


@is_unit_operation(flash=True)
def service_enable(names):
    """
    Enable one or more services

    Keyword argument:
        names -- Services name to enable

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command("enable", name):
            diagnosis_unignore(["services", f"service={name}"])
            logger.success(m18n.n("service_enabled", service=name))
        else:
            raise YunohostError(
                "service_enable_failed", service=name, logs=_get_journalctl_logs(name)
            )


@is_unit_operation(flash=True)
def service_disable(names):
    """
    Disable one or more services

    Keyword argument:
        names -- Services name to disable

    """
    if isinstance(names, str):
        names = [names]
    for name in names:
        if _run_service_command("disable", name):
            diagnosis_ignore(["services", f"service={name}"])
            logger.success(m18n.n("service_disabled", service=name))
        else:
            raise YunohostError(
                "service_disable_failed", service=name, logs=_get_journalctl_logs(name)
            )


def service_status(names=[]):
    """
    Show status information about one or more services (all by default)

    Keyword argument:
        names -- Services name to show

    """
    services = _get_services()

    # If function was called with a specific list of service
    if names != []:
        # If user wanna check the status of a single service
        if isinstance(names, str):
            names = [names]

        # Validate service names requested
        for name in names:
            if name not in services.keys():
                raise YunohostValidationError("service_unknown", service=name)

        # Filter only requested servivces
        services = {k: v for k, v in services.items() if k in names}

    # Remove services that aren't "real" services
    #
    # the historical reason is because regenconf has been hacked into the
    # service part of YunoHost will in some situation we need to regenconf
    # for things that aren't services
    # the hack was to add fake services...
    services = {k: v for k, v in services.items() if v.get("status", "") is not None}

    output = {
        s: _get_and_format_service_status(s, infos) for s, infos in services.items()
    }

    if len(names) == 1:
        return output[names[0]]
    return output


def _get_service_information_from_systemd(service):
    "this is the equivalent of 'systemctl status $service'"
    import dbus

    d = dbus.SystemBus()

    systemd = d.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
    manager = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")

    # c.f. https://zignar.net/2014/09/08/getting-started-with-dbus-python-systemd/
    # Very interface, much intuitive, wow
    service_unit = manager.LoadUnit(service + ".service")
    service_proxy = d.get_object("org.freedesktop.systemd1", str(service_unit))
    properties_interface = dbus.Interface(
        service_proxy, "org.freedesktop.DBus.Properties"
    )

    unit = properties_interface.GetAll("org.freedesktop.systemd1.Unit")
    service = properties_interface.GetAll("org.freedesktop.systemd1.Service")

    if unit.get("LoadState", "not-found") == "not-found":
        # Service doesn't really exist
        return (None, None)
    else:
        return (unit, service)


def _get_and_format_service_status(service, infos):
    systemd_service = infos.get("actual_systemd_service", service)
    raw_status, raw_service = _get_service_information_from_systemd(systemd_service)

    if raw_status is None:
        logger.error(
            f"Failed to get status information via dbus for service {systemd_service}, systemctl didn't recognize this service ('NoSuchUnit')."
        )
        return {
            "status": "unknown",
            "start_on_boot": "unknown",
            "last_state_change": "unknown",
            "description": "Error: failed to get information for this service, it doesn't exists for systemd",
            "configuration": "unknown",
        }

    # Try to get description directly from services.yml
    description = infos.get("description")

    # If no description was there, try to get it from the .json locales
    if not description:
        translation_key = f"service_description_{service}"
        if m18n.key_exists(translation_key):
            description = m18n.n(translation_key)
        else:
            description = str(raw_status.get("Description", ""))

    output = {
        "status": str(raw_status.get("SubState", "unknown")),
        "start_on_boot": str(raw_status.get("UnitFileState", "unknown")),
        "last_state_change": "unknown",
        "description": description,
        "configuration": "unknown",
    }

    # Fun stuff™ : to obtain the enabled/disabled status for sysv services,
    # gotta do this ... cf code of /lib/systemd/systemd-sysv-install
    if output["start_on_boot"] == "generated":
        output["start_on_boot"] = (
            "enabled" if glob("/etc/rc[S5].d/S??" + service) else "disabled"
        )
    elif os.path.exists(
        f"/etc/systemd/system/multi-user.target.wants/{service}.service"
    ):
        output["start_on_boot"] = "enabled"

    if "StateChangeTimestamp" in raw_status:
        output["last_state_change"] = datetime.utcfromtimestamp(
            raw_status["StateChangeTimestamp"] / 1000000
        )

    # 'test_status' is an optional field to test the status of the service using a custom command
    if "test_status" in infos:
        p = subprocess.Popen(
            infos["test_status"],
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        p.communicate()

        output["status"] = "running" if p.returncode == 0 else "failed"
    elif (
        raw_service.get("Type", "").lower() == "oneshot"
        and output["status"] == "exited"
    ):
        # These are services like yunohost-firewall, hotspot, vpnclient,
        # ... they will be "exited" why doesn't provide any info about
        # the real state of the service (unless they did provide a
        # test_status, c.f. previous condition)
        output["status"] = "unknown"

    # 'test_status' is an optional field to test the status of the service using a custom command
    if "test_conf" in infos:
        p = subprocess.Popen(
            infos["test_conf"],
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        out, _ = p.communicate()
        if p.returncode == 0:
            output["configuration"] = "valid"
        else:
            out = out.decode()
            output["configuration"] = "broken"
            output["configuration-details"] = out.strip().split("\n")

    return output


def service_log(name, number=50):
    """
    Log every log files of a service

    Keyword argument:
        name -- Service name to log
        number -- Number of lines to display

    """
    services = _get_services()
    number = int(number)

    if name not in services.keys():
        raise YunohostValidationError("service_unknown", service=name)

    log_list = services[name].get("log", [])

    if not isinstance(log_list, list):
        log_list = [log_list]

    # Legacy stuff related to --log_type where we'll typically have the service
    # name in the log list but it's not an actual logfile. Nowadays journalctl
    # is automatically fetch as well as regular log files.
    if name in log_list:
        log_list.remove(name)

    result = {}

    # First we always add the logs from journalctl / systemd
    result["journalctl"] = _get_journalctl_logs(name, number).splitlines()

    for log_path in log_list:
        if not os.path.exists(log_path):
            continue

        # Make sure to resolve symlinks
        log_path = os.path.realpath(log_path)

        # log is a file, read it
        if os.path.isfile(log_path):
            result[log_path] = _tail(log_path, number)
            continue
        elif not os.path.isdir(log_path):
            result[log_path] = []
            continue

        for log_file in os.listdir(log_path):
            log_file_path = os.path.join(log_path, log_file)
            # not a file : skip
            if not os.path.isfile(log_file_path):
                continue

            if not log_file.endswith(".log"):
                continue

            result[log_file_path] = (
                _tail(log_file_path, number) if os.path.exists(log_file_path) else []
            )

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
        raise YunohostValidationError("service_unknown", service=service)

    possible_actions = [
        "start",
        "stop",
        "restart",
        "reload",
        "reload-or-restart",
        "enable",
        "disable",
    ]
    if action not in possible_actions:
        raise ValueError(
            f"Unknown action '{action}', available actions are: {', '.join(possible_actions)}"
        )

    cmd = f"systemctl {action} {service}"

    need_lock = services[service].get("need_lock", False) and action in [
        "start",
        "stop",
        "restart",
        "reload",
        "reload-or-restart",
    ]

    if action in ["enable", "disable"]:
        cmd += " --quiet"

    try:
        # Launch the command
        logger.debug(f"Running '{cmd}'")
        p = subprocess.Popen(cmd.split(), stderr=subprocess.STDOUT)
        # If this command needs a lock (because the service uses yunohost
        # commands inside), find the PID and add a lock for it
        if need_lock:
            PID = _give_lock(action, service, p)
        # Wait for the command to complete
        p.communicate()

        if p.returncode != 0:
            logger.warning(m18n.n("service_cmd_exec_failed", command=cmd))
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

    cmd_get_son_PID = f"systemctl show {service} -p {systemctl_PID_name}"
    son_PID = 0
    # As long as we did not found the PID and that the command is still running
    while son_PID == 0 and p.poll() is None:
        # Call systemctl to get the PID
        # Output of the command is e.g. ControlPID=1234
        son_PID = check_output(cmd_get_son_PID).split("=")[1]
        son_PID = int(son_PID)
        time.sleep(1)

    # If we found a PID
    if son_PID != 0:
        # Append the PID to the lock file
        logger.debug(f"Giving a lock to PID {son_PID} for service {service} !")
        append_to_file(MOULINETTE_LOCK, f"\n{son_PID}")

    return son_PID


def _remove_lock(PID_to_remove):
    # FIXME ironically not concurrency safe because it's not atomic...

    PIDs = read_file(MOULINETTE_LOCK).split("\n")
    PIDs_to_keep = [PID for PID in PIDs if int(PID) != PID_to_remove]
    write_to_file(MOULINETTE_LOCK, "\n".join(PIDs_to_keep))


def _get_services():
    """
    Get a dict of managed services with their parameters

    """
    try:
        services = read_yaml(SERVICES_CONF_BASE) or {}

        # These are keys flagged 'null' in the base conf
        legacy_keys_to_delete = [k for k, v in services.items() if v is None]

        services.update(read_yaml(SERVICES_CONF) or {})

        services = {
            name: infos
            for name, infos in services.items()
            if name not in legacy_keys_to_delete
        }
    except Exception:
        return {}

    # Dirty hack to automatically find custom SSH port ...
    ssh_port_line = re.findall(
        r"\bPort *([0-9]{2,5})\b", read_file("/etc/ssh/sshd_config")
    )
    if len(ssh_port_line) == 1:
        services["ssh"]["needs_exposed_ports"] = [int(ssh_port_line[0])]

    # Dirty hack to check the status of ynh-vpnclient
    if "ynh-vpnclient" in services:
        if "log" not in services["ynh-vpnclient"]:
            services["ynh-vpnclient"]["log"] = ["/var/log/ynh-vpnclient.log"]

    services_with_package_condition = [
        name
        for name, infos in services.items()
        if infos.get("ignore_if_package_is_not_installed")
    ]
    for name in services_with_package_condition:
        package = services[name]["ignore_if_package_is_not_installed"]
        if (
            check_output(
                f"dpkg-query --show --showformat='${{db:Status-Status}}' '{package}' 2>/dev/null || true"
            )
            != "installed"
        ):
            del services[name]

    php_fpm_versions = check_output(
        r"dpkg --list | grep -P 'ii  php\d.\d-fpm' | awk '{print $2}' | grep -o -P '\d.\d' || true",
        cwd="/tmp",
    )
    php_fpm_versions = [v for v in php_fpm_versions.split("\n") if v.strip()]

    for version in php_fpm_versions:
        # Skip php 7.3 which is most likely dead after buster->bullseye migration
        # because users get spooked
        if version == "7.3":
            continue
        services[f"php{version}-fpm"] = {
            "log": f"/var/log/php{version}-fpm.log",
            "test_conf": f"php-fpm{version} --test",  # ofc the service is phpx.y-fpm but the program is php-fpmx.y because why not ...
            "category": "web",
        }

    # Remove legacy /var/log/daemon.log and /var/log/syslog from log entries
    # because they are too general. Instead, now the journalctl log is
    # returned by default which is more relevant.
    for infos in services.values():
        if infos.get("log") in ["/var/log/syslog", "/var/log/daemon.log"]:
            del infos["log"]

    return services


def _save_services(services):
    """
    Save managed services to files

    Keyword argument:
        services -- A dict of managed services with their parameters

    """

    # Compute the diff with the base file
    # such that /etc/yunohost/services.yml contains the minimal
    # changes with respect to the base conf

    conf_base = yaml.safe_load(open(SERVICES_CONF_BASE)) or {}

    diff = {}

    for service_name, service_infos in services.items():
        # Ignore php-fpm services, they are to be added dynamically by the core,
        # but not actually saved
        if service_name.startswith("php") and service_name.endswith("-fpm"):
            continue

        service_conf_base = conf_base.get(service_name, {}) or {}
        diff[service_name] = {}

        for key, value in service_infos.items():
            if service_conf_base.get(key) != value:
                diff[service_name][key] = value

    diff = {
        name: infos for name, infos in diff.items() if infos or name not in conf_base
    }

    write_to_yaml(SERVICES_CONF, diff)


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
            f = open(file, errors="replace")
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
    splitext = os.path.splitext(file)
    if splitext[1] == ".gz":
        file = splitext[0]
    splitext = os.path.splitext(file)
    ext = splitext[1]
    i = re.findall(r"\.(\d+)", ext)
    i = int(i[0]) + 1 if len(i) > 0 else 1

    previous_file = file if i == 1 else splitext[0]
    previous_file = previous_file + f".{i}"
    if os.path.exists(previous_file):
        return previous_file

    previous_file = previous_file + ".gz"
    if os.path.exists(previous_file):
        return previous_file

    return None


def _get_journalctl_logs(service, number="all"):
    services = _get_services()
    systemd_service = services.get(service, {}).get("actual_systemd_service", service)
    try:
        return check_output(
            f"journalctl --no-hostname --no-pager -u {systemd_service} -n{number}"
        )
    except Exception:
        import traceback

        trace_ = traceback.format_exc()
        return f"error while get services logs from journalctl:\n{trace_}"
