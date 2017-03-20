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

""" yunohost_monitor.py

    Monitoring functions
"""
import re
import json
import time
import psutil
import calendar
import subprocess
import xmlrpclib
import os.path
import errno
import os
import dns.resolver
import cPickle as pickle
from datetime import datetime

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.domain import get_public_ip, _get_maindomain

logger = getActionLogger('yunohost.monitor')

GLANCES_URI = 'http://127.0.0.1:61209'
STATS_PATH = '/var/lib/yunohost/stats'
CRONTAB_PATH = '/etc/cron.d/yunohost-monitor'


def monitor_disk(units=None, mountpoint=None, human_readable=False):
    """
    Monitor disk space and usage

    Keyword argument:
        units -- Unit(s) to monitor
        mountpoint -- Device mountpoint
        human_readable -- Print sizes in human readable format

    """
    glances = _get_glances_api()
    result_dname = None
    result = {}

    if units is None:
        units = ['io', 'filesystem']

    _format_dname = lambda d: (os.path.realpath(d)).replace('/dev/', '')

    # Get mounted devices
    devices = {}
    for p in psutil.disk_partitions(all=True):
        if not p.device.startswith('/dev/') or not p.mountpoint:
            continue
        if mountpoint is None:
            devices[_format_dname(p.device)] = p.mountpoint
        elif mountpoint == p.mountpoint:
            dn = _format_dname(p.device)
            devices[dn] = p.mountpoint
            result_dname = dn
    if len(devices) == 0:
        if mountpoint is not None:
            raise MoulinetteError(errno.ENODEV, m18n.n('mountpoint_unknown'))
        return result

    # Retrieve monitoring for unit(s)
    for u in units:
        if u == 'io':
            # Define setter
            if len(units) > 1:
                def _set(dn, dvalue):
                    try:
                        result[dn][u] = dvalue
                    except KeyError:
                        result[dn] = {u: dvalue}
            else:
                def _set(dn, dvalue):
                    result[dn] = dvalue

            # Iterate over values
            devices_names = devices.keys()
            for d in json.loads(glances.getDiskIO()):
                dname = d.pop('disk_name')
                try:
                    devices_names.remove(dname)
                except:
                    continue
                else:
                    _set(dname, d)
            for dname in devices_names:
                _set(dname, 'not-available')
        elif u == 'filesystem':
            # Define setter
            if len(units) > 1:
                def _set(dn, dvalue):
                    try:
                        result[dn][u] = dvalue
                    except KeyError:
                        result[dn] = {u: dvalue}
            else:
                def _set(dn, dvalue):
                    result[dn] = dvalue

            # Iterate over values
            devices_names = devices.keys()
            for d in json.loads(glances.getFs()):
                dname = _format_dname(d.pop('device_name'))
                try:
                    devices_names.remove(dname)
                except:
                    continue
                else:
                    d['avail'] = d['size'] - d['used']
                    if human_readable:
                        for i in ['used', 'avail', 'size']:
                            d[i] = binary_to_human(d[i]) + 'B'
                    _set(dname, d)
            for dname in devices_names:
                _set(dname, 'not-available')
        else:
            raise MoulinetteError(errno.EINVAL, m18n.n('unit_unknown', unit=u))

    if result_dname is not None:
        return result[result_dname]
    return result


def monitor_network(units=None, human_readable=False):
    """
    Monitor network interfaces

    Keyword argument:
        units -- Unit(s) to monitor
        human_readable -- Print sizes in human readable format

    """
    glances = _get_glances_api()
    result = {}

    if units is None:
        units = ['check', 'usage', 'infos']

    # Get network devices and their addresses
    devices = {}
    output = subprocess.check_output('ip addr show'.split())
    for d in re.split('^(?:[0-9]+: )', output, flags=re.MULTILINE):
        # Extract device name (1) and its addresses (2)
        m = re.match('([^\s@]+)(?:@[\S]+)?: (.*)', d, flags=re.DOTALL)
        if m:
            devices[m.group(1)] = m.group(2)

    # Retrieve monitoring for unit(s)
    for u in units:
        if u == 'check':
            result[u] = {}
            domain = _get_maindomain()
            cmd_check_smtp = os.system('/bin/nc -z -w1 yunohost.org 25')
            if cmd_check_smtp == 0:
                smtp_check = m18n.n('network_check_smtp_ok')
            else:
                smtp_check = m18n.n('network_check_smtp_ko')

            try:
                answers = dns.resolver.query(domain, 'MX')
                mx_check = {}
                i = 0
                for server in answers:
                    mx_id = 'mx%s' % i
                    mx_check[mx_id] = server
                    i = i + 1
            except:
                mx_check = m18n.n('network_check_mx_ko')
            result[u] = {
                'smtp_check': smtp_check,
                'mx_check': mx_check
            }
        elif u == 'usage':
            result[u] = {}
            for i in json.loads(glances.getNetwork()):
                iname = i['interface_name']
                if iname in devices.keys():
                    del i['interface_name']
                    if human_readable:
                        for k in i.keys():
                            if k != 'time_since_update':
                                i[k] = binary_to_human(i[k]) + 'B'
                    result[u][iname] = i
                else:
                    logger.debug('interface name %s was not found', iname)
        elif u == 'infos':
            try:
                p_ipv4 = get_public_ip()
            except:
                p_ipv4 = 'unknown'

            l_ip = 'unknown'
            for name, addrs in devices.items():
                if name == 'lo':
                    continue
                if not isinstance(l_ip, dict):
                    l_ip = {}
                l_ip[name] = _extract_inet(addrs)

            gateway = 'unknown'
            output = subprocess.check_output('ip route show'.split())
            m = re.search('default via (.*) dev ([a-z]+[0-9]?)', output)
            if m:
                addr = _extract_inet(m.group(1), True)
                if len(addr) == 1:
                    proto, gateway = addr.popitem()

            result[u] = {
                'public_ip': p_ipv4,
                'local_ip': l_ip,
                'gateway': gateway,
            }
        else:
            raise MoulinetteError(errno.EINVAL, m18n.n('unit_unknown', unit=u))

    if len(units) == 1:
        return result[units[0]]
    return result


def monitor_system(units=None, human_readable=False):
    """
    Monitor system informations and usage

    Keyword argument:
        units -- Unit(s) to monitor
        human_readable -- Print sizes in human readable format

    """
    glances = _get_glances_api()
    result = {}

    if units is None:
        units = ['memory', 'cpu', 'process', 'uptime', 'infos']

    # Retrieve monitoring for unit(s)
    for u in units:
        if u == 'memory':
            ram = json.loads(glances.getMem())
            swap = json.loads(glances.getMemSwap())
            if human_readable:
                for i in ram.keys():
                    if i != 'percent':
                        ram[i] = binary_to_human(ram[i]) + 'B'
                for i in swap.keys():
                    if i != 'percent':
                        swap[i] = binary_to_human(swap[i]) + 'B'
            result[u] = {
                'ram': ram,
                'swap': swap
            }
        elif u == 'cpu':
            result[u] = {
                'load': json.loads(glances.getLoad()),
                'usage': json.loads(glances.getCpu())
            }
        elif u == 'process':
            result[u] = json.loads(glances.getProcessCount())
        elif u == 'uptime':
            result[u] = (str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0])
        elif u == 'infos':
            result[u] = json.loads(glances.getSystem())
        else:
            raise MoulinetteError(errno.EINVAL, m18n.n('unit_unknown', unit=u))

    if len(units) == 1 and type(result[units[0]]) is not str:
        return result[units[0]]
    return result


def monitor_update_stats(period):
    """
    Update monitoring statistics

    Keyword argument:
        period -- Time period to update (day, week, month)

    """
    if period not in ['day', 'week', 'month']:
        raise MoulinetteError(errno.EINVAL, m18n.n('monitor_period_invalid'))

    stats = _retrieve_stats(period)
    if not stats:
        stats = {'disk': {}, 'network': {}, 'system': {}, 'timestamp': []}

    monitor = None
    # Get monitoring stats
    if period == 'day':
        monitor = _monitor_all('day')
    else:
        t = stats['timestamp']
        p = 'day' if period == 'week' else 'week'
        if len(t) > 0:
            monitor = _monitor_all(p, t[len(t) - 1])
        else:
            monitor = _monitor_all(p, 0)
    if not monitor:
        raise MoulinetteError(errno.ENODATA, m18n.n('monitor_stats_no_update'))

    stats['timestamp'].append(time.time())

    # Append disk stats
    for dname, units in monitor['disk'].items():
        disk = {}
        # Retrieve current stats for disk name
        if dname in stats['disk'].keys():
            disk = stats['disk'][dname]

        for unit, values in units.items():
            # Continue if unit doesn't contain stats
            if not isinstance(values, dict):
                continue

            # Retrieve current stats for unit and append new ones
            curr = disk[unit] if unit in disk.keys() else {}
            if unit == 'io':
                disk[unit] = _append_to_stats(curr, values, 'time_since_update')
            elif unit == 'filesystem':
                disk[unit] = _append_to_stats(curr, values, ['fs_type', 'mnt_point'])
        stats['disk'][dname] = disk

    # Append network stats
    net_usage = {}
    for iname, values in monitor['network']['usage'].items():
        # Continue if units doesn't contain stats
        if not isinstance(values, dict):
            continue

        # Retrieve current stats and append new ones
        curr = {}
        if 'usage' in stats['network'] and iname in stats['network']['usage']:
            curr = stats['network']['usage'][iname]
        net_usage[iname] = _append_to_stats(curr, values, 'time_since_update')
    stats['network'] = {'usage': net_usage, 'infos': monitor['network']['infos']}

    # Append system stats
    for unit, values in monitor['system'].items():
        # Continue if units doesn't contain stats
        if not isinstance(values, dict):
            continue

        # Set static infos unit
        if unit == 'infos':
            stats['system'][unit] = values
            continue

        # Retrieve current stats and append new ones
        curr = stats['system'][unit] if unit in stats['system'].keys() else {}
        stats['system'][unit] = _append_to_stats(curr, values)

    _save_stats(stats, period)


def monitor_show_stats(period, date=None):
    """
    Show monitoring statistics

    Keyword argument:
        period -- Time period to show (day, week, month)

    """
    if period not in ['day', 'week', 'month']:
        raise MoulinetteError(errno.EINVAL, m18n.n('monitor_period_invalid'))

    result = _retrieve_stats(period, date)
    if result is False:
        raise MoulinetteError(errno.ENOENT,
                              m18n.n('monitor_stats_file_not_found'))
    elif result is None:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('monitor_stats_period_unavailable'))
    return result


def monitor_enable(with_stats=False):
    """
    Enable server monitoring

    Keyword argument:
        with_stats -- Enable monitoring statistics

    """
    from yunohost.service import (service_status, service_enable,
        service_start)

    glances = service_status('glances')
    if glances['status'] != 'running':
        service_start('glances')
    if glances['loaded'] != 'enabled':
        service_enable('glances')

    # Install crontab
    if with_stats:
        #  day: every 5 min  #  week: every 1 h  #  month: every 4 h  #
        rules = ('*/5 * * * * root {cmd} day >> /dev/null\n'
                 '3 * * * * root {cmd} week >> /dev/null\n'
                 '6 */4 * * * root {cmd} month >> /dev/null').format(
            cmd='/usr/bin/yunohost --quiet monitor update-stats')
        with open(CRONTAB_PATH, 'w') as f:
            f.write(rules)

    logger.success(m18n.n('monitor_enabled'))


def monitor_disable():
    """
    Disable server monitoring

    """
    from yunohost.service import (service_status, service_disable,
        service_stop)

    glances = service_status('glances')
    if glances['status'] != 'inactive':
        service_stop('glances')
    if glances['loaded'] != 'disabled':
        try:
            service_disable('glances')
        except MoulinetteError as e:
            logger.warning(e.strerror)

    # Remove crontab
    try:
        os.remove(CRONTAB_PATH)
    except:
        pass

    logger.success(m18n.n('monitor_disabled'))


def _get_glances_api():
    """
    Retrieve Glances API running on the local server

    """
    try:
        p = xmlrpclib.ServerProxy(GLANCES_URI)
        p.system.methodHelp('getAll')
    except (xmlrpclib.ProtocolError, IOError):
        pass
    else:
        return p

    from yunohost.service import service_status

    if service_status('glances')['status'] != 'running':
        raise MoulinetteError(errno.EPERM, m18n.n('monitor_not_enabled'))
    raise MoulinetteError(errno.EIO, m18n.n('monitor_glances_con_failed'))


def _extract_inet(string, skip_netmask=False, skip_loopback=True):
    """
    Extract IP addresses (v4 and/or v6) from a string limited to one
    address by protocol

    Keyword argument:
        string -- String to search in
        skip_netmask -- True to skip subnet mask extraction
        skip_loopback -- False to include addresses reserved for the
            loopback interface

    Returns:
        A dict of {protocol: address} with protocol one of 'ipv4' or 'ipv6'

    """
    ip4_pattern = '((25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}'
    ip6_pattern = '(((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)'
    ip4_pattern += '/[0-9]{1,2})' if not skip_netmask else ')'
    ip6_pattern += '/[0-9]{1,3})' if not skip_netmask else ')'
    result = {}

    for m in re.finditer(ip4_pattern, string):
        addr = m.group(1)
        if skip_loopback and addr.startswith('127.'):
            continue

        # Limit to only one result
        result['ipv4'] = addr
        break

    for m in re.finditer(ip6_pattern, string):
        addr = m.group(1)
        if skip_loopback and addr == '::1':
            continue

        # Limit to only one result
        result['ipv6'] = addr
        break

    return result


def binary_to_human(n, customary=False):
    """
    Convert bytes or bits into human readable format with binary prefix

    Keyword argument:
        n -- Number to convert
        customary -- Use customary symbol instead of IEC standard

    """
    symbols = ('Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi', 'Yi')
    if customary:
        symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%s" % n


def _retrieve_stats(period, date=None):
    """
    Retrieve statistics from pickle file

    Keyword argument:
        period -- Time period to retrieve (day, week, month)
        date -- Date of stats to retrieve

    """
    pkl_file = None

    # Retrieve pickle file
    if date is not None:
        timestamp = calendar.timegm(date)
        pkl_file = '%s/%d_%s.pkl' % (STATS_PATH, timestamp, period)
    else:
        pkl_file = '%s/%s.pkl' % (STATS_PATH, period)
    if not os.path.isfile(pkl_file):
        return False

    # Read file and process its content
    with open(pkl_file, 'r') as f:
        result = pickle.load(f)
    if not isinstance(result, dict):
        return None
    return result


def _save_stats(stats, period, date=None):
    """
    Save statistics to pickle file

    Keyword argument:
        stats -- Stats dict to save
        period -- Time period of stats (day, week, month)
        date -- Date of stats

    """
    pkl_file = None

    # Set pickle file name
    if date is not None:
        timestamp = calendar.timegm(date)
        pkl_file = '%s/%d_%s.pkl' % (STATS_PATH, timestamp, period)
    else:
        pkl_file = '%s/%s.pkl' % (STATS_PATH, period)
    if not os.path.isdir(STATS_PATH):
        os.makedirs(STATS_PATH)

    # Limit stats
    if date is None:
        t = stats['timestamp']
        limit = {'day': 86400, 'week': 604800, 'month': 2419200}
        if (t[len(t) - 1] - t[0]) > limit[period]:
            begin = t[len(t) - 1] - limit[period]
            stats = _filter_stats(stats, begin)

    # Write file content
    with open(pkl_file, 'w') as f:
        pickle.dump(stats, f)
    return True


def _monitor_all(period=None, since=None):
    """
    Monitor all units (disk, network and system) for the given period
    If since is None, real-time monitoring is returned. Otherwise, the
    mean of stats since this timestamp is calculated and returned.

    Keyword argument:
        period -- Time period to monitor (day, week, month)
        since -- Timestamp of the stats beginning

    """
    result = {'disk': {}, 'network': {}, 'system': {}}

    # Real-time stats
    if period == 'day' and since is None:
        result['disk'] = monitor_disk()
        result['network'] = monitor_network()
        result['system'] = monitor_system()
        return result

    # Retrieve stats and calculate mean
    stats = _retrieve_stats(period)
    if not stats:
        return None
    stats = _filter_stats(stats, since)
    if not stats:
        return None
    result = _calculate_stats_mean(stats)

    return result


def _filter_stats(stats, t_begin=None, t_end=None):
    """
    Filter statistics by beginning and/or ending timestamp

    Keyword argument:
        stats -- Dict stats to filter
        t_begin -- Beginning timestamp
        t_end -- Ending timestamp

    """
    if t_begin is None and t_end is None:
        return stats

    i_begin = i_end = None
    # Look for indexes of timestamp interval
    for i, t in enumerate(stats['timestamp']):
        if t_begin and i_begin is None and t >= t_begin:
            i_begin = i
        if t_end and i != 0 and i_end is None and t > t_end:
            i_end = i
    # Check indexes
    if i_begin is None:
        if t_begin and t_begin > stats['timestamp'][0]:
            return None
        i_begin = 0
    if i_end is None:
        if t_end and t_end < stats['timestamp'][0]:
            return None
        i_end = len(stats['timestamp'])
    if i_begin == 0 and i_end == len(stats['timestamp']):
        return stats

    # Filter function
    def _filter(s, i, j):
        for k, v in s.items():
            if isinstance(v, dict):
                s[k] = _filter(v, i, j)
            elif isinstance(v, list):
                s[k] = v[i:j]
        return s

    stats = _filter(stats, i_begin, i_end)
    return stats


def _calculate_stats_mean(stats):
    """
    Calculate the weighted mean for each statistic

    Keyword argument:
        stats -- Stats dict to process

    """
    timestamp = stats['timestamp']
    t_sum = sum(timestamp)
    del stats['timestamp']

    # Weighted mean function
    def _mean(s, t, ts):
        for k, v in s.items():
            if isinstance(v, dict):
                s[k] = _mean(v, t, ts)
            elif isinstance(v, list):
                try:
                    nums = [float(x * t[i]) for i, x in enumerate(v)]
                except:
                    pass
                else:
                    s[k] = sum(nums) / float(ts)
        return s

    stats = _mean(stats, timestamp, t_sum)
    return stats


def _append_to_stats(stats, monitor, statics=[]):
    """
    Append monitoring statistics to current statistics

    Keyword argument:
        stats -- Current stats dict
        monitor -- Monitoring statistics
        statics -- List of stats static keys

    """
    if isinstance(statics, str):
        statics = [statics]

    # Appending function
    def _append(s, m, st):
        for k, v in m.items():
            if k in st:
                s[k] = v
            elif isinstance(v, dict):
                if k not in s:
                    s[k] = {}
                s[k] = _append(s[k], v, st)
            else:
                if k not in s:
                    s[k] = []
                if isinstance(v, list):
                    s[k].extend(v)
                else:
                    s[k].append(v)
        return s

    stats = _append(stats, monitor, statics)
    return stats
