# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2017 YUNOHOST.ORG

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
import logging
import re
import subprocess
from moulinette.utils.network import download_text

logger = logging.getLogger('yunohost.utils.network')


def get_public_ip(protocol=4):
    """Retrieve the public IP address from ip.yunohost.org"""

    if protocol == 4:
        url = 'https://ip.yunohost.org'
    elif protocol == 6:
        url = 'https://ip6.yunohost.org'
    else:
        raise ValueError("invalid protocol version")

    try:
        return download_text(url, timeout=30).strip()
    except Exception as e:
        logger.debug("Could not get public IPv%s : %s" % (str(protocol), str(e)))
        return None


def get_network_interfaces():

    # Get network devices and their addresses (raw infos from 'ip addr')
    devices_raw = {}
    output = subprocess.check_output('ip addr show'.split())
    for d in re.split(r'^(?:[0-9]+: )', output, flags=re.MULTILINE):
        # Extract device name (1) and its addresses (2)
        m = re.match(r'([^\s@]+)(?:@[\S]+)?: (.*)', d, flags=re.DOTALL)
        if m:
            devices_raw[m.group(1)] = m.group(2)

    # Parse relevant informations for each of them
    devices = {name: _extract_inet(addrs) for name, addrs in devices_raw.items() if name != "lo"}

    return devices


def get_gateway():

    output = subprocess.check_output('ip route show'.split())
    m = re.search(r'default via (.*) dev ([a-z]+[0-9]?)', output)
    if not m:
        return None

    addr = _extract_inet(m.group(1), True)
    return addr.popitem()[1] if len(addr) == 1 else None


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
    ip4_pattern = r'((25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}'
    ip6_pattern = r'(((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)'
    ip4_pattern += r'/[0-9]{1,2})' if not skip_netmask else ')'
    ip6_pattern += r'/[0-9]{1,3})' if not skip_netmask else ')'
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
