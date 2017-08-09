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

""" yunohost_dyndns.py

    Subscribe and Update DynDNS Hosts
"""
import os
import re
import json
import glob
import base64
import errno
import requests
import subprocess

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.domain import get_public_ip, _get_maindomain, _build_dns_conf

logger = getActionLogger('yunohost.dyndns')


class IPRouteLine(object):
    """ Utility class to parse an ip route output line

    The output of ip ro is variable and hard to parse completly, it would
    require a real parser, not just a regexp, so do minimal parsing here...

    >>> a = IPRouteLine('2001:: from :: via fe80::c23f:fe:1e:cafe dev eth0  src 2000:de:beef:ca:0:fe:1e:cafe  metric 0')
    >>> a.src_addr
    "2000:de:beef:ca:0:fe:1e:cafe"
    """
    regexp = re.compile(
        r'(?P<unreachable>unreachable)?.*src\s+(?P<src_addr>[0-9a-f:]+).*')

    def __init__(self, line):
        self.m = self.regexp.match(line)
        if not self.m:
            raise ValueError("Not a valid ip route get line")

        # make regexp group available as object attributes
        for k, v in self.m.groupdict().items():
            setattr(self, k, v)

re_dyndns_private_key = re.compile(
    r'.*/K(?P<domain>[^\s\+]+)\.\+157.+\.private$'
)


def dyndns_subscribe(subscribe_host="dyndns.yunohost.org", domain=None, key=None):
    """
    Subscribe to a DynDNS service

    Keyword argument:
        domain -- Full domain to subscribe with
        key -- Public DNS key
        subscribe_host -- Dynette HTTP API to subscribe to

    """
    if domain is None:
        domain = _get_maindomain()

    # Verify if domain is available
    try:
        if requests.get('https://%s/test/%s' % (subscribe_host, domain)).status_code != 200:
            raise MoulinetteError(errno.EEXIST, m18n.n('dyndns_unavailable'))
    except requests.ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))

    if key is None:
        if len(glob.glob('/etc/yunohost/dyndns/*.key')) == 0:
            os.makedirs('/etc/yunohost/dyndns')

            logger.info(m18n.n('dyndns_key_generating'))

            os.system('cd /etc/yunohost/dyndns && '
                      'dnssec-keygen -a hmac-md5 -b 128 -r /dev/urandom -n USER %s' % domain)
            os.system('chmod 600 /etc/yunohost/dyndns/*.key /etc/yunohost/dyndns/*.private')

        key_file = glob.glob('/etc/yunohost/dyndns/*.key')[0]
        with open(key_file) as f:
            key = f.readline().strip().split(' ')[-1]

    # Send subscription
    try:
        r = requests.post('https://%s/key/%s' % (subscribe_host, base64.b64encode(key)), data={'subdomain': domain})
    except requests.ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))
    if r.status_code != 201:
        try:
            error = json.loads(r.text)['error']
        except:
            error = "Server error"
        raise MoulinetteError(errno.EPERM,
                              m18n.n('dyndns_registration_failed', error=error))

    logger.success(m18n.n('dyndns_registered'))

    dyndns_installcron()


def dyndns_update(dyn_host="dyndns.yunohost.org", domain=None, key=None,
                  ipv4=None, ipv6=None):
    """
    Update IP on DynDNS platform

    Keyword argument:
        domain -- Full domain to update
        dyn_host -- Dynette DNS server to inform
        key -- Public DNS key
        ipv4 -- IP address to send
        ipv6 -- IPv6 address to send

    """
    # IPv4
    if ipv4 is None:
        ipv4 = get_public_ip()

    try:
        with open('/etc/yunohost/dyndns/old_ip', 'r') as f:
            old_ip = f.readline().rstrip()
    except IOError:
        old_ip = '0.0.0.0'

    # IPv6
    if ipv6 is None:
        try:
            ip_route_out = subprocess.check_output(
                ['ip', 'route', 'get', '2000::']).split('\n')

            if len(ip_route_out) > 0:
                route = IPRouteLine(ip_route_out[0])
                if not route.unreachable:
                    ipv6 = route.src_addr

        except (OSError, ValueError) as e:
            # Unlikely case "ip route" does not return status 0
            # or produces unexpected output
            raise MoulinetteError(errno.EBADMSG,
                                  "ip route cmd error : {}".format(e))

        if ipv6 is None:
            logger.info(m18n.n('no_ipv6_connectivity'))

    try:
        with open('/etc/yunohost/dyndns/old_ipv6', 'r') as f:
            old_ipv6 = f.readline().rstrip()
    except IOError:
        old_ipv6 = '0000:0000:0000:0000:0000:0000:0000:0000'

    # no need to update
    if old_ip == ipv4 and old_ipv6 == ipv6:
        return

    if domain is None:
        # Retrieve the first registered domain
        for path in glob.iglob('/etc/yunohost/dyndns/K*.private'):
            match = re_dyndns_private_key.match(path)
            if not match:
                continue
            _domain = match.group('domain')

            try:
                # Check if domain is registered
                request_url = 'https://{0}/test/{1}'.format(dyn_host, _domain)
                if requests.get(request_url, timeout=30).status_code == 200:
                    continue
            except requests.ConnectionError:
                raise MoulinetteError(errno.ENETUNREACH,
                                      m18n.n('no_internet_connection'))
            except requests.exceptions.Timeout:
                logger.warning("Correction timed out on {}, skip it".format(
                                   request_url))
            domain = _domain
            key = path
            break
        if not domain:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('dyndns_no_domain_registered'))

    if key is None:
        keys = glob.glob('/etc/yunohost/dyndns/K{0}.+*.private'.format(domain))

        if not keys:
            raise MoulinetteError(errno.EIO, m18n.n('dyndns_key_not_found'))

        key = keys[0]

    host = domain.split('.')[1:]
    host = '.'.join(host)

    lines = [
        'server %s' % dyn_host,
        'zone %s' % host,
    ]

    dns_conf = _build_dns_conf(domain)

    # Delete the old records for all domain/subdomains

    # every dns_conf.values() is a list of :
    # [{"name": "...", "ttl": "...", "type": "...", "value": "..."}]
    for records in dns_conf.values():
        for record in records:
            action = "update delete {name}.{domain}.".format(domain=domain, **record)
            action = action.replace(" @.", " ")
            lines.append(action)

    # Add the new records for all domain/subdomains

    for records in dns_conf.values():
        for record in records:
            # (For some reason) here we want the format with everytime the
            # entire, full domain shown explicitly, not just "muc" or "@", it
            # should be muc.the.domain.tld. or the.domain.tld
            if record["value"] == "@":
                record["value"] = domain

            action = "update add {name}.{domain}. {ttl} {type} {value}".format(domain=domain, **record)
            action = action.replace(" @.", " ")
            lines.append(action)

    lines += [
        'show',
        'send'
    ]

    with open('/etc/yunohost/dyndns/zone', 'w') as zone:
        zone.write('\n'.join(lines))

    if os.system('/usr/bin/nsupdate -k %s /etc/yunohost/dyndns/zone' % key) != 0:
        os.system('rm -f /etc/yunohost/dyndns/old_ip')
        os.system('rm -f /etc/yunohost/dyndns/old_ipv6')
        raise MoulinetteError(errno.EPERM,
                              m18n.n('dyndns_ip_update_failed'))

    logger.success(m18n.n('dyndns_ip_updated'))
    with open('/etc/yunohost/dyndns/old_ip', 'w') as f:
        f.write(ipv4)
    if ipv6 is not None:
        with open('/etc/yunohost/dyndns/old_ipv6', 'w') as f:
            f.write(ipv6)


def dyndns_installcron():
    """
    Install IP update cron


    """
    with open('/etc/cron.d/yunohost-dyndns', 'w+') as f:
        f.write('*/2 * * * * root yunohost dyndns update >> /dev/null\n')

    logger.success(m18n.n('dyndns_cron_installed'))


def dyndns_removecron():
    """
    Remove IP update cron


    """
    try:
        os.remove("/etc/cron.d/yunohost-dyndns")
    except:
        raise MoulinetteError(errno.EIO, m18n.n('dyndns_cron_remove_failed'))

    logger.success(m18n.n('dyndns_cron_removed'))
