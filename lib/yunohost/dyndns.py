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
import sys
import re
import requests
import json
import glob
import base64
import errno

from moulinette.core import MoulinetteError


class IfInet6Line(object):
    """ Utility class to parse a /proc/net/if_inet6 line

    >>> a = IfInet6Line("00000000000000000000000000000001 01 80 10 80 lo")
    >>> a.hex_addr
    "00000000000000000000000000000001"
    """
    regexp = re.compile(
        r'^(?P<hex_addr>[0-9a-f]{32}) (?P<devnum>[0-9a-f]{2}) '
        r'(?P<prefix_length>[0-9a-f]{2}) (?P<scope>[0-9a-f]{2}) '
        r'(?P<iface_flags>[0-9a-f]{2})\s+(?P<iface_name>\w+)$')

    re_leadingzero = re.compile(r':0+')
    re_multisemicolons = re.compile(r':::+')

    SCOPE_NODELOCAL = '10'
    SCOPE_LINKLOCAL = '20'
    SCOPE_SITELOCAL = '50'
    SCOPE_ORGLOCAL = '80'
    SCOPE_GLOBAL = '00'

    def __init__(self, line):
        self.m = self.regexp.match(line)
        if not self.m:
            raise ValueError("Not a valid /proc/net/if_inet6 line")
        # make regexp group available as object attributes
        for k, v in self.m.groupdict().items():
            setattr(self, k, v)

        self.addr = self._compact_quad(self._quad_notation(self.hex_addr))

    @staticmethod
    def _quad_notation(hex_addr):
        """ Transform IPv6 hex form in quad notation

        >>> IfNet6Line._quad_notation('00000000000000000000000000000001')
        "0000:0000:0000:0000:0000:0000:0000:0001"
        """
        return ':'.join(map(''.join, zip(*[iter(hex_addr)]*4)))

    @classmethod
    def _compact_quad(cls, quad_addr):
        """ Remove leading zeroes

        >>>> IfNet6Line._compact_quad('0000:0000:0000:0000:0000:0000:0000:0001')
        "::0"
        """
        wo_zeroes = cls.re_leadingzero.sub(':', quad_addr)
        compact_quad = cls.re_multisemicolons.sub('::', wo_zeroes)
        return compact_quad


def dyndns_subscribe(subscribe_host="dyndns.yunohost.org", domain=None, key=None):
    """
    Subscribe to a DynDNS service

    Keyword argument:
        domain -- Full domain to subscribe with
        key -- Public DNS key
        subscribe_host -- Dynette HTTP API to subscribe to

    """
    if domain is None:
        with open('/etc/yunohost/current_host', 'r') as f:
            domain = f.readline().rstrip()

    # Verify if domain is available
    try:
        if requests.get('https://%s/test/%s' % (subscribe_host, domain)).status_code != 200:
            raise MoulinetteError(errno.EEXIST, m18n.n('dyndns_unavailable'))
    except requests.ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))

    if key is None:
        if len(glob.glob('/etc/yunohost/dyndns/*.key')) == 0:
            os.makedirs('/etc/yunohost/dyndns')

            msignals.display(m18n.n('dyndns_key_generating'))

            os.system('cd /etc/yunohost/dyndns && ' \
                      'dnssec-keygen -a hmac-md5 -b 128 -n USER %s' % domain)
            os.system('chmod 600 /etc/yunohost/dyndns/*.key /etc/yunohost/dyndns/*.private')

        key_file = glob.glob('/etc/yunohost/dyndns/*.key')[0]
        with open(key_file) as f:
            key = f.readline().strip().split(' ')[-1]

    # Send subscription
    try:
        r = requests.post('https://%s/key/%s' % (subscribe_host, base64.b64encode(key)), data={ 'subdomain': domain })
    except ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))
    if r.status_code != 201:
        try:    error = json.loads(r.text)['error']
        except: error = "Server error"
        raise MoulinetteError(errno.EPERM,
                              m18n.n('dyndns_registration_failed', error))

    msignals.display(m18n.n('dyndns_registered'), 'success')

    dyndns_installcron()


def dyndns_update(dyn_host="dynhost.yunohost.org", domain=None, key=None, ip=None):
    """
    Update IP on DynDNS platform

    Keyword argument:
        domain -- Full domain to subscribe with
        dyn_host -- Dynette DNS server to inform
        key -- Public DNS key
        ip -- IP address to send

    """
    if domain is None:
        with open('/etc/yunohost/current_host', 'r') as f:
            domain = f.readline().rstrip()

    if ip is None:
        try:
            new_ip = requests.get('http://ip.yunohost.org').text
        except ConnectionError:
            raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))
    else:
        new_ip = ip

    try:
        with open('/etc/yunohost/dyndns/old_ip', 'r') as f:
            old_ip = f.readline().rstrip()
    except IOError:
        old_ip = '0.0.0.0'

    # IPv6
    new_ipv6 = None
    try:
        with open('/etc/yunohost/ipv6') as f:
            old_ipv6 = f.readline().rstrip()
    except IOError:
        old_ipv6 = '0000:0000:0000:0000:0000:0000:0000:0000'

    try:
        # Get the interface
        with open('/etc/yunohost/interface') as f:
            interface = f.readline().rstrip()
        with open('/proc/net/if_inet6') as f:
            for line in f.readlines():
                addr_line = IfInet6Line(line)
                # stop at the first globally routable address
                if ((addr_line.iface_name == interface) and
                        (addr_line.scope == addr_line.SCOPE_GLOBAL)):
                    new_ipv6 = addr_line.addr
                    with open('/etc/yunohost/ipv6', 'w+') as f:
                        f.write(new_ipv6)
                    break
    except IOError:
        pass
    except ValueError:
        raise MoulinetteError(None, "Invalid /proc/net/if_inet6 format")
    if old_ip != new_ip or old_ipv6 != new_ipv6 and new_ipv6 is not None:
        host = domain.split('.')[1:]
        host = '.'.join(host)
        lines = [
            'server %s' % dyn_host,
            'zone %s' % host,
            'update delete %s. A'        % domain,
            'update delete %s. AAAA'     % domain,
            'update delete %s. MX'       % domain,
            'update delete %s. TXT'      % domain,
            'update delete pubsub.%s. A' % domain,
            'update delete pubsub.%s. AAAA' % domain,
            'update delete muc.%s. A'    % domain,
            'update delete muc.%s. AAAA'    % domain,
            'update delete vjud.%s. A'   % domain,
            'update delete vjud.%s. AAAA'   % domain,
            'update delete _xmpp-client._tcp.%s. SRV' % domain,
            'update delete _xmpp-server._tcp.%s. SRV' % domain,
            'update add %s. 1800 A %s'      % (domain, new_ip),
            'update add %s. 14400 MX 5 %s.' % (domain, domain),
            'update add %s. 14400 TXT "v=spf1 a mx -all"' % domain,
            'update add pubsub.%s. 1800 A %s'    % (domain, new_ip),
            'update add muc.%s. 1800 A %s'       % (domain, new_ip),
            'update add vjud.%s. 1800 A %s'      % (domain, new_ip),
            'update add _xmpp-client._tcp.%s. 14400 SRV 0 5 5222 %s.' % (domain, domain),
            'update add _xmpp-server._tcp.%s. 14400 SRV 0 5 5269 %s.' % (domain, domain),
        ]
        if new_ipv6 is not None:
            lines += [
                'update add %s. 1800 AAAA %s'   % (domain, new_ipv6),
                'update add pubsub.%s. 1800 AAAA %s' % (domain, new_ipv6),
                'update add muc.%s. 1800 AAAA %s'    % (domain, new_ipv6),
                'update add vjud.%s. 1800 AAAA %s'   % (domain, new_ipv6),
            ]
        lines += [
            'show',
            'send'
        ]
        with open('/etc/yunohost/dyndns/zone', 'w') as zone:
            for line in lines:
                zone.write(line + '\n')

        if key is None:
            private_key_file = glob.glob('/etc/yunohost/dyndns/*.private')[0]
        else:
            private_key_file = key
        if os.system('/usr/bin/nsupdate -k %s /etc/yunohost/dyndns/zone' % private_key_file) == 0:
            msignals.display(m18n.n('dyndns_ip_updated'), 'success')
            with open('/etc/yunohost/dyndns/old_ip', 'w') as f:
                f.write(new_ip)
        else:
            os.system('rm /etc/yunohost/dyndns/old_ip > /dev/null 2>&1')
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('dyndns_ip_update_failed'))


def dyndns_installcron():
    """
    Install IP update cron


    """
    with open('/etc/cron.d/yunohost-dyndns', 'w+') as f:
        f.write('*/2 * * * * root yunohost dyndns update >> /dev/null\n')

    msignals.display(m18n.n('dyndns_cron_installed'), 'success')


def dyndns_removecron():
    """
    Remove IP update cron


    """
    try:
        os.remove("/etc/cron.d/yunohost-dyndns")
    except:
        raise MoulinetteError(errno.EIO, m18n.n('dyndns_cron_remove_failed'))

    msignals.display(m18n.n('dyndns_cron_removed'), 'success')
