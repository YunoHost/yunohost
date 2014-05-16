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

""" yunohost_domain.py

    Manage domains
"""
import os
import sys
import datetime
import re
import shutil
import json
import yaml
import errno
from urllib import urlopen

from moulinette.core import MoulinetteError


def domain_list(auth, filter=None, limit=None, offset=None):
    """
    List domains

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for domain fetching
        limit -- Maximum number of domain fetched

    """
    result_list = []

    # Set default arguments values
    if offset is None:
        offset = 0
    if limit is None:
        limit = 1000
    if filter is None:
        filter = 'virtualdomain=*'

    result = auth.search('ou=domains,dc=yunohost,dc=org', filter, ['virtualdomain'])

    if len(result) > offset and limit > 0:
        for domain in result[offset:offset+limit]:
            result_list.append(domain['virtualdomain'][0])
    return { 'domains': result_list }


def domain_add(auth, domains, main=False, dyndns=False):
    """
    Create a custom domain

    Keyword argument:
        domains -- Domain name to add
        main -- Is the main domain
        dyndns -- Subscribe to DynDNS

    """
    attr_dict = { 'objectClass' : ['mailDomain', 'top'] }
    ip = str(urlopen('http://ip.yunohost.org').read())
    now = datetime.datetime.now()
    timestamp = str(now.year) + str(now.month) + str(now.day)
    result = []

    if not isinstance(domains, list):
        domains = [ domains ]

    for domain in domains:
        if domain in domain_list(auth)['domains']:
            continue

        # DynDNS domain
        if dyndns:
            if len(domain.split('.')) < 3:
                raise MoulinetteError(errno.EINVAL, m18n.n('domain_dyndns_invalid'))
            import requests
            from yunohost.dyndns import dyndns_subscribe

            r = requests.get('http://dyndns.yunohost.org/domains')
            dyndomains = json.loads(r.text)
            dyndomain  = '.'.join(domain.split('.')[1:])
            if dyndomain in dyndomains:
                if os.path.exists('/etc/cron.d/yunohost-dyndns'):
                    raise MoulinetteError(errno.EPERM,
                                          m18n.n('domain_dyndns_already_subscribed'))
                dyndns_subscribe(domain=domain)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('domain_dyndns_root_unknown'))

        # Commands
        ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
        ssl_domain_path  = '/etc/yunohost/certs/%s' % domain
        with open('%s/serial' % ssl_dir, 'r') as f:
            serial = f.readline().rstrip()
        try: os.listdir(ssl_domain_path)
        except OSError: os.makedirs(ssl_domain_path)

        command_list = [
            'cp %s/openssl.cnf %s'                               % (ssl_dir, ssl_domain_path),
            'sed -i "s/yunohost.org/%s/g" %s/openssl.cnf'        % (domain, ssl_domain_path),
            'openssl req -new -config %s/openssl.cnf -days 3650 -out %s/certs/yunohost_csr.pem -keyout %s/certs/yunohost_key.pem -nodes -batch'
            % (ssl_domain_path, ssl_dir, ssl_dir),
            'openssl ca -config %s/openssl.cnf -days 3650 -in %s/certs/yunohost_csr.pem -out %s/certs/yunohost_crt.pem -batch'
            % (ssl_domain_path, ssl_dir, ssl_dir),
            'ln -s /etc/ssl/certs/ca-yunohost_crt.pem %s/ca.pem' % ssl_domain_path,
            'cp %s/certs/yunohost_key.pem    %s/key.pem'         % (ssl_dir, ssl_domain_path),
            'cp %s/newcerts/%s.pem %s/crt.pem'                   % (ssl_dir, serial, ssl_domain_path),
            'chmod 755 %s'                                       % ssl_domain_path,
            'chmod 640 %s/key.pem'                               % ssl_domain_path,
            'chmod 640 %s/crt.pem'                               % ssl_domain_path,
            'chmod 600 %s/openssl.cnf'                           % ssl_domain_path,
            'chown root:metronome %s/key.pem'                    % ssl_domain_path,
            'chown root:metronome %s/crt.pem'                    % ssl_domain_path
        ]

        for command in command_list:
            if os.system(command) != 0:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('domain_cert_gen_failed'))

        try:
            auth.validate_uniqueness({ 'virtualdomain': domain })
        except MoulinetteError:
            raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))


        attr_dict['virtualdomain'] = domain

        try:
            with open('/var/lib/bind/%s.zone' % domain) as f: pass
        except IOError as e:
            zone_lines = [
             '$TTL    38400',
             '%s.      IN   SOA   ns.%s. root.%s. %s 10800 3600 604800 38400' % (domain, domain, domain, timestamp),
             '%s.      IN   NS    ns.%s.'                         % (domain, domain),
             '%s.      IN   A     %s'                             % (domain, ip),
             '%s.      IN   MX    5 %s.'                          % (domain, domain),
             '%s.      IN   TXT   "v=spf1 mx a -all"'             % domain,
             'ns.%s.   IN   A     %s'                             % (domain, ip),
             '_xmpp-client._tcp.%s.  IN   SRV   0  5   5222  %s.' % (domain, domain),
             '_xmpp-server._tcp.%s.  IN   SRV   0  5   5269  %s.' % (domain, domain),
             '_jabber._tcp.%s.       IN   SRV   0  5   5269  %s.' % (domain, domain),
            ]
            if main:
                zone_lines.extend([
                    'pubsub.%s.   IN   A     %s' % (domain, ip),
                    'muc.%s.      IN   A     %s' % (domain, ip),
                    'vjud.%s.     IN   A     %s' % (domain, ip)
                ])
            with open('/var/lib/bind/%s.zone' % domain, 'w') as zone:
                for line in zone_lines:
                    zone.write(line + '\n')

            os.system('chown bind /var/lib/bind/%s.zone' % domain)

        else:
            raise MoulinetteError(errno.EEXIST,
                                  m18n.n('domain_zone_exists'))

        conf_lines = [
            'zone "%s" {' % domain,
            '    type master;',
            '    file "/var/lib/bind/%s.zone";' % domain,
            '    allow-transfer {',
            '        127.0.0.1;',
            '        localnets;',
            '    };',
            '};'
        ]
        with open('/etc/bind/named.conf.local', 'a') as conf:
            for line in conf_lines:
               conf.write(line + '\n')

        os.system('service bind9 reload')

        # XMPP
        try:
            with open('/etc/metronome/conf.d/%s.cfg.lua' % domain) as f: pass
        except IOError as e:
            conf_lines = [
                'VirtualHost "%s"' % domain,
                '  ssl = {',
                '        key = "%s/key.pem";' % ssl_domain_path,
                '        certificate = "%s/crt.pem";' % ssl_domain_path,
                '  }',
                '  authentication = "ldap2"',
                '  ldap = {',
                '     hostname      = "localhost",',
                '     user = {',
                '       basedn        = "ou=users,dc=yunohost,dc=org",',
                '       filter        = "(&(objectClass=posixAccount)(mail=*@%s))",' % domain,
                '       usernamefield = "mail",',
                '       namefield     = "cn",',
                '       },',
                '  }',
            ]
            with open('/etc/metronome/conf.d/%s.cfg.lua' % domain, 'w') as conf:
                for line in conf_lines:
                    conf.write(line + '\n')

        os.system('mkdir -p /var/lib/metronome/%s/pep' % domain.replace('.', '%2e'))
        os.system('chown -R metronome: /var/lib/metronome/')
        os.system('chown -R metronome: /etc/metronome/conf.d/')
        os.system('service metronome restart')


        # Nginx
        os.system('cp /usr/share/yunohost/yunohost-config/nginx/template.conf /etc/nginx/conf.d/%s.conf' % domain)
        os.system('mkdir /etc/nginx/conf.d/%s.d/' % domain)
        os.system('sed -i s/yunohost.org/%s/g /etc/nginx/conf.d/%s.conf' % (domain, domain))
        os.system('service nginx reload')

        if auth.add('virtualdomain=%s,ou=domains' % domain, attr_dict):
            result.append(domain)
            continue
        else:
            raise MoulinetteError(errno.EIO, m18n.n('domain_creation_failed'))


    os.system('yunohost app ssowatconf > /dev/null 2>&1')

    msignals.display(m18n.n('domain_created'), 'success')
    return { 'domains': result }


def domain_remove(auth, domains):
    """
    Delete domains

    Keyword argument:
        domains -- Domain(s) to delete

    """
    result = []
    domains_list = domain_list(auth)['domains']

    if not isinstance(domains, list):
        domains = [ domains ]

    for domain in domains:
        if domain not in domains_list:
            raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

        # Check if apps are installed on the domain
        for app in os.listdir('/etc/yunohost/apps/'):
            with open('/etc/yunohost/apps/' + app +'/settings.yml') as f:
                try:
                    app_domain = yaml.load(f)['domain']
                except:
                    continue
                else:
                    if app_domain == domain:
                        raise MoulinetteError(errno.EPERM,
                                              m18n.n('domain_uninstall_app_first'))

        if auth.remove('virtualdomain=' + domain + ',ou=domains'):
            try:
                shutil.rmtree('/etc/yunohost/certs/%s' % domain)
                os.remove('/var/lib/bind/%s.zone' % domain)
                shutil.rmtree('/var/lib/metronome/%s' % domain.replace('.', '%2e'))
                os.remove('/etc/metronome/conf.d/%s.cfg.lua' % domain)
                shutil.rmtree('/etc/nginx/conf.d/%s.d' % domain)
                os.remove('/etc/nginx/conf.d/%s.conf' % domain)
            except:
                pass
            with open('/etc/bind/named.conf.local', 'r') as conf:
                conf_lines = conf.readlines()
            with open('/etc/bind/named.conf.local', 'w') as conf:
                in_block = False
                for line in conf_lines:
                    if re.search(r'^zone "%s' % domain, line):
                        in_block = True
                    if in_block:
                        if re.search(r'^};$', line):
                            in_block = False
                    else:
                        conf.write(line)
            result.append(domain)
            continue
        else:
            raise MoulinetteError(errno.EIO, m18n.n('domain_deletion_failed'))

    os.system('yunohost app ssowatconf > /dev/null 2>&1')
    os.system('service nginx reload')
    os.system('service bind9 reload')
    os.system('service metronome restart')

    msignals.display(m18n.n('domain_deleted'), 'success')
    return { 'domains': result }
