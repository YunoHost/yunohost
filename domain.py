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


def domain_add(auth, domain, dyndns=False):
    """
    Create a custom domain

    Keyword argument:
        domain -- Domain name to add
        dyndns -- Subscribe to DynDNS

    """
    attr_dict = { 'objectClass' : ['mailDomain', 'top'] }
    try:
        ip = str(urlopen('http://ip.yunohost.org').read())
    except IOError:
        ip = "127.0.0.1"
    now = datetime.datetime.now()
    timestamp = str(now.year) + str(now.month) + str(now.day)

    if domain in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))

    # DynDNS domain
    if dyndns:
        if len(domain.split('.')) < 3:
            raise MoulinetteError(errno.EINVAL, m18n.n('domain_dyndns_invalid'))
        import requests
        from yunohost.dyndns import dyndns_subscribe

        try:
            r = requests.get('https://dyndns.yunohost.org/domains')
        except ConnectionError:
            pass
        else:
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

    try:
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

        dnsmasq_config_path='/etc/dnsmasq.d'
        try:
            os.listdir(dnsmasq_config_path)
        except OSError:
            msignals.display(m18n.n('dnsmasq_isnt_installed'),
                                  'warning')
            os.makedirs(dnsmasq_config_path)

        try:
            with open('%s/%s' % (dnsmasq_config_path, domain)) as f: pass
        except IOError as e:
            zone_lines = [
             'address=/%s/%s' % (domain, ip),
             'txt-record=%s,"v=spf1 mx a -all"' % domain,
             'mx-host=%s,%s,5' % (domain, domain),
             'srv-host=_xmpp-client._tcp.%s,%s,5222,0,5' % (domain, domain),
             'srv-host=_xmpp-server._tcp.%s,%s,5269,0,5' % (domain, domain),
             'srv-host=_jabber._tcp.%s,%s,5269,0,5' % (domain, domain),
            ]
            with open('%s/%s' % (dnsmasq_config_path, domain), 'w') as zone:
                for line in zone_lines:
                    zone.write(line + '\n')
            os.system('service dnsmasq restart')

        else:
            msignals.display(m18n.n('domain_zone_exists'),
                                 'warning')

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

        if not auth.add('virtualdomain=%s,ou=domains' % domain, attr_dict):
            raise MoulinetteError(errno.EIO, m18n.n('domain_creation_failed'))

        os.system('yunohost app ssowatconf > /dev/null 2>&1')
    except:
        # Force domain removal silently
        try: domain_remove(auth, domain, True)
        except: pass
        raise

    msignals.display(m18n.n('domain_created'), 'success')


def domain_remove(auth, domain, force=False):
    """
    Delete domains

    Keyword argument:
        domain -- Domain to delete
        force -- Force the domain removal

    """
    if not force and domain not in domain_list(auth)['domains']:
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

    if auth.remove('virtualdomain=' + domain + ',ou=domains') or force:
        command_list = [
            'rm -rf /etc/yunohost/certs/%s' % domain,
            'rm -f  /etc/dnsmasq.d/%s' % domain,
            'rm -rf /var/lib/metronome/%s' % domain.replace('.', '%2e'),
            'rm -f  /etc/metronome/conf.d/%s.cfg.lua' % domain,
            'rm -rf /etc/nginx/conf.d/%s.d' % domain,
            'rm -f  /etc/nginx/conf.d/%s.conf' % domain,
        ]
        for command in command_list:
            if os.system(command) != 0:
                msignals.display(m18n.n('path_removal_failed', command[7:]),
                                 'warning')
    else:
        raise MoulinetteError(errno.EIO, m18n.n('domain_deletion_failed'))

    os.system('yunohost app ssowatconf > /dev/null 2>&1')
    os.system('service nginx reload')
    os.system('service bind9 reload')
    os.system('service metronome restart')

    msignals.display(m18n.n('domain_deleted'), 'success')
