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
import datetime
import re
import json
import yaml
import errno
import requests

from urllib import urlopen

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

import yunohost.certificate

from yunohost.service import service_regen_conf

logger = getActionLogger('yunohost.domain')


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
        for domain in result[offset:offset + limit]:
            result_list.append(domain['virtualdomain'][0])

    return {'domains': result_list}


def domain_add(auth, domain, dyndns=False):
    """
    Create a custom domain

    Keyword argument:
        domain -- Domain name to add
        dyndns -- Subscribe to DynDNS

    """
    from yunohost.hook import hook_callback

    attr_dict = {'objectClass': ['mailDomain', 'top']}

    now = datetime.datetime.now()
    timestamp = str(now.year) + str(now.month) + str(now.day)

    if domain in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))

    # DynDNS domain
    if dyndns:
        if len(domain.split('.')) < 3:
            raise MoulinetteError(errno.EINVAL, m18n.n('domain_dyndns_invalid'))
        from yunohost.dyndns import dyndns_subscribe

        try:
            r = requests.get('https://dyndns.yunohost.org/domains')
        except requests.ConnectionError:
            pass
        else:
            dyndomains = json.loads(r.text)
            dyndomain = '.'.join(domain.split('.')[1:])
            if dyndomain in dyndomains:
                if os.path.exists('/etc/cron.d/yunohost-dyndns'):
                    raise MoulinetteError(errno.EPERM,
                                          m18n.n('domain_dyndns_already_subscribed'))
                dyndns_subscribe(domain=domain)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('domain_dyndns_root_unknown'))

    try:
        yunohost.certificate._certificate_install_selfsigned([domain], False)

        try:
            auth.validate_uniqueness({'virtualdomain': domain})
        except MoulinetteError:
            raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))

        attr_dict['virtualdomain'] = domain

        if not auth.add('virtualdomain=%s,ou=domains' % domain, attr_dict):
            raise MoulinetteError(errno.EIO, m18n.n('domain_creation_failed'))

        try:
            with open('/etc/yunohost/installed', 'r') as f:
                service_regen_conf(names=[
                    'nginx', 'metronome', 'dnsmasq', 'rmilter'])
                os.system('yunohost app ssowatconf > /dev/null 2>&1')
        except IOError:
            pass
    except:
        # Force domain removal silently
        try:
            domain_remove(auth, domain, True)
        except:
            pass
        raise

    hook_callback('post_domain_add', args=[domain])

    logger.success(m18n.n('domain_created'))


def domain_remove(auth, domain, force=False):
    """
    Delete domains

    Keyword argument:
        domain -- Domain to delete
        force -- Force the domain removal

    """
    from yunohost.hook import hook_callback

    if not force and domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    # Check domain is not the main domain
    if domain == _get_maindomain():
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_cannot_remove_main'))

    # Check if apps are installed on the domain
    for app in os.listdir('/etc/yunohost/apps/'):
        with open('/etc/yunohost/apps/' + app + '/settings.yml') as f:
            try:
                app_domain = yaml.load(f)['domain']
            except:
                continue
            else:
                if app_domain == domain:
                    raise MoulinetteError(errno.EPERM,
                                          m18n.n('domain_uninstall_app_first'))

    if auth.remove('virtualdomain=' + domain + ',ou=domains') or force:
        os.system('rm -rf /etc/yunohost/certs/%s' % domain)
    else:
        raise MoulinetteError(errno.EIO, m18n.n('domain_deletion_failed'))

    service_regen_conf(names=['nginx', 'metronome', 'dnsmasq'])
    os.system('yunohost app ssowatconf > /dev/null 2>&1')

    hook_callback('post_domain_remove', args=[domain])

    logger.success(m18n.n('domain_deleted'))


def domain_dns_conf(domain, ttl=None):
    """
    Generate DNS configuration for a domain

    Keyword argument:
        domain -- Domain name
        ttl -- Time to live

    """

    ttl = 3600 if ttl is None else ttl

    dns_conf = _build_dns_conf(domain, ttl)

    result = ""

    result += "# Basic ipv4/ipv6 records"
    for record in dns_conf["basic"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    result += "\n\n"
    result += "# XMPP"
    for record in dns_conf["xmpp"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    result += "\n\n"
    result += "# Mail"
    for record in dns_conf["mail"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    return result


def domain_cert_status(auth, domain_list, full=False):
    return yunohost.certificate.certificate_status(auth, domain_list, full)


def domain_cert_install(auth, domain_list, force=False, no_checks=False, self_signed=False, staging=False):
    return yunohost.certificate.certificate_install(auth, domain_list, force, no_checks, self_signed, staging)


def domain_cert_renew(auth, domain_list, force=False, no_checks=False, email=False, staging=False):
    return yunohost.certificate.certificate_renew(auth, domain_list, force, no_checks, email, staging)


def domain_url_available(auth, domain, path):
    """
    Check availability of a web path

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
    """

    domain, path = _normalize_domain_path(domain, path)

    # Abort if domain is unknown
    if domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    # This import cannot be put on top of file because it would create a
    # recursive import...
    from yunohost.app import app_map

    # Fetch apps map
    apps_map = app_map(raw=True)

    # Loop through all apps to check if path is taken by one of them
    available = True
    if domain in apps_map:
        # Loop through apps
        for p, a in apps_map[domain].items():
            if path == p:
                available = False
                break
            # We also don't want conflicts with other apps starting with
            # same name
            elif path.startswith(p) or p.startswith(path):
                available = False
                break

    return available


def get_public_ip(protocol=4):
    """Retrieve the public IP address from ip.yunohost.org"""
    if protocol == 4:
        url = 'https://ip.yunohost.org'
    elif protocol == 6:
        url = 'https://ip6.yunohost.org'
    else:
        raise ValueError("invalid protocol version")
    try:
        return urlopen(url).read().strip()
    except IOError:
        logger.debug('cannot retrieve public IPv%d' % protocol, exc_info=1)
        raise MoulinetteError(errno.ENETUNREACH,
                              m18n.n('no_internet_connection'))


def _get_maindomain():
    with open('/etc/yunohost/current_host', 'r') as f:
        maindomain = f.readline().rstrip()
    return maindomain


def _set_maindomain(domain):
    with open('/etc/yunohost/current_host', 'w') as f:
        f.write(domain)


def _normalize_domain_path(domain, path):

    # We want url to be of the format :
    #  some.domain.tld/foo

    # Remove http/https prefix if it's there
    if domain.startswith("https://"):
        domain = domain[len("https://"):]
    elif domain.startswith("http://"):
        domain = domain[len("http://"):]

    # Remove trailing slashes
    domain = domain.rstrip("/")
    path = "/" + path.strip("/")

    return domain, path


# DNS conf

def _build_dns_conf(domain, ttl=3600):

    # Init output / groups
    dnsconf = {}
    dnsconf["basic"] = []
    dnsconf["xmpp"] = []
    dnsconf["mail"] = []

    try:
        ipv4 = get_public_ip()
    except:
        ipv4 = None
    try:
        ipv6 = get_public_ip(6)
    except:
        ipv6 = None

    def _dns_record(name, ttl, type_, value):

        return { "name": name,
                 "ttl": ttl,
                 "type": type_,
                 "value": value
        }

    # Basic ipv4/ipv6 records
    if ipv4:
        dnsconf["basic"].append(_dns_record("@", ttl, "A", ipv4))
        dnsconf["basic"].append(_dns_record("*", ttl, "A", ipv4))

    if ipv6:
        dnsconf["basic"].append(_dns_record("@", ttl, "AAAA", ipv6))
        dnsconf["basic"].append(_dns_record("*", ttl, "AAAA", ipv6))

    # XMPP
    dnsconf["xmpp"].append(_dns_record("_xmpp-client._tcp", ttl, "SRV", "0 5 5222 %s." % domain))
    dnsconf["xmpp"].append(_dns_record("_xmpp-server._tcp", ttl, "SRV", "0 5 5269 %s." % domain))
    dnsconf["xmpp"].append(_dns_record("muc", ttl, "CNAME", "@"))
    dnsconf["xmpp"].append(_dns_record("pubsub", ttl, "CNAME", "@"))
    dnsconf["xmpp"].append(_dns_record("vjud", ttl, "CNAME", "@"))

    # Email
    dnsconf["mail"].append(_dns_record("@", ttl, "MX", "10 %s." % domain))

        # SPF record
    spf_record = '"v=spf1 a mx'
    if ipv4:
        spf_record += ' ip4:{ip4}'.format(ip4=ipv4)
    if ipv6:
        spf_record += ' ip6:{ip6}'.format(ip6=ipv6)
    spf_record += ' -all"'

    dnsconf["mail"].append(_dns_record("@", ttl, "TXT", spf_record))

        # DKIM/DMARC record
    dkim_host, dkim_publickey = _get_DKIM(domain)
    if dkim_host:
        dnsconf["mail"].append(_dns_record(dkim_host, ttl, "TXT", dkim_publickey))
        dnsconf["mail"].append(_dns_record("_dmarc", ttl, "TXT", '"v=DMARC1; p=none"'))

    return dnsconf


def _get_DKIM(domain):
    DKIM_file = '/etc/dkim/{domain}.mail.txt'.format(domain=domain)

    if not os.path.isfile(DKIM_file):
        return (None, None)

    with open(DKIM_file) as f:
        dkim_content = f.read()

    dkim = re.match((
        r'^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+[^"]*'
        '(?=.*(;[\s]*|")v=(?P<v>[^";]+))'
        '(?=.*(;[\s]*|")k=(?P<k>[^";]+))'
        '(?=.*(;[\s]*|")p=(?P<p>[^";]+))'), dkim_content, re.M | re.S
    )

    if dkim:
        return (dkim.group('host'),
                '"v={v}; k={k}; p={p}"'.format(
                v=dkim.group('v'), k=dkim.group('k'), p=dkim.group('p')))
    else:
        return (None, None)
