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
import re
import json
import yaml
import errno
import requests

from moulinette import m18n, msettings
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

import yunohost.certificate

from yunohost.service import service_regen_conf
from yunohost.utils.network import get_public_ip

logger = getActionLogger('yunohost.domain')


def domain_list(auth):
    """
    List domains

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for domain fetching
        limit -- Maximum number of domain fetched

    """
    result_list = []

    result = auth.search('ou=domains,dc=yunohost,dc=org', 'virtualdomain=*', ['virtualdomain'])

    for domain in result:
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
    from yunohost.app import app_ssowatconf

    try:
        auth.validate_uniqueness({'virtualdomain': domain})
    except MoulinetteError:
        raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))

    # DynDNS domain
    if dyndns:

        # Do not allow to subscribe to multiple dyndns domains...
        if os.path.exists('/etc/cron.d/yunohost-dyndns'):
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('domain_dyndns_already_subscribed'))

        from yunohost.dyndns import dyndns_subscribe, _dyndns_provides

        # Check that this domain can effectively be provided by
        # dyndns.yunohost.org. (i.e. is it a nohost.me / noho.st)
        if not _dyndns_provides("dyndns.yunohost.org", domain):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('domain_dyndns_root_unknown'))

        # Actually subscribe
        dyndns_subscribe(domain=domain)

    try:
        yunohost.certificate._certificate_install_selfsigned([domain], False)

        attr_dict = {
            'objectClass': ['mailDomain', 'top'],
            'virtualdomain': domain,
        }

        if not auth.add('virtualdomain=%s,ou=domains' % domain, attr_dict):
            raise MoulinetteError(errno.EIO, m18n.n('domain_creation_failed'))

        # Don't regen these conf if we're still in postinstall
        if os.path.exists('/etc/yunohost/installed'):
            service_regen_conf(names=['nginx', 'metronome', 'dnsmasq', 'rmilter'])
            app_ssowatconf(auth)

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
    from yunohost.app import app_ssowatconf

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
    app_ssowatconf(auth)

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

    result += "; Basic ipv4/ipv6 records"
    for record in dns_conf["basic"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    result += "\n\n"
    result += "; XMPP"
    for record in dns_conf["xmpp"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    result += "\n\n"
    result += "; Mail"
    for record in dns_conf["mail"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    is_cli = True if msettings.get('interface') == 'cli' else False
    if is_cli:
        logger.warning(m18n.n("domain_dns_conf_is_just_a_recommendation"))

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


def _build_dns_conf(domain, ttl=3600):
    """
    Internal function that will returns a data structure containing the needed
    information to generate/adapt the dns configuration

    The returned datastructure will have the following form:
    {
        "basic": [
            # if ipv4 available
            {"type": "A", "name": "@", "value": "123.123.123.123", "ttl": 3600},
            {"type": "A", "name": "*", "value": "123.123.123.123", "ttl": 3600},
            # if ipv6 available
            {"type": "AAAA", "name": "@", "value": "valid-ipv6", "ttl": 3600},
            {"type": "AAAA", "name": "*", "value": "valid-ipv6", "ttl": 3600},
        ],
        "xmpp": [
            {"type": "SRV", "name": "_xmpp-client._tcp", "value": "0 5 5222 domain.tld.", "ttl": 3600},
            {"type": "SRV", "name": "_xmpp-server._tcp", "value": "0 5 5269 domain.tld.", "ttl": 3600},
            {"type": "CNAME", "name": "muc", "value": "@", "ttl": 3600},
            {"type": "CNAME", "name": "pubsub", "value": "@", "ttl": 3600},
            {"type": "CNAME", "name": "vjud", "value": "@", "ttl": 3600}
        ],
        "mail": [
            {"type": "MX", "name": "@", "value": "10 domain.tld.", "ttl": 3600},
            {"type": "TXT", "name": "@", "value": "\"v=spf1 a mx ip4:123.123.123.123 ipv6:valid-ipv6 -all\"", "ttl": 3600 },
            {"type": "TXT", "name": "mail._domainkey", "value": "\"v=DKIM1; k=rsa; p=some-super-long-key\"", "ttl": 3600},
            {"type": "TXT", "name": "_dmarc", "value": "\"v=DMARC1; p=none\"", "ttl": 3600}
        ],
    }
    """

    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    basic = []

    # Basic ipv4/ipv6 records
    if ipv4:
        basic += [
            ["@", ttl, "A", ipv4],
            ["*", ttl, "A", ipv4],
        ]

    if ipv6:
        basic += [
            ["@", ttl, "AAAA", ipv6],
            ["*", ttl, "AAAA", ipv6],
        ]

    # XMPP
    xmpp = [
        ["_xmpp-client._tcp", ttl, "SRV", "0 5 5222 %s." % domain],
        ["_xmpp-server._tcp", ttl, "SRV", "0 5 5269 %s." % domain],
        ["muc", ttl, "CNAME", "@"],
        ["pubsub", ttl, "CNAME", "@"],
        ["vjud", ttl, "CNAME", "@"],
    ]

    # SPF record
    spf_record = '"v=spf1 a mx'
    if ipv4:
        spf_record += ' ip4:{ip4}'.format(ip4=ipv4)
    if ipv6:
        spf_record += ' ip6:{ip6}'.format(ip6=ipv6)
    spf_record += ' -all"'

    # Email
    mail = [
        ["@", ttl, "MX", "10 %s." % domain],
        ["@", ttl, "TXT", spf_record],
    ]

    # DKIM/DMARC record
    dkim_host, dkim_publickey = _get_DKIM(domain)

    if dkim_host:
        mail += [
            [dkim_host, ttl, "TXT", dkim_publickey],
            ["_dmarc", ttl, "TXT", '"v=DMARC1; p=none"'],
        ]

    return {
        "basic": [{"name": name, "ttl": ttl, "type": type_, "value": value} for name, ttl, type_, value in basic],
        "xmpp": [{"name": name, "ttl": ttl, "type": type_, "value": value} for name, ttl, type_, value in xmpp],
        "mail": [{"name": name, "ttl": ttl, "type": type_, "value": value} for name, ttl, type_, value in mail],
    }


def _get_DKIM(domain):
    DKIM_file = '/etc/dkim/{domain}.mail.txt'.format(domain=domain)

    if not os.path.isfile(DKIM_file):
        return (None, None)

    with open(DKIM_file) as f:
        dkim_content = f.read()

    # Gotta manage two formats :
    #
    # Legacy
    # -----
    #
    # mail._domainkey IN      TXT     ( "v=DKIM1; k=rsa; "
    #           "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCYhnvJ+JgF9tfVbUVy6L20b2IVHygZD1GjY6k+/je+3y3C9BzPAlEitL4s2vkQpPfAevw8P6uE7s1usCa/tnTzmq4r6Q/9YRf+Wx5e79XuIY5/ZKJw1YKkDWRlGzpenu8i+6kssaPqPmtmQaYuoOwTlcpXcN9qKNIodDsaWOxBwIDAQAB" )
    #
    # New
    # ------
    # mail._domainkey IN  TXT ( "v=DKIM1; h=sha256; k=rsa; "
    #             "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWIw/R6QIL7nbJr+yX4cS8TfFx1POMvnzbsDWAFG5U4aPqLwCkJNqrum1hG9rzCb43pGkNy5JNAh0tTZpxq+S1kBAu+DAOSHgbYVg2Tr6zTm9YNL1n/thjKB9U/dyaCzWnxlMFJYkXNlDICtSSf47ZWqcrurkAOfmtmGYQivoz8ipXMvou4t22W9DbZR+XpPbtc3RkCKK32E8O"
    #                 "02OT9PHbsBCOakb+W1vkocVZpZo78eu5Q2phOntE9Vl2MXtd54+TEdWv6zPcGrHrF9aazEuGcNQwSUgJaHlEceT2u8X+sliwIr0on3Om2NMaTDkPgZzg2poQIDPkyxDQire7jGBwIDAQAB"
    #                 )

    is_legacy_format = " h=sha256; " not in dkim_content

    # Legacy DKIM format
    if is_legacy_format:
        dkim = re.match((
            r'^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+'
             '[^"]*"v=(?P<v>[^";]+);'
             '[\s"]*k=(?P<k>[^";]+);'
             '[\s"]*p=(?P<p>[^";]+)'), dkim_content, re.M | re.S
        )
    else:
        dkim = re.match((
            r'^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+'
             '[^"]*"v=(?P<v>[^";]+);'
             '[\s"]*h=(?P<h>[^";]+);'
             '[\s"]*k=(?P<k>[^";]+);'
             '[\s"]*p=(?P<p>[^";]+)'
             '[\s"]*(?P<p2>[^";]+)'), dkim_content, re.M | re.S
        )

    if not dkim:
        return (None, None)

    if is_legacy_format:
        return (
            dkim.group('host'),
            '"v={v}; k={k}; p={p}"'.format(v=dkim.group('v'),
                                           k=dkim.group('k'),
                                           p=dkim.group('p'))
        )
    else:
        return (
            dkim.group('host'),
            '"v={v}; h={h}; k={k}; p={p}"'.format(v=dkim.group('v'),
                                                  h=dkim.group('h'),
                                                  k=dkim.group('k'),
                                                  p=dkim.group('p')
                                                   +dkim.group('p2'))
        )
