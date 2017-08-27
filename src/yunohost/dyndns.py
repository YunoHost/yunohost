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
import time
import base64
import errno
import subprocess

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, write_to_file, rm
from moulinette.utils.network import download_json

from yunohost.domain import _get_maindomain, _build_dns_conf
from yunohost.utils.network import get_public_ip

logger = getActionLogger('yunohost.dyndns')

OLD_IPV4_FILE = '/etc/yunohost/dyndns/old_ip'
OLD_IPV6_FILE = '/etc/yunohost/dyndns/old_ipv6'
DYNDNS_ZONE = '/etc/yunohost/dyndns/zone'

RE_DYNDNS_PRIVATE_KEY_MD5 = re.compile(
    r'.*/K(?P<domain>[^\s\+]+)\.\+157.+\.private$'
)

RE_DYNDNS_PRIVATE_KEY_SHA512 = re.compile(
    r'.*/K(?P<domain>[^\s\+]+)\.\+165.+\.private$'
)


def _dyndns_provides(provider, domain):
    """
    Checks if a provider provide/manage a given domain.

    Keyword arguments:
        provider -- The url of the provider, e.g. "dyndns.yunohost.org"
        domain -- The full domain that you'd like.. e.g. "foo.nohost.me"

    Returns:
        True if the provider provide/manages the domain. False otherwise.
    """

    logger.debug("Checking if %s is managed by %s ..." % (domain, provider))

    try:
        # Dyndomains will be a list of domains supported by the provider
        # e.g. [ "nohost.me", "noho.st" ]
        dyndomains = download_json('https://%s/domains' % provider, timeout=30)
    except MoulinetteError as e:
        logger.error(str(e))
        raise MoulinetteError(errno.EIO,
                              m18n.n('dyndns_could_not_check_provide',
                                     domain=domain, provider=provider))

    # Extract 'dyndomain' from 'domain', e.g. 'nohost.me' from 'foo.nohost.me'
    dyndomain = '.'.join(domain.split('.')[1:])

    return dyndomain in dyndomains


def _dyndns_available(provider, domain):
    """
    Checks if a domain is available from a given provider.

    Keyword arguments:
        provider -- The url of the provider, e.g. "dyndns.yunohost.org"
        domain -- The full domain that you'd like.. e.g. "foo.nohost.me"

    Returns:
        True if the domain is avaible, False otherwise.
    """
    logger.debug("Checking if domain %s is available on %s ..."
                 % (domain, provider))

    try:
        r = download_json('https://%s/test/%s' % (provider, domain),
                          expected_status_code=None)
    except MoulinetteError as e:
        logger.error(str(e))
        raise MoulinetteError(errno.EIO,
                              m18n.n('dyndns_could_not_check_available',
                                     domain=domain, provider=provider))

    return r == u"Domain %s is available" % domain


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

    # Verify if domain is provided by subscribe_host
    if not _dyndns_provides(subscribe_host, domain):
        raise MoulinetteError(errno.ENOENT,
                              m18n.n('dyndns_domain_not_provided',
                                     domain=domain, provider=subscribe_host))

    # Verify if domain is available
    if not _dyndns_available(subscribe_host, domain):
        raise MoulinetteError(errno.ENOENT,
                              m18n.n('dyndns_unavailable', domain=domain))

    if key is None:
        if len(glob.glob('/etc/yunohost/dyndns/*.key')) == 0:
            if not os.path.exists('/etc/yunohost/dyndns'):
                os.makedirs('/etc/yunohost/dyndns')

            logger.info(m18n.n('dyndns_key_generating'))

            os.system('cd /etc/yunohost/dyndns && '
                      'dnssec-keygen -a hmac-sha512 -b 512 -r /dev/urandom -n USER %s' % domain)
            os.system('chmod 600 /etc/yunohost/dyndns/*.key /etc/yunohost/dyndns/*.private')

        key_file = glob.glob('/etc/yunohost/dyndns/*.key')[0]
        with open(key_file) as f:
            key = f.readline().strip().split(' ', 6)[-1]

    import requests # lazy loading this module for performance reasons
    # Send subscription
    try:
        r = requests.post('https://%s/key/%s?key_algo=hmac-sha512' % (subscribe_host, base64.b64encode(key)), data={'subdomain': domain}, timeout=30)
    except requests.ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))
    if r.status_code != 201:
        try:
            error = json.loads(r.text)['error']
        except:
            error = "Server error, code: %s. (Message: \"%s\")" % (r.status_code, r.text)
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
    # Get old ipv4/v6

    old_ipv4, old_ipv6 = (None, None)  # (default values)

    if os.path.isfile(OLD_IPV4_FILE):
        old_ipv4 = read_file(OLD_IPV4_FILE).rstrip()

    if os.path.isfile(OLD_IPV6_FILE):
        old_ipv6 = read_file(OLD_IPV6_FILE).rstrip()

    # Get current IPv4 and IPv6
    ipv4_ = get_public_ip()
    ipv6_ = get_public_ip(6)

    if ipv4 is None:
        ipv4 = ipv4_

    if ipv6 is None:
        ipv6 = ipv6_

    logger.debug("Old IPv4/v6 are (%s, %s)" % (old_ipv4, old_ipv6))
    logger.debug("Requested IPv4/v6 are (%s, %s)" % (ipv4, ipv6))

    # no need to update
    if old_ipv4 == ipv4 and old_ipv6 == ipv6:
        logger.info("No updated needed.")
        return
    else:
        logger.info("Updated needed, going on...")

    # If domain is not given, try to guess it from keys available...
    if domain is None:
        (domain, key) = _guess_current_dyndns_domain(dyn_host)
    # If key is not given, pick the first file we find with the domain given
    elif key is None:
        keys = glob.glob('/etc/yunohost/dyndns/K{0}.+*.private'.format(domain))

        if not keys:
            raise MoulinetteError(errno.EIO, m18n.n('dyndns_key_not_found'))

        key = keys[0]

    # This mean that hmac-md5 is used
    # (Re?)Trigger the migration to sha256 and return immediately.
    # The actual update will be done in next run.
    if "+157" in key:
        from yunohost.tools import _get_migration_by_name
        migration = _get_migration_by_name("migrate_to_tsig_sha256")
        try:
            migration.migrate(dyn_host, domain, key)
        except Exception as e:
            logger.error(m18n.n('migrations_migration_has_failed',
                                exception=e,
                                number=migration.number,
                                name=migration.name),
                                exc_info=1)
        return

    # Extract 'host', e.g. 'nohost.me' from 'foo.nohost.me'
    host = domain.split('.')[1:]
    host = '.'.join(host)

    logger.debug("Building zone update file ...")

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
            record["value"] = record["value"].replace(";","\;")

            action = "update add {name}.{domain}. {ttl} {type} {value}".format(domain=domain, **record)
            action = action.replace(" @.", " ")
            lines.append(action)

    lines += [
        'show',
        'send'
    ]

    # Write the actions to do to update to a file, to be able to pass it
    # to nsupdate as argument
    write_to_file(DYNDNS_ZONE, '\n'.join(lines))

    logger.info("Now pushing new conf to DynDNS host...")

    try:
        command = ["/usr/bin/nsupdate", "-k", key, DYNDNS_ZONE]
        subprocess.check_call(command)
    except subprocess.CalledProcessError:
        rm(OLD_IPV4_FILE, force=True)  # Remove file (ignore if non-existent)
        rm(OLD_IPV6_FILE, force=True)  # Remove file (ignore if non-existent)
        raise MoulinetteError(errno.EPERM,
                              m18n.n('dyndns_ip_update_failed'))

    logger.success(m18n.n('dyndns_ip_updated'))

    if ipv4 is not None:
        write_to_file(OLD_IPV4_FILE, ipv4)
    if ipv6 is not None:
        write_to_file(OLD_IPV6_FILE, ipv6)


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


def _guess_current_dyndns_domain(dyn_host):
    """
    This function tries to guess which domain should be updated by
    "dyndns_update()" because there's not proper management of the current
    dyndns domain :/ (and at the moment the code doesn't support having several
    dyndns domain, which is sort of a feature so that people don't abuse the
    dynette...)
    """

    # Retrieve the first registered domain
    for path in glob.iglob('/etc/yunohost/dyndns/K*.private'):
        match = RE_DYNDNS_PRIVATE_KEY_MD5.match(path)
        if not match:
            match = RE_DYNDNS_PRIVATE_KEY_SHA512.match(path)
            if not match:
                continue
        _domain = match.group('domain')

        # Verify if domain is registered (i.e., if it's available, skip
        # current domain beause that's not the one we want to update..)
        if _dyndns_available(dyn_host, _domain):
            continue
        else:
            return (_domain, path)

    raise MoulinetteError(errno.EINVAL,
                          m18n.n('dyndns_no_domain_registered'))
