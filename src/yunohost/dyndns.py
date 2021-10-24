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
import subprocess

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import write_to_file, read_file, rm, chown, chmod
from moulinette.utils.network import download_json

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.domain import _get_maindomain
from yunohost.utils.network import get_public_ip
from yunohost.utils.dns import dig, is_yunohost_dyndns_domain
from yunohost.log import is_unit_operation
from yunohost.regenconf import regen_conf

logger = getActionLogger("yunohost.dyndns")

DYNDNS_ZONE = "/etc/yunohost/dyndns/zone"

RE_DYNDNS_PRIVATE_KEY_MD5 = re.compile(r".*/K(?P<domain>[^\s\+]+)\.\+157.+\.private$")

RE_DYNDNS_PRIVATE_KEY_SHA512 = re.compile(
    r".*/K(?P<domain>[^\s\+]+)\.\+165.+\.private$"
)

DYNDNS_PROVIDER = "dyndns.yunohost.org"
DYNDNS_DNS_AUTH = ["ns0.yunohost.org", "ns1.yunohost.org"]


def _dyndns_available(domain):
    """
    Checks if a domain is available on dyndns.yunohost.org

    Keyword arguments:
        domain -- The full domain that you'd like.. e.g. "foo.nohost.me"

    Returns:
        True if the domain is available, False otherwise.
    """
    logger.debug(f"Checking if domain {domain} is available on {DYNDNS_PROVIDER} ...")

    try:
        r = download_json(f"https://{DYNDNS_PROVIDER}/test/{domain}", expected_status_code=None)
    except MoulinetteError as e:
        logger.error(str(e))
        raise YunohostError(
            "dyndns_could_not_check_available", domain=domain, provider=DYNDNS_PROVIDER
        )

    return r == f"Domain {domain} is available"


@is_unit_operation()
def dyndns_subscribe(
    operation_logger, domain=None, key=None
):
    """
    Subscribe to a DynDNS service

    Keyword argument:
        domain -- Full domain to subscribe with
        key -- Public DNS key
    """

    if _guess_current_dyndns_domain() != (None, None):
        raise YunohostValidationError("domain_dyndns_already_subscribed")

    if domain is None:
        domain = _get_maindomain()
        operation_logger.related_to.append(("domain", domain))

    # Verify if domain is provided by subscribe_host
    if not is_yunohost_dyndns_domain(domain):
        raise YunohostValidationError(
            "dyndns_domain_not_provided", domain=domain, provider=DYNDNS_PROVIDER
        )

    # Verify if domain is available
    if not _dyndns_available(domain):
        raise YunohostValidationError("dyndns_unavailable", domain=domain)

    operation_logger.start()

    if key is None:
        if len(glob.glob("/etc/yunohost/dyndns/*.key")) == 0:
            if not os.path.exists("/etc/yunohost/dyndns"):
                os.makedirs("/etc/yunohost/dyndns")

            logger.debug(m18n.n("dyndns_key_generating"))

            os.system(
                "cd /etc/yunohost/dyndns && "
                f"dnssec-keygen -a hmac-sha512 -b 512 -r /dev/urandom -n USER {domain}"
            )

            chmod("/etc/yunohost/dyndns", 0o600, recursive=True)
            chown("/etc/yunohost/dyndns", "root", recursive=True)

        private_file = glob.glob("/etc/yunohost/dyndns/*%s*.private" % domain)[0]
        key_file = glob.glob("/etc/yunohost/dyndns/*%s*.key" % domain)[0]
        with open(key_file) as f:
            key = f.readline().strip().split(" ", 6)[-1]

    import requests  # lazy loading this module for performance reasons

    # Send subscription
    try:
        b64encoded_key = base64.b64encode(key.encode()).decode()
        r = requests.post(
            f"https://{DYNDNS_PROVIDER}/key/{b64encoded_key}?key_algo=hmac-sha512",
            data={"subdomain": domain},
            timeout=30,
        )
    except Exception as e:
        rm(private_file, force=True)
        rm(key_file, force=True)
        raise YunohostError("dyndns_registration_failed", error=str(e))
    if r.status_code != 201:
        rm(private_file, force=True)
        rm(key_file, force=True)
        try:
            error = json.loads(r.text)["error"]
        except Exception:
            error = 'Server error, code: %s. (Message: "%s")' % (r.status_code, r.text)
        raise YunohostError("dyndns_registration_failed", error=error)

    # Yunohost regen conf will add the dyndns cron job if a private key exists
    # in /etc/yunohost/dyndns
    regen_conf(["yunohost"])

    # Add some dyndns update in 2 and 4 minutes from now such that user should
    # not have to wait 10ish minutes for the conf to propagate
    cmd = (
        "at -M now + {t} >/dev/null 2>&1 <<< \"/bin/bash -c 'yunohost dyndns update'\""
    )
    # For some reason subprocess doesn't like the redirections so we have to use bash -c explicity...
    subprocess.check_call(["bash", "-c", cmd.format(t="2 min")])
    subprocess.check_call(["bash", "-c", cmd.format(t="4 min")])

    logger.success(m18n.n("dyndns_registered"))


@is_unit_operation()
def dyndns_update(
    operation_logger,
    domain=None,
    key=None,
    ipv4=None,
    ipv6=None,
    force=False,
    dry_run=False,
):
    """
    Update IP on DynDNS platform

    Keyword argument:
        domain -- Full domain to update
        key -- Public DNS key
        ipv4 -- IP address to send
        ipv6 -- IPv6 address to send

    """

    from yunohost.dns import _build_dns_conf

    # If domain is not given, try to guess it from keys available...
    if domain is None:
        (domain, key) = _guess_current_dyndns_domain()

    if domain is None:
        raise YunohostValidationError("dyndns_no_domain_registered")

    # If key is not given, pick the first file we find with the domain given
    else:
        if key is None:
            keys = glob.glob("/etc/yunohost/dyndns/K{0}.+*.private".format(domain))

            if not keys:
                raise YunohostValidationError("dyndns_key_not_found")

            key = keys[0]

    # Extract 'host', e.g. 'nohost.me' from 'foo.nohost.me'
    host = domain.split(".")[1:]
    host = ".".join(host)

    logger.debug("Building zone update file ...")

    lines = [
        f"server {DYNDNS_PROVIDER}",
        f"zone {host}",
    ]

    auth_resolvers = []

    for dns_auth in DYNDNS_DNS_AUTH:
        for type_ in ["A", "AAAA"]:

            ok, result = dig(dns_auth, type_)
            if ok == "ok" and len(result) and result[0]:
                auth_resolvers.append(result[0])

    if not auth_resolvers:
        raise YunohostError(
            f"Failed to resolve IPv4/IPv6 for {DYNDNS_DNS_AUTH} ?", raw_msg=True
        )

    def resolve_domain(domain, rdtype):

        ok, result = dig(domain, rdtype, resolvers=auth_resolvers)
        if ok == "ok":
            return result[0] if len(result) else None
        elif result[0] == "Timeout":
            logger.debug(
                f"Timed-out while trying to resolve {rdtype} record for {domain}"
            )
        else:
            return None

        logger.debug("Falling back to external resolvers")
        ok, result = dig(domain, rdtype, resolvers="force_external")
        if ok == "ok":
            return result[0] if len(result) else None
        elif result[0] == "Timeout":
            logger.debug(
                "Timed-out while trying to resolve %s record for %s using external resolvers : %s"
                % (rdtype, domain, result)
            )
        else:
            return None

        raise YunohostError(
            "Failed to resolve %s for %s" % (rdtype, domain), raw_msg=True
        )

    old_ipv4 = resolve_domain(domain, "A")
    old_ipv6 = resolve_domain(domain, "AAAA")

    # Get current IPv4 and IPv6
    ipv4_ = get_public_ip()
    ipv6_ = get_public_ip(6)

    if ipv4 is None:
        ipv4 = ipv4_

    if ipv6 is None:
        ipv6 = ipv6_

    logger.debug("Old IPv4/v6 are (%s, %s)" % (old_ipv4, old_ipv6))
    logger.debug("Requested IPv4/v6 are (%s, %s)" % (ipv4, ipv6))

    if ipv4 is None and ipv6 is None:
        logger.debug(
            "No ipv4 nor ipv6 ?! Sounds like the server is not connected to the internet, or the ip.yunohost.org infrastructure is down somehow"
        )
        return

    # no need to update
    if (not force and not dry_run) and (old_ipv4 == ipv4 and old_ipv6 == ipv6):
        logger.info("No updated needed.")
        return
    else:
        operation_logger.related_to.append(("domain", domain))
        operation_logger.start()
        logger.info("Updated needed, going on...")

    dns_conf = _build_dns_conf(domain)

    # Delete custom DNS records, we don't support them (have to explicitly
    # authorize them on dynette)
    for category in dns_conf.keys():
        if category not in ["basic", "mail", "xmpp", "extra"]:
            del dns_conf[category]

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
            record["value"] = record["value"].replace(";", r"\;")

            action = "update add {name}.{domain}. {ttl} {type} {value}".format(
                domain=domain, **record
            )
            action = action.replace(" @.", " ")
            lines.append(action)

    lines += ["show", "send"]

    # Write the actions to do to update to a file, to be able to pass it
    # to nsupdate as argument
    write_to_file(DYNDNS_ZONE, "\n".join(lines))

    logger.debug("Now pushing new conf to DynDNS host...")

    if not dry_run:
        try:
            command = ["/usr/bin/nsupdate", "-k", key, DYNDNS_ZONE]
            subprocess.check_call(command)
        except subprocess.CalledProcessError:
            raise YunohostError("dyndns_ip_update_failed")

        logger.success(m18n.n("dyndns_ip_updated"))
    else:
        print(read_file(DYNDNS_ZONE))
        print("")
        print(
            "Warning: dry run, this is only the generated config, it won't be applied"
        )


# Legacy
def dyndns_installcron():
    logger.warning(
        "This command is deprecated. The dyndns cron job should automatically be added/removed by the regenconf depending if there's a private key in /etc/yunohost/dyndns. You can run the regenconf yourself with 'yunohost tools regen-conf yunohost'."
    )


# Legacy
def dyndns_removecron():
    logger.warning(
        "This command is deprecated. The dyndns cron job should automatically be added/removed by the regenconf depending if there's a private key in /etc/yunohost/dyndns. You can run the regenconf yourself with 'yunohost tools regen-conf yunohost'."
    )


def _guess_current_dyndns_domain():
    """
    This function tries to guess which domain should be updated by
    "dyndns_update()" because there's not proper management of the current
    dyndns domain :/ (and at the moment the code doesn't support having several
    dyndns domain, which is sort of a feature so that people don't abuse the
    dynette...)
    """

    # Retrieve the first registered domain
    paths = list(glob.iglob("/etc/yunohost/dyndns/K*.private"))
    for path in paths:
        match = RE_DYNDNS_PRIVATE_KEY_MD5.match(path)
        if not match:
            match = RE_DYNDNS_PRIVATE_KEY_SHA512.match(path)
            if not match:
                continue
        _domain = match.group("domain")

        # Verify if domain is registered (i.e., if it's available, skip
        # current domain beause that's not the one we want to update..)
        # If there's only 1 such key found, then avoid doing the request
        # for nothing (that's very probably the one we want to find ...)
        if len(paths) > 1 and _dyndns_available(_domain):
            continue
        else:
            return (_domain, path)

    return (None, None)
