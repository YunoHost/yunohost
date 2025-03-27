#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import base64
import glob
import hashlib
import json
import os
import subprocess
from logging import getLogger

from moulinette import Moulinette, m18n
from moulinette.core import MoulinetteError
from moulinette.utils.filesystem import chmod, chown, rm, write_to_file

from yunohost.domain import _get_maindomain
from yunohost.log import is_unit_operation
from yunohost.regenconf import regen_conf
from yunohost.utils.dns import dig, is_yunohost_dyndns_domain
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.network import get_public_ip

logger = getLogger("yunohost.dyndns")

DYNDNS_PROVIDER = "dyndns.yunohost.org"
DYNDNS_DNS_AUTH = ["ns0.yunohost.org", "ns1.yunohost.org"]
MAX_DYNDNS_DOMAINS = 1


def is_subscribing_allowed():
    """
    Check if the limit of subscribed DynDNS domains has been reached

    Returns:
        True if the limit is not reached, False otherwise
    """
    return len(dyndns_list()["domains"]) < MAX_DYNDNS_DOMAINS


def _dyndns_available(domain):
    """
    Checks if a domain is available on dyndns.yunohost.org

    Keyword arguments:
        domain -- The full domain that you'd like.. e.g. "foo.nohost.me"

    Returns:
        True if the domain is available, False otherwise.
    """
    import requests  # lazy loading this module for performance reasons

    logger.debug(f"Checking if domain {domain} is available on {DYNDNS_PROVIDER} ...")

    try:
        r = requests.get(f"https://{DYNDNS_PROVIDER}/test/{domain}", timeout=30)
    except MoulinetteError as e:
        logger.error(str(e))
        raise YunohostError(
            "dyndns_could_not_check_available", domain=domain, provider=DYNDNS_PROVIDER
        )

    if r.status_code == 200:
        return r.text.strip('"') == f"Domain {domain} is available"
    elif r.status_code == 409:
        return False
    elif r.status_code == 429:
        raise YunohostValidationError("dyndns_too_many_requests")
    else:
        raise YunohostError(
            "dyndns_could_not_check_available", domain=domain, provider=DYNDNS_PROVIDER
        )


@is_unit_operation(exclude=["recovery_password"])
def dyndns_subscribe(operation_logger, domain=None, recovery_password=None):
    """
    Subscribe to a DynDNS service

    Keyword argument:
        domain -- Full domain to subscribe with
        recovery_password -- Password that will be used to delete the domain
    """

    # Verify if domain is provided by subscribe_host
    if not is_yunohost_dyndns_domain(domain):
        raise YunohostValidationError(
            "dyndns_domain_not_provided", domain=domain, provider=DYNDNS_PROVIDER
        )

    # Check adding another dyndns domain is still allowed
    if not is_subscribing_allowed():
        raise YunohostValidationError("domain_dyndns_already_subscribed")

    # Verify if domain is available
    if not _dyndns_available(domain):
        # Prompt for a password if running in CLI and no password provided
        if not recovery_password and Moulinette.interface.type == "cli":
            logger.warning(m18n.n("ask_dyndns_recovery_password_explain_unavailable"))
            recovery_password = Moulinette.prompt(
                m18n.n("ask_dyndns_recovery_password"), is_password=True
            )

        if recovery_password:
            # Try to unsubscribe the domain so it can be subscribed again
            # If successful, it will be resubscribed with the same recovery password
            dyndns_unsubscribe(domain=domain, recovery_password=recovery_password)
        else:
            raise YunohostValidationError("dyndns_unavailable", domain=domain)

    # Prompt for a password if running in CLI and no password provided
    if not recovery_password and Moulinette.interface.type == "cli":
        logger.warning(m18n.n("ask_dyndns_recovery_password_explain"))
        recovery_password = Moulinette.prompt(
            m18n.n("ask_dyndns_recovery_password"), is_password=True, confirm=True
        )

    if not recovery_password:
        logger.warning(m18n.n("dyndns_no_recovery_password"))

    if recovery_password:
        from yunohost.utils.password import assert_password_is_strong_enough

        assert_password_is_strong_enough("admin", recovery_password)
        operation_logger.data_to_redact.append(recovery_password)

    if domain is None:
        domain = _get_maindomain()
        operation_logger.related_to.append(("domain", domain))

    operation_logger.start()

    # '165' is the convention identifier for hmac-sha512 algorithm
    # '1234' is idk? doesnt matter, but the old format contained a number here...
    key_file = f"/etc/yunohost/dyndns/K{domain}.+165+1234.key"

    if not os.path.exists("/etc/yunohost/dyndns"):
        os.makedirs("/etc/yunohost/dyndns")

    # Here, we emulate the behavior of the old 'dnssec-keygen' utility
    # which since bullseye was replaced by ddns-keygen which is now
    # in the bind9 package ... but installing bind9 will conflict with dnsmasq
    # and is just madness just to have access to a tsig keygen utility -.-

    # Use 512 // 8 = 64 bytes for hmac-sha512 (c.f. https://git.hactrn.net/sra/tsig-keygen/src/master/tsig-keygen.py)
    secret = base64.b64encode(os.urandom(512 // 8)).decode("ascii")

    # Idk why but the secret is split in two parts, with the first one
    # being 57-long char ... probably some DNS format
    secret = f"{secret[:56]} {secret[56:]}"

    key_content = f"{domain}. IN KEY 0 3 165 {secret}"
    write_to_file(key_file, key_content)

    chmod("/etc/yunohost/dyndns", 0o600, recursive=True)
    chown("/etc/yunohost/dyndns", "root", recursive=True)

    import requests  # lazy loading this module for performance reasons

    # Send subscription
    try:
        # Yeah the secret is already a base64-encoded but we double-bas64-encode it, whatever...
        b64encoded_key = base64.b64encode(secret.encode()).decode()
        data = {"subdomain": domain}
        if recovery_password:
            data["recovery_password"] = hashlib.sha256(
                (domain + ":" + recovery_password.strip()).encode("utf-8")
            ).hexdigest()
        r = requests.post(
            f"https://{DYNDNS_PROVIDER}/key/{b64encoded_key}?key_algo=hmac-sha512",
            data=data,
            timeout=30,
        )
    except Exception as e:
        rm(key_file, force=True)
        raise YunohostError("dyndns_subscribe_failed", error=str(e))
    if r.status_code != 201:
        rm(key_file, force=True)
        try:
            error = json.loads(r.text)["error"]
        except Exception:
            error = f'Server error, code: {r.status_code}. (Message: "{r.text}")'
        raise YunohostError("dyndns_subscribe_failed", error=error)

    # Yunohost regen conf will add the dyndns cron job if a key exists
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

    logger.success(m18n.n("dyndns_subscribed"))


@is_unit_operation(exclude=["recovery_password"])
def dyndns_unsubscribe(operation_logger, domain, recovery_password=None):
    """
    Unsubscribe from a DynDNS service

    Keyword argument:
        domain -- Full domain to unsubscribe with
        recovery_password -- Password that is used to delete the domain ( defined when subscribing )
    """

    import requests  # lazy loading this module for performance reasons

    # Unsubscribe the domain using the key if available
    keys = glob.glob(f"/etc/yunohost/dyndns/K{domain}.+*.key")
    if keys:
        key = keys[0]
        with open(key) as f:
            key = f.readline().strip().split(" ", 6)[-1]
        base64key = base64.b64encode(key.encode()).decode()
        credential = {"key": base64key}
    # Otherwise, ask for the recovery password
    else:
        if Moulinette.interface.type == "cli" and not recovery_password:
            logger.warning(
                m18n.n("ask_dyndns_recovery_password_explain_during_unsubscribe")
            )
            recovery_password = Moulinette.prompt(
                m18n.n("ask_dyndns_recovery_password"), is_password=True
            )

        if not recovery_password:
            logger.error(
                f"Cannot unsubscribe the domain {domain}: no credential provided"
            )
            return

        secret = str(domain) + ":" + str(recovery_password).strip()
        credential = {
            "recovery_password": hashlib.sha256(secret.encode("utf-8")).hexdigest()
        }

    operation_logger.start()

    # Send delete request
    try:
        r = requests.delete(
            f"https://{DYNDNS_PROVIDER}/domains/{domain}",
            data=credential,
            timeout=30,
        )
    except Exception as e:
        raise YunohostError("dyndns_unsubscribe_failed", error=str(e))

    if r.status_code == 200:  # Deletion was successful
        for key_file in glob.glob(f"/etc/yunohost/dyndns/K{domain}.+*.key"):
            rm(key_file, force=True)
        # Yunohost regen conf will add the dyndns cron job if a key exists
        # in /etc/yunohost/dyndns
        regen_conf(["yunohost"])
    elif r.status_code == 403:
        raise YunohostValidationError("dyndns_unsubscribe_denied")
    elif r.status_code == 409:
        raise YunohostValidationError("dyndns_unsubscribe_already_unsubscribed")
    elif r.status_code == 429:
        raise YunohostValidationError("dyndns_too_many_requests")
    else:
        raise YunohostError(
            "dyndns_unsubscribe_failed",
            error=f"The server returned code {r.status_code}",
        )

    logger.success(m18n.n("dyndns_unsubscribed"))


@is_unit_operation(flash=True)
def dyndns_set_recovery_password(domain, recovery_password):
    keys = glob.glob(f"/etc/yunohost/dyndns/K{domain}.+*.key")

    if not keys:
        raise YunohostValidationError("dyndns_key_not_found")

    from yunohost.utils.password import assert_password_is_strong_enough

    assert_password_is_strong_enough("admin", recovery_password)
    secret = str(domain) + ":" + str(recovery_password).strip()

    key = keys[0]
    with open(key) as f:
        key = f.readline().strip().split(" ", 6)[-1]
    base64key = base64.b64encode(key.encode()).decode()

    import requests  # lazy loading this module for performance reasons

    # Send delete request
    try:
        r = requests.put(
            f"https://{DYNDNS_PROVIDER}/domains/{domain}/recovery_password",
            data={
                "key": base64key,
                "recovery_password": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            },
            timeout=30,
        )
    except Exception as e:
        raise YunohostError("dyndns_set_recovery_password_failed", error=str(e))

    if r.status_code == 200:
        logger.success(m18n.n("dyndns_set_recovery_password_success"))
    elif r.status_code == 403:
        raise YunohostError("dyndns_set_recovery_password_denied")
    elif r.status_code == 404:
        raise YunohostError("dyndns_set_recovery_password_unknown_domain")
    elif r.status_code == 409:
        raise YunohostError("dyndns_set_recovery_password_invalid_password")
    else:
        raise YunohostError(
            "dyndns_set_recovery_password_failed",
            error=f"The server returned code {r.status_code}",
        )


def dyndns_list():
    """
    Returns all currently subscribed DynDNS domains ( deduced from the key files )
    """

    from yunohost.domain import domain_list

    domains = domain_list(exclude_subdomains=True)["domains"]
    dyndns_domains = [
        d
        for d in domains
        if is_yunohost_dyndns_domain(d)
        and glob.glob(f"/etc/yunohost/dyndns/K{d}.+*.key")
    ]

    return {"domains": dyndns_domains}


@is_unit_operation()
def dyndns_update(
    operation_logger,
    domain=None,
    force=False,
    dry_run=False,
):
    """
    Update IP on DynDNS platform

    Keyword argument:
        domain -- Full domain to update
    """

    import dns.query
    import dns.tsig
    import dns.tsigkeyring
    import dns.update
    from yunohost.dns import _build_dns_conf

    # If domain is not given, update all DynDNS domains
    if domain is None:
        dyndns_domains = dyndns_list()["domains"]

        if not dyndns_domains:
            raise YunohostValidationError("dyndns_no_domain_registered")

        for domain in dyndns_domains:
            dyndns_update(domain, force=force, dry_run=dry_run)

        return

    # If key is not given, pick the first file we find with the domain given
    keys = glob.glob(f"/etc/yunohost/dyndns/K{domain}.+*.key")

    if not keys:
        raise YunohostValidationError("dyndns_key_not_found")

    key = keys[0]

    # Get current IPv4 and IPv6
    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    if ipv4 is None and ipv6 is None:
        logger.debug(
            "No ipv4 nor ipv6 ?! Sounds like the server is not connected to the internet, or the ip.yunohost.org infrastructure is down somehow"
        )
        return

    # Extract 'host', e.g. 'nohost.me' from 'foo.nohost.me'
    zone = domain.split(".")[1:]
    zone = ".".join(zone)

    logger.debug("Building zone update ...")

    with open(key) as f:
        key = f.readline().strip().split(" ", 6)[-1]

    keyring = dns.tsigkeyring.from_text({f"{domain}.": key})
    # Python's dns.update is similar to the old nsupdate cli tool
    update = dns.update.Update(zone, keyring=keyring, keyalgorithm=dns.tsig.HMAC_SHA512)

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

        raise YunohostError(f"Failed to resolve {rdtype} for {domain}", raw_msg=True)

    old_ipv4 = resolve_domain(domain, "A")
    old_ipv6 = resolve_domain(domain, "AAAA")

    logger.debug(f"Old IPv4/v6 are ({old_ipv4}, {old_ipv6})")
    logger.debug(f"Requested IPv4/v6 are ({ipv4}, {ipv6})")

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
        if category not in ["basic", "mail", "extra"]:
            del dns_conf[category]

    # Delete the old records for all domain/subdomains

    # every dns_conf.values() is a list of :
    # [{"name": "...", "ttl": "...", "type": "...", "value": "..."}]
    for records in dns_conf.values():
        for record in records:
            name = (
                f"{record['name']}.{domain}." if record["name"] != "@" else f"{domain}."
            )
            update.delete(name)

    # Add the new records for all domain/subdomains

    for records in dns_conf.values():
        for record in records:
            # (For some reason) here we want the format with everytime the
            # entire, full domain shown explicitly, not just "muc" or "@", it
            # should be muc.the.domain.tld. or the.domain.tld
            if record["value"] == "@":
                record["value"] = domain
            record["value"] = record["value"].replace(";", r"\;")
            name = (
                f"{record['name']}.{domain}." if record["name"] != "@" else f"{domain}."
            )

            update.add(name, record["ttl"], record["type"], record["value"])

    logger.debug("Now pushing new conf to DynDNS host...")
    logger.debug(update)

    if not dry_run:
        try:
            r = dns.query.tcp(update, auth_resolvers[0])
        except Exception as e:
            logger.error(e)
            raise YunohostError("dyndns_ip_update_failed")

        if "rcode NOERROR" not in str(r):
            logger.error(str(r))
            raise YunohostError("dyndns_ip_update_failed")

        logger.success(m18n.n("dyndns_ip_updated"))
    else:
        print(
            "Warning: dry run, this is only the generated config, it won't be applied"
        )
