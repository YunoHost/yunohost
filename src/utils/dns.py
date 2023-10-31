#
# Copyright (c) 2023 YunoHost Contributors
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
import dns.resolver
from typing import List

from moulinette.utils.filesystem import read_file

SPECIAL_USE_TLDS = ["home.arpa", "local", "localhost", "onion", "test"]

YNH_DYNDNS_DOMAINS = ["nohost.me", "noho.st", "ynh.fr"]

# Lazy dev caching to avoid re-reading the file multiple time when calling
# dig() often during same yunohost operation
external_resolvers_: List[str] = []


def is_yunohost_dyndns_domain(domain):
    return any(
        domain.endswith(f".{dyndns_domain}") for dyndns_domain in YNH_DYNDNS_DOMAINS
    )


def is_special_use_tld(domain):
    return any(domain.endswith(f".{tld}") for tld in SPECIAL_USE_TLDS)


def external_resolvers():
    global external_resolvers_

    if not external_resolvers_:
        resolv_dnsmasq_conf = read_file("/etc/resolv.dnsmasq.conf").split("\n")
        external_resolvers_ = [
            r.split(" ")[1] for r in resolv_dnsmasq_conf if r.startswith("nameserver")
        ]
        # We keep only ipv4 resolvers, otherwise on IPv4-only instances, IPv6
        # will be tried anyway resulting in super-slow dig requests that'll wait
        # until timeout...
        external_resolvers_ = [r for r in external_resolvers_ if ":" not in r]

    return external_resolvers_


def dig(
    qname, rdtype="A", timeout=5, resolvers="local", edns_size=1500, full_answers=False
):
    """
    Do a quick DNS request and avoid the "search" trap inside /etc/resolv.conf
    """

    # It's very important to do the request with a qname ended by .
    # If we don't and the domain fail, dns resolver try a second request
    # by concatenate the qname with the end of the "hostname"
    if not qname.endswith("."):
        qname += "."

    if resolvers == "local":
        resolvers = ["127.0.0.1"]
    elif resolvers == "force_external":
        resolvers = external_resolvers()
    else:
        assert isinstance(resolvers, list)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.use_edns(0, 0, edns_size)
    resolver.nameservers = resolvers
    # resolver.timeout is used to trigger the next DNS query on resolvers list.
    # In python-dns 1.16, this value is set to 2.0. However, this means that if
    # the 3 first dns resolvers in list are down, we wait 6 seconds before to
    # run the DNS query to a DNS resolvers up...
    # In diagnosis dnsrecords, with 10 domains this means at least 12min, too long.
    resolver.timeout = 1.0
    # resolver.lifetime is the timeout for resolver.query()
    # By default set it to 5 seconds to allow 4 resolvers to be unreachable.
    resolver.lifetime = timeout
    try:
        answers = resolver.query(qname, rdtype)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.NoAnswer,
        dns.exception.Timeout,
    ) as e:
        return ("nok", (e.__class__.__name__, e))

    if not full_answers:
        answers = [answer.to_text() for answer in answers]

    return ("ok", answers)
