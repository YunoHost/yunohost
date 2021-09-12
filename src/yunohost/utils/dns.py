# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2018 YUNOHOST.ORG

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
import dns.resolver
from moulinette.utils.filesystem import read_file

# Lazy dev caching to avoid re-reading the file multiple time when calling
# dig() often during same yunohost operation
external_resolvers_ = []


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


def get_dns_zone_from_domain(domain):
    # TODO Check if this function is YNH_DYNDNS_DOMAINS compatible
    """
    Get the DNS zone of a domain

    Keyword arguments:
        domain -- The domain name

    """

    # For foo.bar.baz.gni we want to scan all the parent domains
    # (including the domain itself)
    # foo.bar.baz.gni
    #     bar.baz.gni
    #         baz.gni
    #             gni
    parent_list = [domain.split(".", i)[-1]
                   for i, _ in enumerate(domain.split("."))]

    for parent in parent_list:

        # Check if there's a NS record for that domain
        answer = dig(parent, rdtype="NS", full_answers=True, resolvers="force_external")
        if answer[0] == "ok":
            # Domain is dns_zone
            return parent

    # FIXME: returning None will probably trigger bugs when this happens, code expects a domain string
    return None
