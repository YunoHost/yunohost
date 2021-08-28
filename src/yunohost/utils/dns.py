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
from publicsuffixlist import PublicSuffixList
from yunohost.utils.network import dig

YNH_DYNDNS_DOMAINS = ["nohost.me", "noho.st", "ynh.fr"]

def get_public_suffix(domain):
    """get_public_suffix("www.example.com") -> "example.com"

    Return the public suffix of a domain name based
    """
    # Load domain public suffixes
    psl = PublicSuffixList()

    public_suffix = psl.publicsuffix(domain)

    # FIXME: wtf is this supposed to do ? :|
    if public_suffix in YNH_DYNDNS_DOMAINS:
        domain_prefix = domain[0:-(1 + len(public_suffix))]
        public_suffix = domain_prefix.split(".")[-1] + "." + public_suffix

    return public_suffix

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
        # Otherwise, check if the parent of this parent is in the public suffix list
        if parent.split(".", 1)[-1] == get_public_suffix(parent):
            # Couldn't check if domain is dns zone,    # FIXME : why "couldn't" ...?
            # returning private suffix
            return parent

    # FIXME: returning None will probably trigger bugs when this happens, code expects a domain string
    return None
