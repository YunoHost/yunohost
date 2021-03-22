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
from publicsuffix import PublicSuffixList

YNH_DYNDNS_DOMAINS = ["nohost.me", "noho.st", "ynh.fr"]

def get_public_suffix(domain):
    """get_public_suffix("www.example.com") -> "example.com"

    Return the public suffix of a domain name based 
    """
    # Load domain public suffixes
    psl = PublicSuffixList()

    public_suffix = psl.get_public_suffix(domain)
    if public_suffix in YNH_DYNDNS_DOMAINS:
        domain_prefix = domain_name[0:-(1 + len(public_suffix))]
        public_suffix =  domain_prefix.plit(".")[-1] + "." + public_suffix

    return public_suffix