# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2017 YUNOHOST.ORG

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
import logging
from urllib import urlopen

logger = logging.getLogger('yunohost.utils.network')

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
        return None
