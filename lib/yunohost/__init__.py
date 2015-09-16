# -*- coding: utf-8 -*-

""" YunoHost scripts for the moulinette """

""" License

    Copyright (C) 2015 YUNOHOST.ORG

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see https://www.gnu.org/licenses

"""

## Packages versions

def get_version(package):
    from moulinette.utils import process
    return process.check_output(
        "dpkg-query -W -f='${{Version}}' {0}".format(package)
    ).strip()

def get_versions(*args, **kwargs):
    from collections import OrderedDict
    return OrderedDict([
        ('moulinette', get_version('moulinette')),
        ('moulinette-yunohost', get_version('moulinette-yunohost')),
        ('yunohost-admin', get_version('yunohost-admin')),
    ])
