# -*- coding: utf-8 -*-

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
    along with this program; if not, see http://www.gnu.org/licenses

"""
from collections import OrderedDict

import apt
from apt_pkg import version_compare


# Exceptions -----------------------------------------------------------------

class PackageException(Exception):
    """Base exception related to a package

    Represent an exception related to the package named `pkgname`. If no
    `message` is provided, it will first try to use the translation key
    `message_key` if defined by the derived class. Otherwise, a standard
    message will be used.

    """
    message_key = 'package_unexpected_error'

    def __init__(self, pkgname, message=None):
        super(PackageException, self).__init__(
            message or m18n.n(self.message_key, pkgname=pkgname))
        self.pkgname = pkgname


class UnknownPackage(PackageException):
    message_key = 'package_unknown'


class UninstalledPackage(PackageException):
    message_key = 'package_not_installed'


# Packages and cache helpers -------------------------------------------------

def get_installed_version(*pkgnames, **kwargs):
    """Get the installed version of package(s)

    Retrieve one or more packages named `pkgnames` and return their installed
    version as a dict or as a string if only one is requested. If `strict` is
    `True`, an exception will be raised if a package is unknown or not
    installed.

    """
    cache = apt.Cache()
    strict = kwargs.get('strict', False)
    versions = OrderedDict()
    for pkgname in pkgnames:
        try:
            pkg = cache[pkgname]
        except KeyError:
            if strict:
                raise UnknownPackage(pkgname)
            logger.warning(m18n.n('package_unknown', pkgname=pkgname))
        try:
            version = pkg.installed.version
        except AttributeError:
            if strict:
                raise UninstalledPackage(pkgname)
            version = None
        versions[pkgname] = version
    if len(pkgnames) == 1:
        return versions[pkgnames[0]]
    return versions

def has_min_version(min_version, package='yunohost'):
    """Check if a package has a minimum installed version"""
    version = get_installed_version(package)
    if version_compare(version, min_version) > 0:
        return True
    return False


# YunoHost related methods ---------------------------------------------------

def ynh_packages_version(*args, **kwargs):
    """Return the version of each YunoHost package"""
    return get_installed_version(
        'yunohost', 'yunohost-admin', 'moulinette', 'ssowat',
    )
