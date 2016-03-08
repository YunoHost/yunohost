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
import re
import logging
from collections import OrderedDict

import apt
from apt_pkg import version_compare

logger = logging.getLogger('yunohost.utils.packages')


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
    """The package is not found in the cache."""
    message_key = 'package_unknown'


class UninstalledPackage(PackageException):
    """The package is not installed."""
    message_key = 'package_not_installed'


class InvalidSpecifier(ValueError):
    """An invalid specifier was found."""


# Version specifier ----------------------------------------------------------
# The packaging package has been a nice inspiration for the following classes.
# See: https://github.com/pypa/packaging

class Specifier(object):
    """Unique package version specifier

    Restrict a package version according to the `spec`. It must be a string
    containing a relation from the list below followed by a version number
    value. The relations allowed are, as defined by the Debian Policy Manual:

      - `<<` for strictly lower
      - `<=` for lower or equal
      - `=` for exactly equal
      - `>=` for greater or equal
      - `>>` for strictly greater

    """
    _regex_str = (
        r"""
        (?P<relation>(<<|<=|=|>=|>>))
        \s*
        (?P<version>[^,;\s)]*)
        """
    )
    _regex = re.compile(
        r"^\s*" + _regex_str + r"\s*$", re.VERBOSE | re.IGNORECASE)

    _relations = {
        "<<": "lower_than",
        "<=": "lower_or_equal_than",
        "=": "equal",
        ">=": "greater_or_equal_than",
        ">>": "greater_than",
    }

    def __init__(self, spec):
        match = self._regex.search(spec)
        if not match:
            raise InvalidSpecifier("Invalid specifier: '{0}'".format(spec))

        self._spec = (
            match.group("relation").strip(),
            match.group("version").strip(),
        )

    def __repr__(self):
        return "<Specifier({1!r})>".format(str(self))

    def __str__(self):
        return "{0}{1}".format(*self._spec)

    def __hash__(self):
        return hash(self._spec)

    def __eq__(self, other):
        if isinstance(other, basestring):
            try:
                other = self.__class__(other)
            except InvalidSpecifier:
                return NotImplemented
        elif not isinstance(other, self.__class__):
            return NotImplemented

        return self._spec == other._spec

    def __ne__(self, other):
        if isinstance(other, basestring):
            try:
                other = self.__class__(other)
            except InvalidSpecifier:
                return NotImplemented
        elif not isinstance(other, self.__class__):
            return NotImplemented

        return self._spec != other._spec

    def _get_relation(self, op):
        return getattr(self, "_compare_{0}".format(self._relations[op]))

    def _compare_lower_than(self, version, spec):
        return version_compare(version, spec) < 0

    def _compare_lower_or_equal_than(self, version, spec):
        return version_compare(version, spec) <= 0

    def _compare_equal(self, version, spec):
        return version_compare(version, spec) == 0

    def _compare_greater_or_equal_than(self, version, spec):
        return version_compare(version, spec) >= 0

    def _compare_greater_than(self, version, spec):
        return version_compare(version, spec) > 0

    @property
    def relation(self):
        return self._spec[0]

    @property
    def version(self):
        return self._spec[1]

    def __contains__(self, item):
        return self.contains(item)

    def contains(self, item):
        return self._get_relation(self.relation)(item, self.version)


class SpecifierSet(object):
    """A set of package version specifiers

    Combine several Specifier separated by a comma. It allows to restrict
    more precisely a package version. Each package version specifier must be
    meet. Note than an empty set of specifiers will always be meet.

    """

    def __init__(self, specifiers):
        specifiers = [s.strip() for s in specifiers.split(",") if s.strip()]

        parsed = set()
        for specifier in specifiers:
            parsed.add(Specifier(specifier))

        self._specs = frozenset(parsed)

    def __repr__(self):
        return "<SpecifierSet({1!r})>".format(str(self))

    def __str__(self):
        return ",".join(sorted(str(s) for s in self._specs))

    def __hash__(self):
        return hash(self._specs)

    def __and__(self, other):
        if isinstance(other, basestring):
            other = SpecifierSet(other)
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        specifier = SpecifierSet()
        specifier._specs = frozenset(self._specs | other._specs)
        return specifiers

    def __eq__(self, other):
        if isinstance(other, basestring):
            other = SpecifierSet(other)
        elif isinstance(other, Specifier):
            other = SpecifierSet(str(other))
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        return self._specs == other._specs

    def __ne__(self, other):
        if isinstance(other, basestring):
            other = SpecifierSet(other)
        elif isinstance(other, Specifier):
            other = SpecifierSet(str(other))
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        return self._specs != other._specs

    def __len__(self):
        return len(self._specs)

    def __iter__(self):
        return iter(self._specs)

    def __contains__(self, item):
        return self.contains(item)

    def contains(self, item):
        return all(
            s.contains(item)
            for s in self._specs
        )


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

def meets_version_specifier(pkgname, specifier):
    """Check if a package installed version meets specifier"""
    spec = SpecifierSet(specifier)
    return get_installed_version(pkgname) in spec


# YunoHost related methods ---------------------------------------------------

def ynh_packages_version(*args, **kwargs):
    """Return the version of each YunoHost package"""
    return get_installed_version(
        'yunohost', 'yunohost-admin', 'moulinette', 'ssowat',
    )
