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
import os
import logging
from collections import OrderedDict

import apt
from apt_pkg import version_compare

from moulinette import m18n

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
        if isinstance(spec, basestring):
            match = self._regex.search(spec)
            if not match:
                raise InvalidSpecifier("Invalid specifier: '{0}'".format(spec))

            self._spec = (
                match.group("relation").strip(),
                match.group("version").strip(),
            )
        elif isinstance(spec, self.__class__):
            self._spec = spec._spec
        else:
            return NotImplemented

    def __repr__(self):
        return "<Specifier({0!r})>".format(str(self))

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

    def __and__(self, other):
        return self.intersection(other)

    def __or__(self, other):
        return self.union(other)

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

    def intersection(self, other):
        """Make the intersection of two specifiers

        Return a new `SpecifierSet` with version specifier(s) common to the
        specifier and the other.

        Example:
            >>> Specifier('>= 2.2') & '>> 2.2.1' == '>> 2.2.1'
            >>> Specifier('>= 2.2') & '<< 2.3' == '>= 2.2, << 2.3'

        """
        if isinstance(other, basestring):
            try:
                other = self.__class__(other)
            except InvalidSpecifier:
                return NotImplemented
        elif not isinstance(other, self.__class__):
            return NotImplemented

        # store spec parts for easy access
        rel1, v1 = self.relation, self.version
        rel2, v2 = other.relation, other.version
        result = []

        if other == self:
            result = [other]
        elif rel1 == '=':
            result = [self] if v1 in other else None
        elif rel2 == '=':
            result = [other] if v2 in self else None
        elif v1 == v2:
            result = [other if rel1[1] == '=' else self]
        elif v2 in self or v1 in other:
            is_self_greater = version_compare(v1, v2) > 0
            if rel1[0] == rel2[0]:
                if rel1[0] == '>':
                    result = [self if is_self_greater else other]
                else:
                    result = [other if is_self_greater else self]
            else:
                result = [self, other]
        return SpecifierSet(result if result is not None else '')

    def union(self, other):
        """Make the union of two version specifiers

        Return a new `SpecifierSet` with version specifiers from the
        specifier and the other.

        Example:
            >>> Specifier('>= 2.2') | '<< 2.3' == '>= 2.2, << 2.3'

        """
        if isinstance(other, basestring):
            try:
                other = self.__class__(other)
            except InvalidSpecifier:
                return NotImplemented
        elif not isinstance(other, self.__class__):
            return NotImplemented

        return SpecifierSet([self, other])

    def contains(self, item):
        """Check if the specifier contains an other

        Return whether the item is contained in the version specifier.

        Example:
            >>> '2.2.1' in Specifier('<< 2.3')
            >>> '2.4' not in Specifier('<< 2.3')

        """
        return self._get_relation(self.relation)(item, self.version)


class SpecifierSet(object):

    """A set of package version specifiers

    Combine several Specifier separated by a comma. It allows to restrict
    more precisely a package version. Each package version specifier must be
    meet. Note than an empty set of specifiers will always be meet.

    """

    def __init__(self, specifiers):
        if isinstance(specifiers, basestring):
            specifiers = [s.strip() for s in specifiers.split(",")
                          if s.strip()]

        parsed = set()
        for specifier in specifiers:
            parsed.add(Specifier(specifier))

        self._specs = frozenset(parsed)

    def __repr__(self):
        return "<SpecifierSet({0!r})>".format(str(self))

    def __str__(self):
        return ",".join(sorted(str(s) for s in self._specs))

    def __hash__(self):
        return hash(self._specs)

    def __and__(self, other):
        return self.intersection(other)

    def __or__(self, other):
        return self.union(other)

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

    def intersection(self, other):
        """Make the intersection of two specifiers sets

        Return a new `SpecifierSet` with version specifier(s) common to the
        set and the other.

        Example:
            >>> SpecifierSet('>= 2.2') & '>> 2.2.1' == '>> 2.2.1'
            >>> SpecifierSet('>= 2.2, << 2.4') & '<< 2.3' == '>= 2.2, << 2.3'
            >>> SpecifierSet('>= 2.2, << 2.3') & '>= 2.4' == ''

        """
        if isinstance(other, basestring):
            other = SpecifierSet(other)
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        specifiers = set(self._specs | other._specs)
        intersection = [specifiers.pop()] if specifiers else []

        for specifier in specifiers:
            parsed = set()
            for spec in intersection:
                inter = spec & specifier
                if not inter:
                    parsed.clear()
                    break
                # TODO: validate with other specs in parsed
                parsed.update(inter._specs)
            intersection = parsed
            if not intersection:
                break
        return SpecifierSet(intersection)

    def union(self, other):
        """Make the union of two specifiers sets

        Return a new `SpecifierSet` with version specifiers from the set
        and the other.

        Example:
            >>> SpecifierSet('>= 2.2') | '<< 2.3' == '>= 2.2, << 2.3'

        """
        if isinstance(other, basestring):
            other = SpecifierSet(other)
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        specifiers = SpecifierSet([])
        specifiers._specs = frozenset(self._specs | other._specs)
        return specifiers

    def contains(self, item):
        """Check if the set contains a version specifier

        Return whether the item is contained in all version specifiers.

        Example:
            >>> '2.2.1' in SpecifierSet('>= 2.2, << 2.3')
            >>> '2.4' not in SpecifierSet('>= 2.2, << 2.3')

        """
        return all(
            s.contains(item)
            for s in self._specs
        )


# Packages and cache helpers -------------------------------------------------

def get_installed_version(*pkgnames, **kwargs):
    """Get the installed version of package(s)

    Retrieve one or more packages named `pkgnames` and return their installed
    version as a dict or as a string if only one is requested and `as_dict` is
    `False`. If `strict` is `True`, an exception will be raised if a package
    is unknown or not installed.

    """
    versions = OrderedDict()
    cache = apt.Cache()

    # Retrieve options
    as_dict = kwargs.get('as_dict', False)
    strict = kwargs.get('strict', False)
    with_repo = kwargs.get('with_repo', False)

    for pkgname in pkgnames:
        try:
            pkg = cache[pkgname]
        except KeyError:
            if strict:
                raise UnknownPackage(pkgname)
            logger.warning(m18n.n('package_unknown', pkgname=pkgname))
            continue

        try:
            version = pkg.installed.version
        except AttributeError:
            if strict:
                raise UninstalledPackage(pkgname)
            version = None

        try:
            # stable, testing, unstable
            repo = pkg.installed.origins[0].component
        except AttributeError:
            if strict:
                raise UninstalledPackage(pkgname)
            repo = ""

        if with_repo:
            versions[pkgname] = {
                "version": version,
                # when we don't have component it's because it's from a local
                # install or from an image (like in vagrant)
                "repo": repo if repo else "local",
            }
        else:
            versions[pkgname] = version

    if len(pkgnames) == 1 and not as_dict:
        return versions[pkgnames[0]]
    return versions


def meets_version_specifier(pkgname, specifier):
    """Check if a package installed version meets specifier"""
    spec = SpecifierSet(specifier)
    return get_installed_version(pkgname) in spec


# YunoHost related methods ---------------------------------------------------

def ynh_packages_version(*args, **kwargs):
    # from cli the received arguments are:
    # (Namespace(_callbacks=deque([]), _tid='_global', _to_return={}), []) {}
    # they don't seem to serve any purpose
    """Return the version of each YunoHost package"""
    return get_installed_version(
        'yunohost', 'yunohost-admin', 'moulinette', 'ssowat',
        with_repo=True
    )


def dpkg_is_broken():
    # If dpkg is broken, /var/lib/dpkg/updates
    # will contains files like 0001, 0002, ...
    # ref: https://sources.debian.org/src/apt/1.4.9/apt-pkg/deb/debsystem.cc/#L141-L174
    if not os.path.isdir("/var/lib/dpkg/updates/"):
        return False
    return any(re.match("^[0-9]+$", f)
               for f in os.listdir("/var/lib/dpkg/updates/"))

def dpkg_lock_available():
    return os.system("lsof /var/lib/dpkg/lock >/dev/null") != 0

def _list_upgradable_apt_packages():

    from moulinette.utils.process import check_output

    # List upgradable packages
    # LC_ALL=C is here to make sure the results are in english
    upgradable_raw = check_output("LC_ALL=C apt list --upgradable")

    # Dirty parsing of the output
    upgradable_raw = [l.strip() for l in upgradable_raw.split("\n") if l.strip()]
    for line in upgradable_raw:

        # Remove stupid warning and verbose messages >.>
        if "apt does not have a stable CLI interface" in line or "Listing..." in line:
            continue

        # line should look like :
        # yunohost/stable 3.5.0.2+201903211853 all [upgradable from: 3.4.2.4+201903080053]
        line = line.split()
        if len(line) != 6:
            logger.warning("Failed to parse this line : %s" % ' '.join(line))
            continue

        yield {
            "name": line[0].split("/")[0],
            "new_version": line[1],
            "current_version": line[5].strip("]"),
        }


def _dump_sources_list():

    from glob import glob

    filenames = glob("/etc/apt/sources.list") + glob("/etc/apt/sources.list.d/*")
    for filename in filenames:
        with open(filename, "r") as f:
            for line in f.readlines():
                if line.startswith("#") or not line.strip():
                    continue
                yield filename.replace("/etc/apt/", "") + ":" + line.strip()
