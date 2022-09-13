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
import os


def free_space_in_directory(dirpath):
    stat = os.statvfs(dirpath)
    return stat.f_frsize * stat.f_bavail


def space_used_by_directory(dirpath):
    stat = os.statvfs(dirpath)
    return stat.f_frsize * stat.f_blocks

def disk_usage(path):
    # We don't do this in python with os.stat because we don't want
    # to follow symlinks

    du_output = check_output(["du", "-sb", path], shell=False)
    return int(du_output.split()[0])


def binary_to_human(n, customary=False):
    """
    Convert bytes or bits into human readable format with binary prefix
    Keyword argument:
        n -- Number to convert
        customary -- Use customary symbol instead of IEC standard
    """
    symbols = ("Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi")
    if customary:
        symbols = ("K", "M", "G", "T", "P", "E", "Z", "Y")
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return "%.1f%s" % (value, s)
    return "%s" % n
