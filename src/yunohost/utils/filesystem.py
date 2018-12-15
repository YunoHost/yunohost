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
