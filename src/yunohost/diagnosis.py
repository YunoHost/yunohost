# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2018 YunoHost

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

""" diagnosis.py

    Look for possible issues on the server
"""

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils import log

logger = log.getActionLogger('yunohost.diagnosis')

def diagnosis_list():
    pass

def diagnosis_report(categories=[], full=False):
    pass

def diagnosis_run(categories=[], force=False, args=""):
    pass

def diagnosis_ignore(category, args="", unignore=False):
    pass

