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

from moulinette.core import MoulinetteError
from moulinette.__init__ import m18n

class YunohostError(MoulinetteError):
    """Yunohost base exception"""
    def __init__(self, key, *args, **kwargs):
        msg = m18n.n(key, *args, **kwargs)
        super(MoulinetteError, self).__init__(msg)

