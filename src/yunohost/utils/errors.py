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
import errno

from moulinette.core import MoulinetteError


class YunoHostError(MoulinetteError):
    """
    YunoHostError allows to indicate if we should or shouldn't display a message
    to users about how to display logs about this error.
    """

    def __init__(self, message, log_advertisement=True):
        self.log_advertisement = log_advertisement
        super(YunoHostError, self).__init__(errno.EINVAL, message)
