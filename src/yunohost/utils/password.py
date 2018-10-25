# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

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

import sys
import os
import cracklib

import string
ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
SMALL_PWD_LIST = ["yunohost", "olinuxino", "olinux", "raspberry", "admin",
                  "root", "test", "rpi"]

PWDDICT_FOLDER = '/usr/local/share/dict/cracklib/'
PWDDICT_LIST = '100000-most-used'

class PasswordValidator(object):
    """
    PasswordValidator class validate password
    """

    # Length, digits, lowers, uppers, others
    strength_lvl = [
        [6, 0, 0, 0, 0],
        [8, 1, 1, 1, 0],
        [8, 1, 1, 1, 1],
        [12, 1, 1, 1, 1],
    ]

    def __init__(self, validation_strength):
        self.validation_strength = validation_strength

    def validate(self, password):
        """
        Validate a password and raise error or display a warning
        """
        if self.validation_strength <= 0:
            return ("success", "")

        self.listed = password in SMALL_PWD_LIST or self.is_in_cracklib_list(password)
        self.strength = self.compute(password)
        if self.strength < self.validation_strength:
            if self.listed:
                return ("error", "password_listed_" + str(self.validation_strength))
            else:
                return ("error", "password_too_simple_" + str(self.validation_strength))

        if self.strength < 3:
            return ("warning", 'password_advice')
        return ("success", "")

    def compute(self, password):
        # Indicators
        length = len(password)
        digits = 0
        uppers = 0
        lowers = 0
        others = 0

        for character in password:
            if character in string.digits:
                digits = digits + 1
            elif character in ASCII_UPPERCASE:
                uppers = uppers + 1
            elif character in ASCII_LOWERCASE:
                lowers = lowers + 1
            else:
                others = others + 1

        return self.compare(length, digits, lowers, uppers, others)

    def compare(self, length, digits, lowers, uppers, others):
        strength = 0

        for i, config in enumerate(self.strength_lvl):
            if length < config[0] or digits < config[1] \
               or lowers < config[3] or uppers < config[4] \
               or others < config[5]:
                break
            strength = i + 1
        return strength

    def is_in_cracklib_list(self, password):
        try:
            cracklib.VeryFascistCheck(password, None,
                                      os.path.join(PWDDICT_FOLDER, PWDDICT_LIST))
        except ValueError as e:
            # We only want the dictionnary check of cracklib, not the is_simple
            # test.
            if str(e) not in ["is too simple", "is a palindrome"]:
                return True


class ProfilePasswordValidator(PasswordValidator):
    def __init__(self, profile):
        self.profile = profile
        import json
        try:
            settings = json.load(open('/etc/yunohost/settings.json', "r"))
            self.validation_strength = int(settings["security.password." + profile +
                '.strength'])
        except Exception as e:
            self.validation_strength = 2 if profile == 'admin' else 1
            return

class LoggerPasswordValidator(ProfilePasswordValidator):
    """
    PasswordValidator class validate password
    """

    def validate(self, password):
        """
        Validate a password and raise error or display a warning
        """
        if self.validation_strength == -1:
            return
        import errno
        import logging
        from moulinette import m18n
        from moulinette.core import MoulinetteError
        from moulinette.utils.log import getActionLogger

        logger = logging.getLogger('yunohost.utils.password')

        status, msg = super(LoggerPasswordValidator, self).validate(password)
        if status == "error":
            raise MoulinetteError(1, m18n.n(msg))
        elif status == "warning":
            logger.info(m18n.n(msg))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        import getpass
        pwd = getpass.getpass("")
        #print("usage: password.py PASSWORD")
    else:
        pwd = sys.argv[1]
    status, msg = ProfilePasswordValidator('user').validate(pwd)
    print(msg)
    sys.exit(0)


