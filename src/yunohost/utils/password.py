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
PWDDICT_PATH = '/usr/local/share/dict/cracklib/'
SMALL_PWD_LIST = ["yunohost", "olinuxino", "olinux", "raspberry", "admin",
                  "root", "test", "rpi"]
PWD_LIST_FILE = '100000-most-used'
ACTIVATE_ONLINE_PWNED_LIST = False

class PasswordValidator(object):
    """
    PasswordValidator class validate password
    """

    # Unlisted, length, digits, lowers, uppers, others
    strength_lvl = [
        [100000, 6, 0, 0, 0, 0],
        [100000, 8, 1, 1, 1, 0],
        [320000000, 8, 1, 1, 1, 1],
        [320000000, 12, 1, 1, 1, 1],
    ]

    def __init__(self, validation_strength):
        self.validation_strength = validation_strength

    def validate(self, password):
        """
        Validate a password and raise error or display a warning
        """
        if self.validation_strength <= 0:
            return

        self.strength = self.compute(password, ACTIVATE_ONLINE_PWNED_LIST)
        if self.strength < self.validation_strength:
            if self.listed:
                return "password_listed_" + str(self.validation_strength)
            else:
                return "password_too_simple_" + str(self.validation_strength)

    def compute(self, password, online=False):
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

        # Check small list
        unlisted = 0
        if password not in SMALL_PWD_LIST:
            unlisted = len(SMALL_PWD_LIST)

        # Check big list
        size_list = 100000
        if unlisted > 0 and not self.is_in_cracklib_list(password, PWD_LIST_FILE):
            unlisted = size_list if online else 320000000

        # Check online big list
        if unlisted > size_list and online and not self.is_in_online_pwned_list(password):
            unlisted = 320000000

        self.listed = unlisted < 320000000
        return self.compare(unlisted, length, digits, lowers, uppers, others)

    def compare(self, unlisted, length, digits, lowers, uppers, others):
        strength = 0

        for i, config in enumerate(self.strength_lvl):
            if unlisted < config[0] or length < config[1] \
               or digits < config[2] or lowers < config[3] \
               or uppers < config[4] or others < config[5]:
                break
            strength = i + 1
        return strength

    def is_in_online_pwned_list(self, password, silent=True):
        """
        Check if a password is in the list of breached passwords from
        haveibeenpwned.com
        """

        from hashlib import sha1
        import requests
        hash = sha1(password).hexdigest()
        range = hash[:5]
        needle = (hash[5:].upper())

        try:
            hash_list =requests.get('https://api.pwnedpasswords.com/range/' +
                                      range, timeout=30)
        except e:
            if not silent:
                raise
        else:
            if hash_list.find(needle) != -1:
                return True
        return False

    def is_in_cracklib_list(self, password, pwd_dict):
        try:
            cracklib.VeryFascistCheck(password, None,
                                      os.path.join(PWDDICT_PATH, pwd_dict))
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

        error = super(LoggerPasswordValidator, self).validate(password)
        if error is not None:
            raise MoulinetteError(1, m18n.n(error))

        if self.strength < 3:
            logger.info(m18n.n('password_advice'))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: password.py PASSWORD")

    result = ProfilePasswordValidator('user').validate(sys.argv[1])
    if result is not None:
        sys.exit(result)


