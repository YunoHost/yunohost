#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
import string
import subprocess

import yaml

SMALL_PWD_LIST = [
    "yunohost",
    "olinuxino",
    "olinux",
    "raspberry",
    "admin",
    "root",
    "test",
    "rpi",
]

#
# 100k firsts "most used password" with length 8+
#
# List obtained with:
# curl -L https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
# | grep -v -E "^[a-zA-Z0-9]{1,7}$" | head -n 100000 | gzip > 100000-most-used-passwords-length8plus.txt.gz
#
MOST_USED_PASSWORDS = "/usr/share/yunohost/100000-most-used-passwords-length8plus.txt"

# Length, digits, lowers, uppers, others
STRENGTH_LEVELS = [
    (8, 0, 0, 0, 0),
    (8, 1, 1, 1, 0),
    (8, 1, 1, 1, 1),
    (12, 1, 1, 1, 1),
]


def assert_password_is_compatible(password):
    """
    UNIX seems to not like password longer than 127 chars ...
    e.g. SSH login gets broken (or even 'su admin' when entering the password)
    """

    if len(password) >= 127:
        # Note that those imports are made here and can't be put
        # on top (at least not the moulinette ones)
        # because the moulinette needs to be correctly initialized
        # as well as modules available in python's path.
        from yunohost.utils.error import YunohostValidationError

        raise YunohostValidationError("password_too_long")


def assert_password_is_strong_enough(profile, password):
    PasswordValidator(profile).validate(password)


def _hash_user_password(password):
    import passlib.hash

    # passlib will returns something like:
    # $6$rounds=656000$AwCIMolbTAyQhtev$46UvYfVgs.k0Bt6fLTekBHyCcCFkix/NNfgAWiICX.9YUPVYZ3PsIAwY99yP5/tXhg2sYBaAhKj6W3kuYWaR3.
    # cf https://passlib.readthedocs.io/en/stable/modular_crypt_format.html#modular-crypt-format
    return "{CRYPT}" + passlib.hash.sha512_crypt.hash(password)


class PasswordValidator:
    def __init__(self, profile):
        """
        Initialize a password validator.

        The profile shall be either "user" or "admin"
        and will correspond to a validation strength
        defined via the setting "security.password.<profile>_strength"
        """

        self.profile = profile
        try:
            # We do this "manually" instead of using settings_get()
            # from settings.py because this file is also meant to be
            # use as a script by ssowat.
            # (or at least that's my understanding -- Alex)
            settings = yaml.safe_load(open("/etc/yunohost/settings.yml", "r"))
            setting_key = profile + "_strength"
            self.validation_strength = int(settings[setting_key])
        except Exception:
            # Fallback to default value if we can't fetch settings for some reason
            self.validation_strength = 1

    def validate(self, password):
        """
        Check the validation_summary and trigger an exception
        if the password does not pass tests.

        This method is meant to be used from inside YunoHost's code
        (compared to validation_summary which is meant to be called
        by ssowat)
        """
        if self.validation_strength == -1:
            return

        # Note that those imports are made here and can't be put
        # on top (at least not the moulinette ones)
        # because the moulinette needs to be correctly initialized
        # as well as modules available in python's path.
        from yunohost.utils.error import YunohostValidationError

        status, msg = self.validation_summary(password)
        if status == "error":
            raise YunohostValidationError(msg)

    def validation_summary(self, password):
        """
        Check if a password is listed in the list of most used password
        and if the overall strength is good enough compared to the
        validation_strength defined in the constructor.

        Produces a summary-tuple comprised of a level (succes or error)
        and a message key describing the issues found.
        """
        if self.validation_strength < 0:
            return ("success", "")

        listed = password in SMALL_PWD_LIST or self.is_in_most_used_list(password)
        strength_level = self.strength_level(password)
        if listed:
            # i18n: password_listed
            return ("error", "password_listed")
        if strength_level < self.validation_strength:
            # i18n: password_too_simple_1
            # i18n: password_too_simple_2
            # i18n: password_too_simple_3
            # i18n: password_too_simple_4
            return ("error", "password_too_simple_%s" % self.validation_strength)

        return ("success", "")

    def strength(self, password):
        """
        Returns the strength of a password, defined as a tuple
        containing the length of the password, the number of digits,
        lowercase letters, uppercase letters, and other characters.

        For instance, "PikachuDu67" is (11, 2, 7, 2, 0)
        """

        length = len(password)
        digits = 0
        uppers = 0
        lowers = 0
        others = 0

        for character in password:
            if character in string.digits:
                digits = digits + 1
            elif character in string.ascii_uppercase:
                uppers = uppers + 1
            elif character in string.ascii_lowercase:
                lowers = lowers + 1
            else:
                others = others + 1

        return (length, digits, lowers, uppers, others)

    def strength_level(self, password):
        """
        Computes the strength of a password and compares
        it to the STRENGTH_LEVELS.

        Returns an int corresponding to the highest STRENGTH_LEVEL
        satisfied by the password.
        """

        strength = self.strength(password)

        strength_level = 0
        # Iterate over each level and its criterias
        for level, level_criterias in enumerate(STRENGTH_LEVELS):
            # Iterate simulatenously over the level criterias (e.g. [8, 1, 1, 1, 0])
            # and the strength of the password (e.g. [11, 2, 7, 2, 0])
            # and compare the values 1-by-1.
            # If one False is found, the password does not satisfy the level
            if False in [s >= c for s, c in zip(strength, level_criterias)]:
                break
            # Otherwise, the strength of the password is at least of the current level.
            strength_level = level + 1

        return strength_level

    def is_in_most_used_list(self, password):
        # Decompress file if compressed
        if os.path.exists("%s.gz" % MOST_USED_PASSWORDS):
            os.system("gzip -fd %s.gz" % MOST_USED_PASSWORDS)

        # Grep the password in the file
        # We use '-f -' to feed the pattern (= the password) through
        # stdin to avoid it being shown in ps -ef --forest...
        command = "grep -q -F -f - %s" % MOST_USED_PASSWORDS
        p = subprocess.Popen(command.split(), stdin=subprocess.PIPE)
        p.communicate(input=password.encode("utf-8"))
        return not bool(p.returncode)
