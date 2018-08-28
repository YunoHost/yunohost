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
import re
import os
import errno
import logging
import cracklib

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.network import download_text
from yunohost.settings import settings_get

logger = logging.getLogger('yunohost.utils.password')

PWDDICT_PATH = '/usr/local/share/dict/cracklib/'

class HintException(Exception):

    def __init__(self, message, **kwargs):
        # Call the base class constructor with the parameters it needs
        super(HintException, self).__init__(message)
        self.kwargs = kwargs
        self.criticity = 'error'

    @property
    def warn_only(self):
        return m18n.n(self.args[0] + '_warn', **self.kwargs)

    @property
    def error(self):
        return m18n.n(self.args[0] + '_error', **self.kwargs)


class PasswordValidator(object):
    """
    PasswordValidator class validate password
    Derivated from Nextcloud (AGPL-3)
    https://github.com/nextcloud/password_policy/blob/fc4f77052cc248b4e68f0e9fb0d381ab7faf28ad/lib/PasswordValidator.php
    """
    # List of validators (order is important)
    # We keep the online_pwned_list at the end to check only if needed
    validators = ['length', 'numeric', 'upper_lower', 'special',
    'ynh_common_list', 'cracklib_list', 'online_pwned_list']

    def __init__(self, profile):
        self.profile = profile
        self.config = None
        self._get_config()

    def validate(self, password, old=None, validator=None):
        """
        Validate a password and raise error or display a warning
        """

        result = {'error': [], 'warn_only': []}
        # Check a specific validator only if enabled
        if validator is not None and self.config[validator] == 'disabled':
            return result
        elif validator is not None:
            try:
                getattr(self, 'check_' + validator)(password, old)
            except HintException as e:
                criticity = self.config[validator]
                if "warn_only" in [e.criticity, criticity]:
                    criticity = "warn_only"
                result[criticity].append(e)
            return result

        # Run all validators
        for validator in self.validators:
            if result['error'] and validator.endswith('_list'):
                break
            res = self.validate(password, old, validator)
            result['error'] = result['error'] + res['error']
            result['warn_only'] = result['warn_only'] + res['warn_only']

        # Build a concatenate message
        message = []
        for error in result['error']:
            message.append(error.error)
        for warn in result['warn_only']:
            message.append(warn.warn_only)
        message = "\n".join(message)

        # Raise an error or warn the user according to criticity
        if result['error']:
            raise MoulinetteError(errno.EINVAL, message)
        elif result['warn_only']:
            logger.warn(message)
        return result['warn_only']

    def check_length(self, password, old=None):
        """
        Check if password matches the minimum length defined by the admin
        """

        if len(password) < self.config['min_length.error']:
            if self.config['min_length.warn'] == self.config['min_length.error']:
                raise HintException('password_length',
                                min_length=self.config['min_length.error'])
            else:
                raise HintException('password_length_warn',
                                min_length=self.config['min_length.error'],
                                better_length=self.config['min_length.warn'])

        if len(password) < self.config['min_length.warn']:
             e = HintException('password_length',
                                min_length=self.config['min_length.warn'])
             e.criticity = 'warn_only'
             raise e

    def check_numeric(self, password, old=None):
        """
        Check if password contains numeric characters
        """

        if re.search(r'\d', password) is None:
            raise HintException('password_numeric')

    def check_upper_lower(self, password, old=None):
        """
        Check if password contains at least one upper and one lower case
        character
        """

        if password.lower() == password or password.upper() == password:
            raise HintException('password_upper_lower')

    def check_special(self, password, old=None):
        """
        Check if password contains at least one special character
        """

        if re.match(r'^\w*$', password):
            raise HintException('password_special')

    def check_ynh_common_list(self, password, old=None):
        """
        Check if password is a common ynh password
        """

        if password in ["yunohost", "olinuxino", "olinux", "raspberry", "admin",
                        "root", "test"]:
            raise HintException('password_listed')

    def check_cracklib_list(self, password, old=None):
        """
        Check password with cracklib dictionnary from the config
        https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
        """

        error_dict = self.config['cracklib_list.error']
        warn_dict = self.config['cracklib_list.warn']

        self._check_cracklib_list(password, old, error_dict)

        if error_dict == warn_dict:
            return
        try:
            self._check_cracklib_list(password, old, warn_dict)
        except HintException as e:
            e.criticity = 'warn_only'
            raise e

    def check_online_pwned_list(self, password, old=None, silent=True):
        """
        Check if a password is in the list of breached passwords from
        haveibeenpwned.com
        """

        from hashlib import sha1
        from moulinette.utils.network import download_text
        hash = sha1(password).hexdigest()
        range = hash[:5]
        needle = (hash[5:].upper())

        try:
            hash_list = download_text('https://api.pwnedpasswords.com/range/' +
                                      range)
        except MoulinetteError as e:
            if not silent:
                raise
        else:
            if hash_list.find(needle) != -1:
                raise HintException('password_listed')

    def _check_cracklib_list(self, password, old, pwd_dict):
        try:
            cracklib.VeryFascistCheck(password, old,
                                      os.path.join(PWDDICT_PATH, pwd_dict))
        except ValueError as e:
            # We only want the dictionnary check of cracklib, not the is_simple
            # test.
            if str(e) not in ["is too simple", "is a palindrome"]:
                raise HintException('password_listed', pwd_list=pwd_dict)

    def _get_config(self):
        """
        Build profile config from settings
        """

        def _set_param(name):
            self.config[name] = self._get_setting(name)

            if self.config[name] == 'error' and self.config['mode'] == 'warn_only':
                self.config[name] = self.config['mode']
            elif self.config[name] in ['error', 'warn_only'] and \
                 self.config['mode'] == 'disabled':
                self.config[name] = 'disabled'

        if self.config is not None:
            return self.config
        self.config = {}
        self.config['mode'] = self._get_setting('mode')
        for validator in self.validators:
            _set_param(validator)
        for param in ['min_length.', 'cracklib_list.']:
            self.config[param + 'error'] = self._get_setting(param + 'error')
            self.config[param + 'warn'] = self._get_setting(param + 'warn')

        return self.config


    def _get_setting(self, setting):
        return settings_get('security.password.' + self.profile + '.' + setting)

