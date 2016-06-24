# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2016 YunoHost

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

""" yunohost_journals.py

    Manage debug journals
"""

import os

from moulinette.utils.log import getActionLogger

JOURNALS_PATH = '/var/log/journals/'

logger = getActionLogger('yunohost.journals')


def journals_list():
    """
    List domains

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for domain fetching
        limit -- Maximum number of domain fetched

    """

    if not os.path.exists(JOURNALS_PATH):
        return {}

    return {}


class Journal(object):
    def __init__(self, name, category, on_stdout=None, on_stderr=None, on_write=None, **kwargs):
        self.name = name
        self.category = category
        self.first_write = False
        self.started_at = None

        self.on_stdout = [] if on_stdout is None else on_stdout
        self.on_stderr = [] if on_stderr is None else on_stderr
        self.on_write = [] if on_write is None else on_write

        self.additional_information = kwargs

    def write(self, line):
        print "[journal]", line.rstrip()

    def stdout(self, line):
        for i in self.on_stdout:
            i(line)

        self.write(line)

    def stderr(self, line):
        for i in self.on_stderr:
            i(line)

        self.write(line)

    def as_callbacks_tuple(self, stdout=None, stderr=None):
        if stdout:
            self.on_stdout.append(stdout)

        if stderr:
            self.on_stderr.append(stderr)

        return (self.stdout, self.stderr)
