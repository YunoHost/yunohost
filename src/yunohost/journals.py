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
import yaml

from datetime import datetime

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

    result = {}

    for category in os.listdir(JOURNALS_PATH):
        result[category] = []
        for journal in filter(lambda x: x.endswith(".journal"), os.listdir(os.path.join(JOURNALS_PATH, category))):

            journal = journal[:-len(".journal")]
            journal = journal.split("_")
            journal_datetime = datetime.strptime(" ".join(journal[-2:]), "%Y-%m-%d %H-%M-%S")
            result[category].append({
                "started_at": journal_datetime,
                "name": " ".join(journal[:-2]),
            })

        result[category] = list(reversed(sorted(result[category], key=lambda x: x["started_at"])))

    return result


class Journal(object):
    def __init__(self, name, category, on_stdout=None, on_stderr=None, on_write=None, **kwargs):
        self.name = name
        self.category = category
        self.first_write = True

        # this help uniformise file name and avoir threads concurrency errors
        self.started_at = datetime.now()

        self.path = os.path.join(JOURNALS_PATH, category)

        self.fd = None

        self.on_stdout = [] if on_stdout is None else on_stdout
        self.on_stderr = [] if on_stderr is None else on_stderr
        self.on_write = [] if on_write is None else on_write

        self.additional_information = kwargs

    def __del__(self):
        if self.fd:
            self.fd.close()

    def write(self, line):
        if self.first_write:
            self._do_first_write()
            self.first_write = False

        self.fd.write("%s: " % datetime.now().strftime("%F_%X").replace(":", "-"))
        self.fd.write(line.rstrip())
        self.fd.write("\n")
        self.fd.flush()

    def _do_first_write(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        file_name = "%s_%s.journal" % (self.name if isinstance(self.name, basestring) else "_".join(self.name), self.started_at.strftime("%F_%X").replace(":", "-"))

        serialized_additional_information = yaml.safe_dump(self.additional_information, default_flow_style=False)

        self.fd = open(os.path.join(self.path, file_name), "w")

        self.fd.write(serialized_additional_information)
        self.fd.write("\n---\n")

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
