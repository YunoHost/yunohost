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

""" yunohost_log.py

    Manage debug logs
"""

import os
import yaml
import errno

from datetime import datetime

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

OPERATIONS_PATH = '/var/log/yunohost/operation/'
OPERATION_FILE_EXT = '.yml'

logger = getActionLogger('yunohost.log')


def log_list(limit=None):
    """
    List available logs

    Keyword argument:
        limit -- Maximum number of logs per categories
    """

    result = {"categories": []}

    if not os.path.exists(OPERATIONS_PATH):
        return result

    for category in sorted(os.listdir(OPERATIONS_PATH)):
        result["categories"].append({"name": category, "logs": []})
        for operation in filter(lambda x: x.endswith(OPERATION_FILE_EXT), os.listdir(os.path.join(OPERATIONS_PATH, category))):

            file_name = operation

            operation = operation[:-len(OPERATION_FILE_EXT)]
            operation = operation.split("_")

            operation_datetime = datetime.strptime(" ".join(operation[-2:]), "%Y-%m-%d %H-%M-%S")

            result["categories"][-1]["logs"].append({
                "started_at": operation_datetime,
                "name": " ".join(operation[:-2]),
                "file_name": file_name,
                "path": os.path.join(OPERATIONS_PATH, category, file_name),
            })

        result["categories"][-1]["logs"] = list(reversed(sorted(result["categories"][-1]["logs"], key=lambda x: x["started_at"])))

        if limit is not None:
            result["categories"][-1]["logs"] = result["categories"][-1]["logs"][:limit]

    return result


def log_display(file_name_list):
    """
    Display full log or specific logs listed

    Argument:
        file_name_list
    """

    if not os.path.exists(OPERATIONS_PATH):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('log_does_exists', log=" ".join(file_name_list)))

    result = {"logs": []}

    for category in os.listdir(OPERATIONS_PATH):
        for operation in filter(lambda x: x.endswith(OPERATION_FILE_EXT), os.listdir(os.path.join(OPERATIONS_PATH, category))):
            if operation not in file_name_list and file_name_list:
                continue

            file_name = operation

            with open(os.path.join(OPERATIONS_PATH, category, file_name), "r") as content:
                content = content.read()

                operation = operation[:-len(OPERATION_FILE_EXT)]
                operation = operation.split("_")
                operation_datetime = datetime.strptime(" ".join(operation[-2:]), "%Y-%m-%d %H-%M-%S")

                infos, logs = content.split("\n---\n", 1)
                infos = yaml.safe_load(infos)
                logs = [{"datetime": x.split(": ", 1)[0].replace("_", " "), "line": x.split(": ", 1)[1]}  for x in logs.split("\n") if x]

                result['logs'].append({
                    "started_at": operation_datetime,
                    "name": " ".join(operation[:-2]),
                    "file_name": file_name,
                    "path": os.path.join(OPERATIONS_PATH, category, file_name),
                    "metadata": infos,
                    "logs": logs,
                })

    logger.debug("====> %s", len(file_name_list), exc_info=1)
    if len(file_name_list) > 0 and len(result['logs']) < len(file_name_list):
        logger.error(m18n.n('log_does_exists', log="', '".join(file_name_list)))

    if len(result['logs']) > 0:
        return result

class Journal(object):
    def __init__(self, name, category, on_stdout=None, on_stderr=None, on_write=None, **kwargs):
        # TODO add a way to not save password on app installation
        self.name = name
        self.category = category
        self.first_write = True

        # this help uniformise file name and avoir threads concurrency errors
        self.started_at = datetime.now()

        self.path = os.path.join(OPERATIONS_PATH, category)

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

        self.fd.write("%s: " % datetime.now().strftime("%F %X"))
        self.fd.write(line.rstrip())
        self.fd.write("\n")
        self.fd.flush()

    def _do_first_write(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        file_name = "%s_%s" % (self.name if isinstance(self.name, basestring) else "_".join(self.name), self.started_at.strftime("%F_%X").replace(":", "-"))
        file_name += OPERATION_FILE_EXT

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
