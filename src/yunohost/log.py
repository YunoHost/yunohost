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
import logging

from datetime import datetime
from logging import StreamHandler, getLogger, Formatter
from sys import exc_info

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
        result["categories"].append({"name": category, "operations": []})
        for operation in filter(lambda x: x.endswith(OPERATION_FILE_EXT), os.listdir(os.path.join(OPERATIONS_PATH, category))):

            file_name = operation

            operation = operation[:-len(OPERATION_FILE_EXT)]
            operation = operation.split("_")

            operation_datetime = datetime.strptime(" ".join(operation[:2]), "%Y-%m-%d %H-%M-%S")

            result["categories"][-1]["operations"].append({
                "started_at": operation_datetime,
                "name": " ".join(operation[-2:]),
                "file_name": file_name,
                "path": os.path.join(OPERATIONS_PATH, category, file_name),
            })

        result["categories"][-1]["operations"] = list(reversed(sorted(result["categories"][-1]["operations"], key=lambda x: x["started_at"])))

        if limit is not None:
            result["categories"][-1]["operations"] = result["categories"][-1]["operations"][:limit]

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

    result = {"operations": []}

    for category in os.listdir(OPERATIONS_PATH):
        for operation in filter(lambda x: x.endswith(OPERATION_FILE_EXT), os.listdir(os.path.join(OPERATIONS_PATH, category))):
            if operation not in file_name_list and file_name_list:
                continue

            file_name = operation

            with open(os.path.join(OPERATIONS_PATH, category, file_name), "r") as content:
                content = content.read()

                operation = operation[:-len(OPERATION_FILE_EXT)]
                operation = operation.split("_")
                operation_datetime = datetime.strptime(" ".join(operation[:2]), "%Y-%m-%d %H-%M-%S")

                infos, logs = content.split("\n---\n", 1)
                infos = yaml.safe_load(infos)
                logs = [{"datetime": x.split(": ", 1)[0].replace("_", " "), "line": x.split(": ", 1)[1]}  for x in logs.split("\n") if x]

                result['operations'].append({
                    "started_at": operation_datetime,
                    "name": " ".join(operation[-2:]),
                    "file_name": file_name,
                    "path": os.path.join(OPERATIONS_PATH, category, file_name),
                    "metadata": infos,
                    "logs": logs,
                })

    if len(file_name_list) > 0 and len(result['operations']) < len(file_name_list):
        logger.error(m18n.n('log_does_exists', log="', '".join(file_name_list)))

    if len(result['operations']) > 0:
        result['operations'] = sorted(result['operations'], key=lambda operation: operation['started_at'])
        return result

def is_unit_operation(categorie=None, description_key=None):
    def decorate(func):
        def func_wrapper(*args, **kwargs):
            cat = categorie
            desc_key = description_key

            if cat is None:
                cat = func.__module__.split('.')[1]
            if desc_key is None:
                desc_key = func.__name__
            uo = UnitOperationHandler(desc_key, cat, args=kwargs)
            try:
                result = func(*args, **kwargs)
            finally:
                uo.close(exc_info()[0])
            return result
        return func_wrapper
    return decorate

class UnitOperationHandler(StreamHandler):
    def __init__(self, name, category, **kwargs):
        # TODO add a way to not save password on app installation
        self._name = name
        self.category = category
        self.first_write = True
        self.closed = False

        # this help uniformise file name and avoir threads concurrency errors
        self.started_at = datetime.now()

        self.path = os.path.join(OPERATIONS_PATH, category)

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.filename = "%s_%s" % (self.started_at.strftime("%F_%X").replace(":", "-"), self._name if isinstance(self._name, basestring) else "_".join(self._name))
        self.filename += OPERATION_FILE_EXT

        self.additional_information = kwargs

        logging.StreamHandler.__init__(self, self._open())

        self.formatter = Formatter('%(asctime)s: %(levelname)s - %(message)s')

        if self.stream is None:
            self.stream = self._open()

        # Listen to the root logger
        self.logger = getLogger('yunohost')
        self.logger.addHandler(self)


    def _open(self):
        stream = open(os.path.join(self.path, self.filename), "w")
        return stream

    def close(self, error=None):
        """
        Closes the stream.
        """
        if self.closed:
            return
        self.acquire()
        #self.ended_at = datetime.now()
        #self.error = error
        #self.stream.seek(0)
        #context = {
        #    'ended_at': datetime.now()
        #}
        #if error is not None:
        #    context['error'] = error
        #self.stream.write(yaml.safe_dump(context))
        self.logger.removeHandler(self)
        try:
            if self.stream:
                try:
                    self.flush()
                finally:
                    stream = self.stream
                    self.stream = None
                    if hasattr(stream, "close"):
                        stream.close()
        finally:
            self.release()
            self.closed = True

    def __del__(self):
        self.close()

    def emit(self, record):
        if self.first_write:
            self._do_first_write()
            self.first_write = False

        StreamHandler.emit(self, record)

    def _do_first_write(self):

        serialized_additional_information = yaml.safe_dump(self.additional_information, default_flow_style=False)

        self.stream.write(serialized_additional_information)
        self.stream.write("\n---\n")
