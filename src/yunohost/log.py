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
from logging import FileHandler, getLogger, Formatter
from sys import exc_info

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

OPERATIONS_PATH = '/var/log/yunohost/operation/'
METADATA_FILE_EXT = '.yml'
LOG_FILE_EXT = '.log'
RELATED_CATEGORIES = ['app', 'domain', 'service', 'user']

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
        for operation in filter(lambda x: x.endswith(METADATA_FILE_EXT), os.listdir(os.path.join(OPERATIONS_PATH, category))):

            base_filename = operation[:-len(METADATA_FILE_EXT)]
            md_filename = operation
            md_path = os.path.join(OPERATIONS_PATH, category, md_filename)

            operation = base_filename.split("-")

            operation_datetime = datetime.strptime(" ".join(operation[:2]), "%Y%m%d %H%M%S")

            result["categories"][-1]["operations"].append({
                "started_at": operation_datetime,
                "description": m18n.n("log_" + operation[2], *operation[3:]),
                "name": base_filename,
                "path": md_path,
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
        for operation in filter(lambda x: x.endswith(METADATA_FILE_EXT), os.listdir(os.path.join(OPERATIONS_PATH, category))):
            if operation not in file_name_list and file_name_list:
                continue

            base_filename = operation[:-len(METADATA_FILE_EXT)]
            md_filename = operation
            md_path = os.path.join(OPERATIONS_PATH, category, md_filename)
            log_filename = base_filename + LOG_FILE_EXT
            log_path = os.path.join(OPERATIONS_PATH, category, log_filename)
            operation = base_filename.split("-")

            with open(md_path, "r") as md_file:
                try:
                    infos = yaml.safe_load(md_file)
                except yaml.YAMLError as exc:
                    print(exc)

            with open(log_path, "r") as content:
                logs = content.read()
                logs = [{"datetime": x.split(": ", 1)[0].replace("_", " "), "line": x.split(": ", 1)[1]}  for x in logs.split("\n") if x]
            infos['logs'] = logs
            infos['description'] = m18n.n("log_" + operation[2], *operation[3:]),
            infos['name'] = base_filename
            infos['log_path'] = log_path
            result['operations'].append(infos)

    if len(file_name_list) > 0 and len(result['operations']) < len(file_name_list):
        logger.error(m18n.n('log_does_exists', log="', '".join(file_name_list)))

    if len(result['operations']) > 0:
        result['operations'] = sorted(result['operations'], key=lambda operation: operation['started_at'])
        return result

def is_unit_operation(categorie=None, operation_key=None, lazy=False):
    def decorate(func):
        def func_wrapper(*args, **kwargs):
            cat = categorie
            op_key = operation_key
            on = None
            related_to = {}
            inject = lazy
            to_start = not lazy

            if cat is None:
                cat = func.__module__.split('.')[1]
            if op_key is None:
                op_key = func.__name__
            if cat in kwargs:
                on = kwargs[cat]
            for r_category in RELATED_CATEGORIES:
                if r_category in kwargs and kwargs[r_category] is not None:
                    if r_category not in related_to:
                        related_to[r_category] = []
                    if isinstance(kwargs[r_category], basestring):
                        related_to[r_category] += [kwargs[r_category]]
                    else:
                        related_to[r_category] += kwargs[r_category]
            context = kwargs.copy()
            if 'auth' in context:
                context.pop('auth', None)
            uo = UnitOperation(op_key, cat, on, related_to, args=context)
            if to_start:
                uo.start()
            try:
                if inject:
                    args = (uo,) + args
                result = func(*args, **kwargs)
            finally:
                if uo.started_at is not None:
                    uo.close(exc_info()[0])
            return result
        return func_wrapper
    return decorate

class UnitOperation(object):
    def __init__(self, operation, category, on=None, related_to=None, **kwargs):
        # TODO add a way to not save password on app installation
        self.operation = operation
        self.category = category
        self.on = on
        if isinstance(self.on, basestring):
            self.on = [self.on]

        self.related_to = related_to
        if related_to is None:
            if self.category in RELATED_CATEGORIES:
                self.related_to = {self.category: self.on}
        self.extra = kwargs
        self.started_at = None
        self.ended_at = None
        self.logger = None

        self.path = os.path.join(OPERATIONS_PATH, category)

        if not os.path.exists(self.path):
            os.makedirs(self.path)

    def start(self):
        if self.started_at is None:
            self.started_at = datetime.now()
            self.flush()
            self._register_log()

    def _register_log(self):
        # TODO add a way to not save password on app installation
        filename = os.path.join(self.path, self.name + LOG_FILE_EXT)
        self.file_handler = FileHandler(filename)
        self.file_handler.formatter = Formatter('%(asctime)s: %(levelname)s - %(message)s')

        # Listen to the root logger
        self.logger = getLogger('yunohost')
        self.logger.addHandler(self.file_handler)

    def flush(self):
        filename = os.path.join(self.path, self.name + METADATA_FILE_EXT)
        with open(filename, 'w') as outfile:
            yaml.safe_dump(self.metadata, outfile, default_flow_style=False)

    @property
    def name(self):
        name = [self.started_at.strftime("%Y%m%d-%H%M%S")]
        name += [self.operation]
        if self.on is not None:
            name += self.on
        return '-'.join(name)

    @property
    def metadata(self):
        data = {
            'started_at': self.started_at,
            'operation': self.operation,
            'related_to': self.related_to
        }
        if self.on is not None:
            data['on'] = self.on
        if self.ended_at is not None:
            data['ended_at'] = self.ended_at
            data['success'] = self._success
            if self.error is not None:
                data['error'] = self._error
                # TODO: detect if 'extra' erase some key of 'data'
        data.update(self.extra)
        return data

    def success(self):
        self.close()

    def error(self, error):
        self.close(error)

    def close(self, error=None):
        if self.ended_at is not None or self.started_at is None:
            return
        self.ended_at = datetime.now()
        self._error = error
        self._success = error is None
        if self.logger is not None:
            self.logger.removeHandler(self.file_handler)
        self.flush()

    def __del__(self):
        self.error(m18n.n('log_operation_unit_unclosed_properly'))

