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

def log_list(limit=None, full=False):
    """
    List available logs

    Keyword argument:
        limit -- Maximum number of logs
    """

    result = {"operations": []}

    if not os.path.exists(OPERATIONS_PATH):
        return result

    operations = filter(lambda x: x.endswith(METADATA_FILE_EXT), os.listdir(OPERATIONS_PATH))
    operations = reversed(sorted(operations))

    if limit is not None:
        operations = operations[:limit]

    for operation in operations:

        base_filename = operation[:-len(METADATA_FILE_EXT)]
        md_filename = operation
        md_path = os.path.join(OPERATIONS_PATH, md_filename)

        operation = base_filename.split("-")

        operation_datetime = datetime.strptime(" ".join(operation[:2]), "%Y%m%d %H%M%S")

        result["operations"].append({
            "started_at": operation_datetime,
            "description": m18n.n("log_" + operation[2], *operation[3:]),
            "name": base_filename,
            "path": md_path,
        })

    return result


def log_display(file_name, number=50):
    """
    Display full log or specific logs listed

    Argument:
        file_name
        number
    """

    abs_path = file_name
    log_path = None
    if not file_name.startswith('/'):
        abs_path = os.path.join(OPERATIONS_PATH, file_name)

    if os.path.exists(abs_path) and not file_name.endswith(METADATA_FILE_EXT) :
        log_path = abs_path

    base_path = os.path.splitext(abs_path)[0]
    base_filename = os.path.basename(base_path)
    md_path = base_path + METADATA_FILE_EXT
    if log_path is None:
        log_path = base_path + LOG_FILE_EXT

    if not os.path.exists(md_path) and not os.path.exists(log_path):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('log_does_exists', log=file_name))

    infos = {}
    if base_path.startswith(OPERATIONS_PATH):
        operation = base_filename.split("-")
        infos['description'] = m18n.n("log_" + operation[2], *operation[3:]),
        infos['name'] = base_filename

    if os.path.exists(md_path):
        with open(md_path, "r") as md_file:
            try:
                metadata = yaml.safe_load(md_file)
                infos['metadata_path'] = md_path
                infos['metadata'] = metadata
                if 'log_path' in metadata:
                    log_path = metadata['log_path']
            except yaml.YAMLError as exc:
                print(exc)

    if os.path.exists(log_path):
        from yunohost.service import _tail
        logs = _tail(log_path, int(number))
        #logs = [{"datetime": x.split(": ", 1)[0].replace("_", " "), "line": x.split(": ", 1)[1]}  for x in logs if x]
        infos['log_path'] = log_path
        infos['logs'] = logs

    return infos

def is_unit_operation(entities='app,domain,service,user', exclude='auth,password', operation_key=None, auto=True):
    def decorate(func):
        def func_wrapper(*args, **kwargs):
            entities_list = entities.split(',')
            exclude_list = exclude.split(',')
            op_key = operation_key
            related_to = []

            if op_key is None:
                op_key = func.__name__

            for entity in entities_list:
                entity = entity.split(':')
                entity_type = entity[-1]
                entity = entity[0]
                if entity in kwargs and kwargs[entity] is not None:
                    if isinstance(kwargs[entity], basestring):
                        related_to.append({entity_type: kwargs[entity]})
                    else:
                        for x in kwargs[entity]:
                            related_to.append({entity_type: kwargs[x]})

            context = kwargs.copy()
            for field in exclude_list:
                if field in context:
                    context.pop(field, None)
            uo = UnitOperation(op_key, related_to, args=context)
            if auto:
                uo.start()
            try:
                if not auto:
                    args = (uo,) + args
                result = func(*args, **kwargs)
            finally:
                uo.close(exc_info()[0])
            return result
        return func_wrapper
    return decorate

class UnitOperation(object):
    def __init__(self, operation, related_to=None, **kwargs):
        # TODO add a way to not save password on app installation
        self.operation = operation
        self.related_to = related_to
        self.extra = kwargs
        self.started_at = None
        self.ended_at = None
        self.logger = None

        self.path = OPERATIONS_PATH

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
        if self.related_to:
            name += self.related_to[0].values()
        return '-'.join(name)

    @property
    def metadata(self):
        data = {
            'started_at': self.started_at,
            'operation': self.operation,
        }
        if self.related_to is not None:
            data['related_to'] = self.related_to
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

