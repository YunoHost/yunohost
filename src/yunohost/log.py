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
    Display a log file enriched with metadata if any.

    If the file_name is not an absolute path, it will try to search the file in
    the unit operations log path (see OPERATIONS_PATH).

    Argument:
        file_name
        number
    """

    # Normalize log/metadata paths and filenames
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

    # If it's a unit operation, display the name and the description
    if base_path.startswith(OPERATIONS_PATH):
        operation = base_filename.split("-")
        infos['description'] = m18n.n("log_" + operation[2], *operation[3:]),
        infos['name'] = base_filename

    # Display metadata if exist
    if os.path.exists(md_path):
        with open(md_path, "r") as md_file:
            try:
                metadata = yaml.safe_load(md_file)
                infos['metadata_path'] = md_path
                infos['metadata'] = metadata
                if 'log_path' in metadata:
                    log_path = metadata['log_path']
            except yaml.YAMLError:
                error = m18n.n('log_corrupted_md_file', file=md_path)
                if os.path.exists(log_path):
                    logger.warning(error)
                else:
                    raise MoulinetteError(errno.EINVAL, error)

    # Display logs if exist
    if os.path.exists(log_path):
        from yunohost.service import _tail
        logs = _tail(log_path, int(number))
        #logs = [{"datetime": x.split(": ", 1)[0].replace("_", " "), "line": x.split(": ", 1)[1]}  for x in logs if x]
        infos['log_path'] = log_path
        infos['logs'] = logs

    return infos

def is_unit_operation(entities='app,domain,service,user', exclude='auth,password', operation_key=None, auto=True):
    """
    Configure quickly a unit operation

    This decorator help you to configure quickly the record of a unit operations.

    Argument:
    entities    A list seperated by coma of entity types related to the unit
    operation. The entity type is searched inside argument's names of the
    decorated function. If something match, the argument value is added as
    related entity.

    exclude     Remove some arguments from the context. By default, arguments
    called 'password' and 'auth' are removed. If an argument is an object, you
    need to exclude it or create manually the unit operation without this
    decorator.

    operation_key   Key describing the unit operation. If you want to display a
    well formed description you should add a translation key like this
    "log_" + operation_key in locales files.

    auto        If true, start the recording. If False, the unit operation object
    created is given to the decorated function as the first argument and you can
    start recording at the good time.
    """
    def decorate(func):
        def func_wrapper(*args, **kwargs):
            # For a strange reason we can't use directly the arguments from
            # is_unit_operation function. We need to store them in a var before.
            entities_list = entities.split(',')
            exclude_list = exclude.split(',')
            op_key = operation_key
            related_to = []

            if op_key is None:
                op_key = func.__name__

            # Search related entity in arguments of the decorated function
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

            # Exclude unappropriate data from the context
            for field in exclude_list:
                if field in context:
                    context.pop(field, None)
            uo = UnitOperation(op_key, related_to, args=context)

            # Start to record or give the unit operation in argument to let the
            # developper start the record itself
            if auto:
                uo.start()
            try:
                if not auto:
                    args = (uo,) + args
                result = func(*args, **kwargs)
            finally:
                # Close the unit operation if it hasn't been closed before
                uo.close(exc_info()[0])
            return result
        return func_wrapper
    return decorate

class UnitOperation(object):
    """
    Instances of this class represents unit operation the yunohost admin as done.

    Each time an action of the yunohost cli/api change the system, one or several
    unit operations should be registered.

    This class record logs and some metadata like context or start time/end time.
    """

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
        """
        Start to record logs that change the system
        Until this start method is run, no unit operation will be registered.
        """

        if self.started_at is None:
            self.started_at = datetime.now()
            self.flush()
            self._register_log()

    def _register_log(self):
        """
        Register log with a handler connected on log system
        """

        # TODO add a way to not save password on app installation
        filename = os.path.join(self.path, self.name + LOG_FILE_EXT)
        self.file_handler = FileHandler(filename)
        self.file_handler.formatter = Formatter('%(asctime)s: %(levelname)s - %(message)s')

        # Listen to the root logger
        self.logger = getLogger('yunohost')
        self.logger.addHandler(self.file_handler)

    def flush(self):
        """
        Write or rewrite the metadata file with all metadata known
        """

        filename = os.path.join(self.path, self.name + METADATA_FILE_EXT)
        with open(filename, 'w') as outfile:
            yaml.safe_dump(self.metadata, outfile, default_flow_style=False)

    @property
    def name(self):
        """
        Name of the operation
        This name is used as filename, so don't use space
        """
        name = [self.started_at.strftime("%Y%m%d-%H%M%S")]
        name += [self.operation]
        if self.related_to:
            name += self.related_to[0].values()
        return '-'.join(name)

    @property
    def metadata(self):
        """
        Dictionnary of all metadata collected
        """

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
        """
        Declare the success end of the unit operation
        """
        self.close()

    def error(self, error):
        """
        Declare the failure of the unit operation
        """
        self.close(error)

    def close(self, error=None):
        """
        Close properly the unit operation
        """
        if self.ended_at is not None or self.started_at is None:
            return
        self.ended_at = datetime.now()
        self._error = error
        self._success = error is None
        if self.logger is not None:
            self.logger.removeHandler(self.file_handler)
        self.flush()

    def __del__(self):
        """
        Try to close the unit operation, if it's missing.
        The missing of the message below could help to see an electrical
        shortage.
        """
        self.error(m18n.n('log_operation_unit_unclosed_properly'))

