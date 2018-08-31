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

""" yunohost_repository.py

    Manage backup repositories
"""
import os
import re
import json
import errno
import time
import tarfile
import shutil
import subprocess

from moulinette import msignals, m18n
from moulinette.core import MoulinetteError
from moulinette.utils import filesystem
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file

from yunohost.monitor import binary_to_human
from yunohost.log import OperationLogger

logger = getActionLogger('yunohost.repository')
REPOSITORIES_PATH = '/etc/yunohost/repositories.yml'

def backup_repository_list(name, full=False):
    """
    List available repositories where put archives
    """
    repositories = _get_repositories()

    if full:
        return repositories
    else:
        return repositories.keys()

def backup_repository_info(name, human_readable=True, space_used=False):
    """
    Show info about a repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    repositories = _get_repositories()

    repository = repositories.pop(name, None)

    if repository is None:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'backup_repository_doesnt_exists', name=name))

    if space_used:
        repository['used'] = _get_repository_used_space(name)

    if human_readable:
        if 'quota' in repository:
            repository['quota'] = binary_to_human(repository['quota'])
        if 'used' in repository and isinstance(repository['used', int):
            repository['used'] = binary_to_human(repository['used'])

    return repository

@is_unit_operation()
def backup_repository_add(operation_logger, path, name, description=None,
                          methods=None, quota=None, encryption="passphrase"):
    """
    Add a backup repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    repositories = _get_repositories()

    if name in repositories:
        raise MoulinetteError(errno.EIO, m18n.n('backup_repositories_already_exists', repositories=name))

    repositories[name]= {
        'path': path
    }

    if description is not None:
        repositories[name]['description'] = description

    if methods is not None:
        repositories[name]['methods'] = methods

    if quota is not None:
        repositories[name]['quota'] = quota

    if encryption is not None:
        repositories[name]['encryption'] = encryption

    try:
        _save_repositories(repositories)
    except:
        raise MoulinetteError(errno.EIO, m18n.n('backup_repository_add_failed',
                                                repository=name, path=path))

    logger.success(m18n.n('backup_repository_added', repository=name, path=path))

@is_unit_operation()
def backup_repository_update(operation_logger, name, description=None,
                             quota=None, password=None):
    """
    Update a backup repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    repositories = _get_repositories()

    if name not in repositories:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'backup_repository_doesnt_exists', name=name))

    if description is not None:
        repositories[name]['description'] = description

    if quota is not None:
        repositories[name]['quota'] = quota

    _save_repositories(repositories)

    logger.success(m18n.n('backup_repository_updated', repository=name,
                          path=repository['path']))

@is_unit_operation()
def backup_repository_remove(operation_logger, name, purge=False):
    """
    Remove a backup repository

    Keyword arguments:
        name -- Name of the backup repository to remove

    """
    repositories = _get_repositories()

    repository = repositories.pop(name)

    if repository is None:
        raise MoulinetteError(errno.EINVAL, m18n.n(
            'backup_repository_doesnt_exists', name=name))

    _save_repositories(repositories)

    logger.success(m18n.n('backup_repository_removed', repository=name,
                          path=repository['path']))


def _save_repositories(repositories):
    """
    Save managed repositories to file

    Keyword argument:
        repositories -- A dict of managed repositories with their parameters

    """
    try:
        write_to_json(REPOSITORIES_PATH, repositories)
    except Exception as e:
        raise MoulinetteError(1, m18n.n('backup_cant_save_repositories_file',
                                        reason=e),
                              exc_info=1)


def _get_repositories():
    """
    Read repositories configuration from file

    Keyword argument:
        repositories -- A dict of managed repositories with their parameters

    """
    repositories = {}

    if os.path.exists(REPOSITORIES_PATH):
        try:
            repositories = read_json(REPOSITORIES_PATH)
        except MoulinetteError as e:
            raise MoulinetteError(1,
                                  m18n.n('backup_cant_open_repositories_file',
                                         reason=e),
                                  exc_info=1)

    return repositories


def _get_repository_used_space(path, methods=None):
    """
    Return the used space on a repository or 'unknown' if method don't support
    this feature

    Keyword argument:
        path -- Path of the repository

    """
    logger.info("--space-used option not yet implemented")
    return 'unknown'
