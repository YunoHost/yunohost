# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 Yunohost

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
import time
import subprocess

from moulinette import msignals, m18n
from moulinette.core import MoulinetteError
from moulinette.utils import filesystem
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, read_json, write_to_json


from yunohost.utils.error import YunohostError
from yunohost.monitor import binary_to_human
from yunohost.log import OperationLogger, is_unit_operation
from yunohost.backup import BackupMethod

logger = getActionLogger('yunohost.repository')
REPOSITORIES_PATH = '/etc/yunohost/repositories.yml'


class BackupRepository(object):
    """
    BackupRepository manage all repository the admin added to the instance
    """
    repositories = {}

    @classmethod
    def get(cls, name):
        cls.load()

        if name not in cls.repositories:
            raise YunohostError('backup_repository_doesnt_exists', name=name)

        return BackupRepository(**cls.repositories[name])

    @classmethod
    def load(cls):
        """
        Read repositories configuration from file
        """
        cls.repositories = {}

        if os.path.exists(REPOSITORIES_PATH):
            try:
                cls.repositories = read_json(REPOSITORIES_PATH)
            except MoulinetteError as e:
                raise YunohostError('backup_cant_open_repositories_file', reason=e)
        return cls.repositories

    @classmethod
    def save(cls):
        """
        Save managed repositories to file
        """
        try:
            write_to_json(REPOSITORIES_PATH, cls.repositories)
        except Exception as e:
            raise YunohostError('backup_cant_save_repositories_file', reason=e)

    def __init__(self, location, name=None, description=None, method=None,
                 encryption=None, quota=None):

        self.location = location
        self._split_location()

        self.name = location if name is None else name
        if self.name in BackupMethod.repositories:
            raise YunohostError('backup_repository_already_exists', repositories=name)

        self.description = description
        self.encryption = encryption
        self.quota = quota

        if method is None:
            method = 'tar' if self.domain is None else 'borg'
        self.method = BackupMethod.create(method, self)
        
        # Check for forbidden folders
        if self.path.startswith(ARCHIVES_PATH) or \
            re.match(r'^/(|(bin|boot|dev|etc|lib|root|run|sbin|sys|usr|var)(|/.*))$',
                     self.path):
            raise YunohostError('backup_output_directory_forbidden')

        # Check that output directory is empty
        if os.path.isdir(location) and os.listdir(location):
            raise YunohostError('backup_output_directory_not_empty')

    def compute_space_used(self):
        if self.used is None:
            try:
                self.used = self.method.compute_space_used()
            except (AttributeError, NotImplementedError):
                self.used = 'unknown'
        return self.used

    def purge(self):
        self.method.purge()

    def delete(self, purge=False):
        repositories = BackupRepository.repositories

        repositories.pop(self.name)

        BackupRepository.save()

        if purge:
            self.purge()

    def save(self):
        BackupRepository.reposirories[self.name] = self.__dict__
        BackupRepository.save()

    def _split_location(self):
        """
        Split a repository location into protocol, user, domain and path
        """
        location_regex = r'^((?P<protocol>ssh://)?(?P<user>[^@ ]+)@(?P<domain>[^: ]+:))?(?P<path>[^\0]+)$'
        location_match = re.match(location_regex, self.location)

        if location_match is None:
            raise YunohostError('backup_repositories_invalid_location', 
                                location=location)

        self.protocol = location_match.group('protocol')
        self.user = location_match.group('user')
        self.domain = location_match.group('domain')
        self.path = location_match.group('path')


def backup_repository_list(name, full=False):
    """
    List available repositories where put archives
    """
    repositories = BackupRepository.load()

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
    repository = BackupRepository.get(name)

    if space_used:
        repository.compute_space_used()

    repository = repository.__dict__
    if human_readable:
        if 'quota' in repository:
            repository['quota'] = binary_to_human(repository['quota'])
        if 'used' in repository and isinstance(repository['used'], int):
            repository['used'] = binary_to_human(repository['used'])

    return repository


@is_unit_operation()
def backup_repository_add(operation_logger, location, name, description=None,
                          methods=None, quota=None, encryption="passphrase"):
    """
    Add a backup repository

    Keyword arguments:
        location -- Location of the repository (could be a remote location)
        name -- Name of the backup repository
        description -- An optionnal description
        quota -- Maximum size quota of the repository
        encryption -- If available, the kind of encryption to use
    """
    repository = BackupRepository(
        location, name, description, methods, quota, encryption)

    try:
        repository.save()
    except MoulinetteError:
        raise YunohostError('backup_repository_add_failed',
                            repository=name, location=location)

    logger.success(m18n.n('backup_repository_added',
                          repository=name, location=location))


@is_unit_operation()
def backup_repository_update(operation_logger, name, description=None,
                             quota=None, password=None):
    """
    Update a backup repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    repository = BackupRepository.get(name)

    if description is not None:
        repository.description = description

    if quota is not None:
        repository.quota = quota

    try:
        repository.save()
    except MoulinetteError:
        raise YunohostError('backup_repository_update_failed', repository=name)
    logger.success(m18n.n('backup_repository_updated', repository=name,
                          location=repository['location']))


@is_unit_operation()
def backup_repository_remove(operation_logger, name, purge=False):
    """
    Remove a backup repository

    Keyword arguments:
        name -- Name of the backup repository to remove

    """
    repository = BackupRepository.get(name)
    repository.delete(purge)
    logger.success(m18n.n('backup_repository_removed', repository=name,
                          path=repository['path']))
