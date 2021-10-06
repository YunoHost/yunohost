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
import re
import urllib.parse

from moulinette import Moulinette, m18n
from moulinette.core import MoulinetteError
from moulinette.utils import filesystem
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, read_yaml, write_to_json


from yunohost.utils.config import ConfigPanel, Question
from yunohost.utils.error import YunohostError
from yunohost.utils.filesystem import binary_to_human
from yunohost.utils.network import get_ssh_public_key
from yunohost.log import OperationLogger, is_unit_operation

logger = getActionLogger('yunohost.repository')
REPOSITORIES_DIR = '/etc/yunohost/repositories'
REPOSITORY_CONFIG_PATH = "/usr/share/yunohost/other/config_repository.toml"

# TODO i18n
# TODO split COnfigPanel.get to extract "Format result" part and be able to override it
# TODO Migration
# TODO Remove BackupRepository.get_or_create()
# TODO Backup method
# TODO auto test F2F by testing .well-known url
# TODO API params to get description of forms
# TODO tests
# TODO detect external hard drive already mounted and suggest it
# TODO F2F client detection / add / update / delete
# TODO F2F server

class BackupRepository(ConfigPanel):
    """
    BackupRepository manage all repository the admin added to the instance
    """
    @classmethod
    def get(cls, shortname):
        # FIXME
        if name not in cls.repositories:
            raise YunohostError('backup_repository_doesnt_exists', name=name)

        return cls.repositories[name]

    def __init__(self, repository):
        self.repository = repository
        self.save_mode = "full"
        super().__init__(
            config_path=REPOSITORY_CONFIG_PATH,
            save_path=f"{REPOSITORIES_DIR}/{repository}.yml",
        )

        #self.method = BackupMethod.get(method, self)

    def _get_default_values(self):
        values = super()._get_default_values()
        values["public_key"] = get_ssh_public_key()
        return values

    def list(self, with_info=False):
        return self.method.list(with_info)

    def compute_space_used(self):
        if self.used is None:
            try:
                self.used = self.method.compute_space_used()
            except (AttributeError, NotImplementedError):
                self.used = 'unknown'
        return self.used

    def purge(self):
        # TODO F2F delete
        self.method.purge()

    def delete(self, purge=False):

        if purge:
            self.purge()

        os.system("rm -rf {REPOSITORY_SETTINGS_DIR}/{self.repository}.yml")


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


def backup_repository_list(full=False):
    """
    List available repositories where put archives
    """

    try:
        repositories = [f.rstrip(".yml")
                        for f in os.listdir(REPOSITORIES_DIR)
                        if os.path.isfile(f) and f.endswith(".yml")]
    except FileNotFoundError:
        repositories = []

    if not full:
        return repositories

    # FIXME: what if one repo.yml is corrupted ?
    repositories = {repo: BackupRepository(repo).get(mode="export")
                    for repo in repositories}

    return repositories


def backup_repository_info(shortname, human_readable=True, space_used=False):
    """
    Show info about a repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    Question.operation_logger = operation_logger
    repository = BackupRepository(shortname)
    # TODO
    if space_used:
        repository.compute_space_used()

    repository = repository.get(
        mode="export"
    )

    if human_readable:
        if 'quota' in repository:
            repository['quota'] = binary_to_human(repository['quota'])
        if 'used' in repository and isinstance(repository['used'], int):
            repository['used'] = binary_to_human(repository['used'])

    return repository


@is_unit_operation()
def backup_repository_add(operation_logger, shortname, name=None, location=None,
                          method=None, quota=None, passphrase=None,
                          alert=[], alert_delay=7):
    """
    Add a backup repository

    Keyword arguments:
        location -- Location of the repository (could be a remote location)
        shortname -- Name of the backup repository
        name -- An optionnal description
        quota -- Maximum size quota of the repository
        encryption -- If available, the kind of encryption to use
    """
    # FIXME i18n
    # Deduce some value from location
    args = {}
    args['description'] = name
    args['creation'] = True
    if location:
        args["location"] = location
        args["is_remote"] = True
        args["method"] = method if method else "borg"
        domain_re = '^([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,})$'
        if re.match(domain_re, location):
            args["is_f2f"] = True
        elif location[0] != "/":
            args["is_f2f"] = False
        else:
            args["is_remote"] = False
            args["method"] = method
    elif method == "tar":
        args["is_remote"] = False
    if not location:
        args["method"] = method

    args["quota"] = quota
    args["passphrase"] = passphrase
    args["alert"]= ",".join(alert) if alert else None
    args["alert_delay"]= alert_delay

    # TODO validation
    # TODO activate service in apply (F2F or not)
    Question.operation_logger = operation_logger
    repository = BackupRepository(shortname)
    return repository.set(
        args=urllib.parse.urlencode(args),
        operation_logger=operation_logger
    )


@is_unit_operation()
def backup_repository_update(operation_logger, shortname, name=None,
                             quota=None, passphrase=None,
                             alert=[], alert_delay=None):
    """
    Update a backup repository

    Keyword arguments:
        name -- Name of the backup repository
    """

    args = {}
    args['creation'] = False
    if name:
        args['description'] = name
    if quota:
        args["quota"] = quota
    if passphrase:
        args["passphrase"] = passphrase
    if alert is not None:
        args["alert"]= ",".join(alert) if alert else None
    if alert_delay:
        args["alert_delay"]= alert_delay

    # TODO validation
    # TODO activate service in apply
    Question.operation_logger = operation_logger
    repository = BackupRepository(shortname)
    return repository.set(
        args=urllib.parse.urlencode(args),
        operation_logger=operation_logger
    )


@is_unit_operation()
def backup_repository_remove(operation_logger, shortname, purge=False):
    """
    Remove a backup repository

    Keyword arguments:
        name -- Name of the backup repository to remove

    """
    BackupRepository(shortname).delete(purge)
    logger.success(m18n.n('backup_repository_removed', repository=shortname,
                        path=repository['path']))
