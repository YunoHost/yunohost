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

BACKUP_PATH = '/home/yunohost.backup'
ARCHIVES_PATH = '%s/archives' % BACKUP_PATH
logger = getActionLogger('yunohost.backup')


def backup_repository_list(name):
    """
    List available repositories where put archives
    """
    pass

def backup_repository_info(name, human_readable=True, space_used=False):
    """
    Show info about a repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    pass

def backup_repository_add(name, path, name, description=None, methods=None,
                          quota=None, encryption="passphrase"):
    """
    Add a backup repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    pass

def backup_repository_update(name, description=None, quota=None, password=None):
    """
    Update a backup repository

    Keyword arguments:
        name -- Name of the backup repository
    """
    pass

def backup_repository_remove(name):
    """
    Remove a backup repository

    Keyword arguments:
        name -- Name of the backup repository to remove

    """
    pass
