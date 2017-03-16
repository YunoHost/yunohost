# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2016 YUNOHOST.ORG

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

    yunohost_certificate.py

    Manage certificates, in particular Let's encrypt
"""

import os
import errno
import pwd
import grp
import requests
import subprocess
import socket
import glob

import json

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.io')


def _read_file(file_path):
    """
    Read a regular text file

    Keyword argument:
        file_path -- Path to the json file
    """
    assert isinstance(file_path, str)

    # Check file exist
    if not os.path.isfile(file_path):
        raise MoulinetteError(errno.EROENT,
                              m18n.n('io_no_such_file', file=file_path))

    # Open file and read content
    try:
        with open(file_path, "r") as f:
            file_content = f.read()
    except IOError as e:
        raise MoulinetteError(errno.EACCES,
                              m18n.n('io_cannot_open_file', file=file_path))
    except Exception as e:
        raise MoulinetteError(errno.EIO,
                              m18n.n('io_unknown_error_opening_file',
                                     file=file_path, error=str(e)))

    return file_content


def _read_json(file_path):
    """
    Read a json file

    Keyword argument:
        file_path -- Path to the json file
    """
    assert isinstance(file_path, str)

    # Read file
    file_content = _read_file(file_path)

    # Try to load json to check if it's syntaxically correct
    try:
        loaded_json = json.loads(file_content)
    except ValueError:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('io_corrupted_json', file=file_path))

    return loaded_json


def _write_json(file_path, input_dict):
    """
    Write a dictionnary to a json file

    Keyword argument:
        file_path -- Path to the json file
        input_dict -- The dictionnary to write
    """

    # Assumptions
    assert isinstance(file_path, str)
    assert isinstance(input_dict, dict)

    # Write dict to file
    try:
        with open(file_path, "w") as f:
            json.dump(input_dict, f)
    except IOError as e:
        raise MoulinetteError(errno.EACCES,
                              m18n.n('io_cannot_write_file', file=file_path))
    except Exception as e:
        raise MoulinetteError(errno.EIO,
                              m18n.n('io_unknown_error_writing_file',
                                     file=file_path, error=str(e)))


def _remove_file(file_path):
    """
    Remove a regular file if it exists

    Keyword argument:
        file_path -- Path of the file to remove
    """
    # Assumptions
    assert isinstance(file_path, str)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            raise MoulinetteError(errno.EIO,
                                  m18n.n('io_unknown_error_removing_file',
                                         file=file_path, error=str(e)))


def _set_permissions(file_path, user, group, permissions):
    """
    Change permissions of a given file.
    Example : _set_permissions("/etc/swag", "root", "www-data", 0750)

    Keyword argument:
        file_path -- Path to the json file
        user -- Some user name
        group -- Some unix group name
        permissions -- Permissions to set, preferrably in octal format
    """
    # Assumptions
    assert isinstance(file_path, str)
    assert isinstance(user, str)
    assert isinstance(group, str)
    assert isinstance(permissions, int)

    # Check file exist
    if not os.path.isfile(file_path):
        raise MoulinetteError(errno.EROENT,
                              m18n.n('io_no_such_file', file=file_path))

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    os.chown(file_path, uid, gid)
    os.chmod(file_path, permissions)


def _download_text_data(url):
    """
    Download text from a url and returns the raw text

    Keyword argument:
        url -- The url to download the data from
    """
    # Assumptions
    assert isinstance(file_path, str)

    # Download file
    try:
        r = requests.get(url, timeout=30)
    # SSL exceptions
    except requests.exceptions.SSLError:
        raise MoulinetteError(errno.EBADE,
                              m18n.n('io_download_ssl_error',
                                     url=url))
    # Timeout exceptions
    except requests.exceptions.Timeout:
        raise MoulinetteError(errno.ETIME,
                              m18n.n('io_download_timeout',
                                     url=url))
    # Unknown stuff
    except Exception:
        raise MoulinetteError(errno.ECONNRESET,
                              m18n.n('io_download_unknown_error',
                                     url=url))
    # Assume error if status code is not 200 (OK)
    if r.status_code != 200:
        raise MoulinetteError(errno.EBADE,
                              m18n.n('io_download_bad_status_code',
                                     url=url, code=r.status_code))

    return r.text


def _run_shell_commands(command_list):

    # Still very work in progress
    # Maybe have another argument to know what exception to raise if something
    # goes wrong ?

    for command in command_list:
        p = subprocess.Popen(command_list.split(),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        out, _ = p.communicate()

        if p.returncode != 0:
            logger.warning(out)
            raise MoulinetteError(errno.EIO,
                                  m18n.n('io_error_running_shell_command'))
        else:
            logger.info(out)
