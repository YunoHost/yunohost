#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
import yaml
import toml
import errno
import shutil
import json
from pathlib import Path
from typing import Any, TextIO
from collections import OrderedDict

from .error import YunohostError

Jsonable = (
    str | int | float | bool | None | dict["Jsonable", "Jsonable"] | list["Jsonable"]
)


def read_file(file_path: str) -> str:
    """
    Read a regular text file

    Keyword argument:
        file_path -- Path to the text file
    """
    assert isinstance(file_path, str), (
        "Error: file_path '{}' should be a string but is of type '{}' instead".format(
            file_path,
            type(file_path),
        )
    )

    # Check file exists
    if not os.path.isfile(file_path):
        raise YunohostError("file_not_exist", path=file_path)

    # Open file and read content
    try:
        with open(file_path, "r") as f:
            file_content = f.read()
    except IOError as e:
        raise YunohostError("cannot_open_file", file=file_path, error=str(e))
    except Exception as e:
        raise YunohostError("unknown_error_reading_file", file=file_path, error=str(e))

    return file_content


def read_json(file_path: str) -> Jsonable:
    """
    Read a json file

    Keyword argument:
        file_path -- Path to the json file
    """

    # Read file
    file_content = read_file(file_path)

    # Try to load json to check if it's syntaxically correct
    try:
        loaded_json = json.loads(file_content)
    except ValueError as e:
        raise YunohostError("corrupted_json", ressource=file_path, error=str(e))

    return loaded_json


def read_yaml(file_: str | Path | TextIO) -> Jsonable:
    """
    Safely read a yaml file

    Keyword argument:
        file -- Path or stream to the yaml file
    """

    # Read file
    file_path = file_ if isinstance(file_, str) else file_.name
    file_content = read_file(file_) if isinstance(file_, str) else file_

    # Try to load yaml to check if it's syntaxically correct
    try:
        loaded_yaml = yaml.safe_load(file_content)  # type: ignore[arg-type]
    except Exception as e:
        raise YunohostError("corrupted_yaml", ressource=file_path, error=str(e))

    return loaded_yaml


def read_toml(file_path: str) -> Jsonable:
    """
    Safely read a toml file

    Keyword argument:
        file_path -- Path to the toml file
    """

    # Read file
    file_content = read_file(file_path)

    # Try to load toml to check if it's syntactically correct
    try:
        loaded_toml = toml.loads(file_content, _dict=OrderedDict)
    except Exception as e:
        raise YunohostError("corrupted_toml", ressource=file_path, error=str(e))

    return loaded_toml


def write_to_file(
    file_path: str, data: str | bytes | list, file_mode: str = "w"
) -> None:
    """
    Write a single string or a list of string to a text file.
    The text file will be overwritten by default.

    Keyword argument:
        file_path -- Path to the output file
        data -- The data to write (must be a string or list of string)
        file_mode -- Mode used when writing the file. Option meant to be used
        by append_to_file to avoid duplicating the code of this function.
    """
    assert isinstance(data, str) or isinstance(data, bytes) or isinstance(data, list), (
        f"Error: data '{str(data)}' should be either a string or a list but is of type '{type(data)}'"
    )
    assert not os.path.isdir(file_path), (
        "Error: file_path '%s' point to a dir, it should be a file" % file_path
    )
    assert os.path.isdir(os.path.dirname(file_path)), (
        "Error: the path ('{}') base dir ('{}') is not a dir".format(
            file_path,
            os.path.dirname(file_path),
        )
    )

    # If data is a list, check elements are strings and build a single string
    if isinstance(data, list):
        for element in data:
            assert isinstance(element, str), (
                "Error: element '{}' should be a string but is of type '{}' instead".format(
                    element,
                    type(element),
                )
            )
        data = "\n".join(data)

    try:
        with open(file_path, file_mode) as f:
            f.write(data)
    except IOError as e:
        raise YunohostError("cannot_write_file", file=file_path, error=str(e))
    except Exception as e:
        raise YunohostError("error_writing_file", file=file_path, error=str(e))


def append_to_file(file_path: str, data: str | bytes | list) -> None:
    """
    Append a single string or a list of string to a text file.

    Keyword argument:
        file_path -- Path to the output file
        data -- The data to write (must be a string or list of string)
    """

    write_to_file(file_path, data, file_mode="a")


def write_to_json(
    file_path: str, data: Jsonable, sort_keys: bool = False, indent: int | None = None
) -> None:
    """
    Write a dictionnary or a list to a json file

    Keyword argument:
        file_path -- Path to the output json file
        data -- The data to write (must be a dict or a list)
    """

    # Assumptions
    assert isinstance(file_path, str), (
        "Error: file_path '{}' should be a string but is of type '{}' instead".format(
            file_path,
            type(file_path),
        )
    )
    assert isinstance(data, dict) or isinstance(data, list), (
        "Error: data '{}' should be a dict or a list but is of type '{}' instead".format(
            data,
            type(data),
        )
    )
    assert not os.path.isdir(file_path), (
        "Error: file_path '%s' point to a dir, it should be a file" % file_path
    )
    assert os.path.isdir(os.path.dirname(file_path)), (
        "Error: the path ('{}') base dir ('{}') is not a dir".format(
            file_path,
            os.path.dirname(file_path),
        )
    )

    # Write dict to file
    try:
        with open(file_path, "w") as f:
            json.dump(data, f, sort_keys=sort_keys, indent=indent)
    except IOError as e:
        raise YunohostError("cannot_write_file", file=file_path, error=str(e))
    except Exception as e:
        raise YunohostError("error_writing_file", file=file_path, error=str(e))


def write_to_yaml(file_path: str, data: Jsonable) -> None:
    """
    Write a dictionnary or a list to a yaml file

    Keyword argument:
        file_path -- Path to the output yaml file
        data -- The data to write (must be a dict or a list)
    """
    # Assumptions
    assert isinstance(file_path, str)
    assert isinstance(data, dict) or isinstance(data, list)
    assert not os.path.isdir(file_path)
    assert os.path.isdir(os.path.dirname(file_path))

    # Write dict to file
    try:
        with open(file_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False)
    except IOError as e:
        raise YunohostError("cannot_write_file", file=file_path, error=str(e))
    except Exception as e:
        raise YunohostError("error_writing_file", file=file_path, error=str(e))


def mkdir(
    path: str,
    mode: int = 0o0777,
    parents: bool = False,
    uid: str | int | None = None,
    gid: str | int | None = None,
    force: bool = False,
) -> None:
    """Create a directory with optional features

    Create a directory and optionaly set its permissions to mode and its
    owner and/or group. If path refers to an existing path, nothing is done
    unless force is True.

    Keyword arguments:
        - path -- The directory to create
        - mode -- Numeric path mode to set
        - parents -- Make parent directories as needed
        - uid -- Numeric uid or user name
        - gid -- Numeric gid or group name
        - force -- Force directory creation and owning even if the path exists

    """
    if os.path.exists(path) and not force:
        raise Exception(f"Folder {path} already exists")

    if parents:
        # Create parents directories as needed
        head, tail = os.path.split(path)
        if not tail:
            head, tail = os.path.split(head)
        if head and tail and not os.path.exists(head):
            try:
                mkdir(head, mode, parents, uid, gid, force)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
            if tail == os.curdir:
                return

    # Create directory and set permissions
    try:
        oldmask = os.umask(000)
        os.mkdir(path, mode)
        os.umask(oldmask)
    except OSError:
        # mimic Python3.2+ os.makedirs exist_ok behaviour
        if not force or not os.path.isdir(path):
            raise

    if uid is not None or gid is not None:
        chown(path, uid, gid)


def chown(
    path: str,
    uid: str | int | None = None,
    gid: str | int | None = None,
    recursive: bool = False,
) -> None:
    """Change the owner and/or group of a path

    Keyword arguments:
        - uid -- Numeric uid or user name
        - gid -- Numeric gid or group name
        - recursive -- Operate on path recursively

    """

    from pwd import getpwnam
    import grp

    if uid is None and gid is None:
        raise ValueError("either uid or gid argument is required")

    # Retrieve uid/gid
    if isinstance(uid, str):
        try:
            uid = getpwnam(uid).pw_uid
        except KeyError:
            raise YunohostError("unknown_user", user=uid)
    elif uid is None:
        uid = -1
    if isinstance(gid, str):
        try:
            gid = grp.getgrnam(gid).gr_gid
        except KeyError:
            raise YunohostError("unknown_group", group=gid)
    elif gid is None:
        gid = -1

    try:
        os.chown(path, uid, gid)
        if recursive and os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)
    except Exception as e:
        raise YunohostError("error_changing_file_permissions", path=path, error=str(e))


def chmod(
    path: str, mode: int, fmode: int | None = None, recursive: bool = False
) -> None:
    """Change the mode of a path

    Keyword arguments:
        - mode -- Numeric path mode to set
        - fmode -- Numeric file mode to set in case of a recursive directory
        - recursive -- Operate on path recursively

    """

    try:
        os.chmod(path, mode)
        if recursive and os.path.isdir(path):
            if fmode is None:
                fmode = mode
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), mode)
                for f in files:
                    os.chmod(os.path.join(root, f), fmode)
    except Exception as e:
        raise YunohostError("error_changing_file_permissions", path=path, error=str(e))


def rm(path: str, recursive: bool = False, force: bool = False) -> None:
    """Remove a file or directory

    Keyword arguments:
        - path -- The path to remove
        - recursive -- Remove directories and their contents recursively
        - force -- Ignore nonexistent files

    """
    if recursive and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=force)
    else:
        try:
            os.remove(path)
        except OSError as e:
            if not force:
                raise YunohostError("error_removing", path=path, error=str(e))


def cp(source: str, dest: str, recursive: bool = False, **kwargs: Any) -> str:
    if recursive and os.path.isdir(source):
        return shutil.copytree(source, dest, symlinks=True, **kwargs)
    else:
        return shutil.copy2(source, dest, follow_symlinks=False, **kwargs)


def download_text(url: str, timeout: int = 30, expected_status_code: int = 200) -> str:
    """
    Download text from a url and returns the raw text

    Keyword argument:
        url -- The url to download the data from
        timeout -- Number of seconds allowed for download to effectively start
        before giving up
        expected_status_code -- Status code expected from the request. Can be
        None to ignore the status code.
    """
    import requests  # lazy loading this module for performance reasons

    # Assumptions
    assert isinstance(url, str)

    # Download file
    try:
        r = requests.get(url, timeout=timeout)
    # SSL exceptions
    except requests.exceptions.SSLError:
        raise YunohostError("download_ssl_error", url=url)
    # Invalid URL
    except requests.exceptions.ConnectionError:
        raise YunohostError("invalid_url", url=url)
    # Timeout exceptions
    except requests.exceptions.Timeout:
        raise YunohostError("download_timeout", url=url)
    # Unknown stuff
    except Exception as e:
        raise YunohostError("download_unknown_error", url=url, error=str(e))
    # Assume error if status code is not 200 (OK)
    if expected_status_code is not None and r.status_code != expected_status_code:
        raise YunohostError(
            "download_bad_status_code", url=url, code=str(r.status_code)
        )

    return r.text


def download_json(
    url: str, timeout: int = 30, expected_status_code: int = 200
) -> Jsonable:
    """
    Download json from a url and returns the loaded json object

    Keyword argument:
        url -- The url to download the data from
        timeout -- Number of seconds allowed for download to effectively start
        before giving up
    """
    # Fetch the data
    text = download_text(url, timeout, expected_status_code)

    # Try to load json to check if it's syntaxically correct
    try:
        loaded_json = json.loads(text)
    except ValueError as e:
        raise YunohostError("corrupted_json", ressource=url, error=str(e))

    return loaded_json
