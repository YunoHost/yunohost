#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
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
import pytest
import requests
import requests_mock
import pwd
import grp

from moulinette import m18n
from yunohost.utils.error import YunohostError
from yunohost.utils.file_utils import (
    append_to_file,
    read_file,
    read_json,
    read_yaml,
    read_toml,
    rm,
    write_to_file,
    write_to_json,
    write_to_yaml,
    mkdir,
    chown,
    chmod,
    download_json,
    download_text
)


def test_read_file(test_file):
    content = read_file(str(test_file))
    assert content == "foo\nbar\n"


def test_read_file_missing_file():
    bad_file = "doesnt-exist"

    with pytest.raises(YunohostError) as exception:
        read_file(bad_file)

    translation = m18n.n("file_not_exist", path=bad_file)
    expected_msg = translation.format(path=bad_file)
    assert expected_msg in str(exception)


def test_read_file_cannot_read_ioerror(test_file, mocker):
    error = "foobar"

    mocker.patch("builtins.open", side_effect=IOError(error))
    with pytest.raises(YunohostError) as exception:
        read_file(str(test_file))

    translation = m18n.n("cannot_open_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_read_file_cannot_read_exception(test_file, mocker):
    error = "foobar"

    mocker.patch("builtins.open", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        read_file(str(test_file))

    translation = m18n.n("unknown_error_reading_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_read_json(test_json):
    content = read_json(str(test_json))
    assert "foo" in content.keys()
    assert content["foo"] == "bar"


def test_read_json_cannot_read(test_json, mocker):
    error = "foobar"

    mocker.patch("json.loads", side_effect=ValueError(error))
    with pytest.raises(YunohostError) as exception:
        read_json(str(test_json))

    translation = m18n.n("corrupted_json", ressource=str(test_json), error=error)
    expected_msg = translation.format(ressource=str(test_json), error=error)
    assert expected_msg in exception.value.content()


def test_read_yaml(test_yaml):
    content = read_yaml(str(test_yaml))
    assert "foo" in content.keys()
    assert content["foo"] == "bar"


def test_read_yaml_cannot_read(test_yaml, mocker):
    error = "foobar"

    mocker.patch("yaml.safe_load", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        read_yaml(str(test_yaml))

    translation = m18n.n("corrupted_yaml", ressource=str(test_yaml), error=error)
    expected_msg = translation.format(ressource=str(test_yaml), error=error)
    assert expected_msg in exception.value.content()


def test_read_toml(test_toml):
    content = read_toml(str(test_toml))
    assert "foo" in content.keys()
    assert content["foo"] == "bar"


def test_read_toml_cannot_read(test_toml, mocker):
    error = "foobar"

    mocker.patch("toml.loads", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        read_toml(str(test_toml))

    translation = m18n.n("corrupted_toml", ressource=str(test_toml), error=error)
    expected_msg = translation.format(ressource=str(test_toml), error=error)
    assert expected_msg in exception.value.content()


def test_write_to_existing_file(test_file):
    write_to_file(str(test_file), "yolo\nswag")
    assert read_file(str(test_file)) == "yolo\nswag"


def test_write_to_new_file(tmp_path):
    new_file = tmp_path / "newfile.txt"

    write_to_file(str(new_file), "yolo\nswag")

    assert os.path.exists(str(new_file))
    assert read_file(str(new_file)) == "yolo\nswag"


def test_write_to_existing_file_bad_perms(test_file, mocker):
    error = "foobar"

    mocker.patch("builtins.open", side_effect=IOError(error))
    with pytest.raises(YunohostError) as exception:
        write_to_file(str(test_file), "yolo\nswag")

    translation = m18n.n("cannot_write_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_write_to_file_exception(test_file, mocker):
    error = "foobar"

    mocker.patch("builtins.open", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        write_to_file(str(test_file), "yolo\nswag")

    translation = m18n.n("error_writing_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_write_cannot_write_folder(tmp_path):
    with pytest.raises(AssertionError):
        write_to_file(str(tmp_path), "yolo\nswag")


def test_write_cannot_write_to_non_existant_folder():
    with pytest.raises(AssertionError):
        write_to_file("/toto/test", "yolo\nswag")


def test_write_to_file_with_a_list(test_file):
    write_to_file(str(test_file), ["yolo", "swag"])
    assert read_file(str(test_file)) == "yolo\nswag"


def test_append_to_existing_file(test_file):
    append_to_file(str(test_file), "yolo\nswag")
    assert read_file(str(test_file)) == "foo\nbar\nyolo\nswag"


def test_append_to_new_file(tmp_path):
    new_file = tmp_path / "newfile.txt"

    append_to_file(str(new_file), "yolo\nswag")

    assert os.path.exists(str(new_file))
    assert read_file(str(new_file)) == "yolo\nswag"


def test_write_dict_to_json(tmp_path):
    new_file = tmp_path / "newfile.json"

    dummy_dict = {"foo": 42, "bar": ["a", "b", "c"]}
    write_to_json(str(new_file), dummy_dict)
    _json = read_json(str(new_file))

    assert "foo" in _json.keys()
    assert "bar" in _json.keys()

    assert _json["foo"] == 42
    assert _json["bar"] == ["a", "b", "c"]


def test_write_json_to_existing_file_bad_perms(test_file, mocker):
    error = "foobar"

    dummy_dict = {"foo": 42, "bar": ["a", "b", "c"]}

    mocker.patch("builtins.open", side_effect=IOError(error))
    with pytest.raises(YunohostError) as exception:
        write_to_json(str(test_file), dummy_dict)

    translation = m18n.n("cannot_write_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_write_json_to_file_exception(test_file, mocker):
    error = "foobar"

    dummy_dict = {"foo": 42, "bar": ["a", "b", "c"]}

    mocker.patch("builtins.open", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        write_to_json(str(test_file), dummy_dict)

    translation = m18n.n("error_writing_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def text_write_list_to_json(tmp_path):
    new_file = tmp_path / "newfile.json"

    dummy_list = ["foo", "bar", "baz"]
    write_to_json(str(new_file), dummy_list)

    _json = read_json(str(new_file))
    assert _json == ["foo", "bar", "baz"]


def test_write_to_json_bad_perms(test_json, mocker):
    error = "foobar"

    mocker.patch("builtins.open", side_effect=IOError(error))
    with pytest.raises(YunohostError) as exception:
        write_to_json(str(test_json), {"a": 1})

    translation = m18n.n("cannot_write_file", file=str(test_json), error=error)
    expected_msg = translation.format(file=str(test_json), error=error)
    assert expected_msg in exception.value.content()


def test_write_json_cannot_write_to_non_existant_folder():
    with pytest.raises(AssertionError):
        write_to_json("/toto/test.json", ["a", "b"])


def test_write_dict_to_yaml(tmp_path):
    new_file = tmp_path / "newfile.yaml"

    dummy_dict = {"foo": 42, "bar": ["a", "b", "c"]}
    write_to_yaml(str(new_file), dummy_dict)
    _yaml = read_yaml(str(new_file))

    assert "foo" in _yaml.keys()
    assert "bar" in _yaml.keys()

    assert _yaml["foo"] == 42
    assert _yaml["bar"] == ["a", "b", "c"]


def test_write_yaml_to_existing_file_bad_perms(test_file, mocker):
    error = "foobar"

    dummy_dict = {"foo": 42, "bar": ["a", "b", "c"]}

    mocker.patch("builtins.open", side_effect=IOError(error))
    with pytest.raises(YunohostError) as exception:
        write_to_yaml(str(test_file), dummy_dict)

    translation = m18n.n("cannot_write_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_write_yaml_to_file_exception(test_file, mocker):
    error = "foobar"

    dummy_dict = {"foo": 42, "bar": ["a", "b", "c"]}

    mocker.patch("builtins.open", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        write_to_yaml(str(test_file), dummy_dict)

    translation = m18n.n("error_writing_file", file=str(test_file), error=error)
    expected_msg = translation.format(file=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def text_write_list_to_yaml(tmp_path):
    new_file = tmp_path / "newfile.yaml"

    dummy_list = ["foo", "bar", "baz"]
    write_to_yaml(str(new_file), dummy_list)

    _yaml = read_yaml(str(new_file))
    assert _yaml == ["foo", "bar", "baz"]


def test_write_to_yaml_bad_perms(test_yaml, mocker):
    error = "foobar"

    mocker.patch("builtins.open", side_effect=IOError(error))
    with pytest.raises(YunohostError) as exception:
        write_to_yaml(str(test_yaml), {"a": 1})

    translation = m18n.n("cannot_write_file", file=str(test_yaml), error=error)
    expected_msg = translation.format(file=str(test_yaml), error=error)
    assert expected_msg in exception.value.content()


def test_write_yaml_cannot_write_to_non_existant_folder():
    with pytest.raises(AssertionError):
        write_to_yaml("/toto/test.yaml", ["a", "b"])


def test_mkdir(tmp_path):
    new_path = tmp_path / "new_folder"
    mkdir(str(new_path))

    assert os.path.isdir(str(new_path))
    assert oct(os.stat(str(new_path)).st_mode & 0o777) == oct(0o777)


def test_mkdir_with_permission(tmp_path, mocker):
    # This test only make sense when not being root
    if os.getuid() == 0:
        return

    new_path = tmp_path / "new_folder"
    permission = 0o700
    mkdir(str(new_path), mode=permission)

    assert os.path.isdir(str(new_path))
    assert oct(os.stat(str(new_path)).st_mode & 0o777) == oct(permission)

    new_path = tmp_path / "new_parent2" / "new_folder"

    with pytest.raises(OSError):
        mkdir(str(new_path), parents=True, mode=0o000)


def test_mkdir_with_parent(tmp_path):
    new_path = tmp_path / "new_folder"
    mkdir(str(new_path) + "/", parents=True)

    assert os.path.isdir(str(new_path))

    new_path = tmp_path / "new_parent" / "new_folder"
    mkdir(str(new_path), parents=True)

    assert os.path.isdir(str(new_path))


def test_mkdir_existing_folder(tmp_path):
    new_path = tmp_path / "new_folder"
    os.makedirs(str(new_path))
    with pytest.raises(Exception):
        mkdir(str(new_path))


def test_chown(test_file):
    with pytest.raises(ValueError):
        chown(str(test_file))

    current_uid = os.getuid()
    current_gid = os.getgid()
    chown(str(test_file), current_uid, current_gid)

    assert os.stat(str(test_file)).st_uid == current_uid
    assert os.stat(str(test_file)).st_gid == current_gid

    current_gid = os.getgid()
    chown(str(test_file), uid=None, gid=current_gid)

    assert os.stat(str(test_file)).st_gid == current_gid

    current_uid = pwd.getpwuid(os.getuid())[0]
    current_gid = grp.getgrgid(os.getgid())[0]
    chown(str(test_file), current_uid, current_gid)

    assert os.stat(str(test_file)).st_uid == os.getuid()
    assert os.stat(str(test_file)).st_gid == os.getgid()

    fake_user = "nousrlol"
    with pytest.raises(YunohostError) as exception:
        chown(str(test_file), fake_user)

    translation = m18n.n("unknown_user", user=fake_user)
    expected_msg = translation.format(user=fake_user)
    assert expected_msg in exception.value.content()

    fake_grp = "nogrplol"
    with pytest.raises(YunohostError) as exception:
        chown(str(test_file), gid=fake_grp)

    translation = m18n.n("unknown_group", group=fake_grp)
    expected_msg = translation.format(group=fake_grp)
    assert expected_msg in exception.value.content()


def test_chown_recursive(test_file):
    current_uid = os.getuid()
    dirname = os.path.dirname(str(test_file))
    mkdir(os.path.join(dirname, "new_dir"))
    chown(str(dirname), current_uid, recursive=True)

    assert os.stat(str(dirname)).st_uid == current_uid


def test_chown_exception(test_file, mocker):
    error = "foobar"

    mocker.patch("os.chown", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        chown(str(test_file), 1)

    translation = m18n.n(
        "error_changing_file_permissions", path=str(test_file), error=str(error)
    )
    expected_msg = translation.format(path=str(test_file), error=str(error))
    assert expected_msg in exception.value.content()


def test_chmod(test_file):
    permission = 0o723
    chmod(str(test_file), permission)

    assert oct(os.stat(str(test_file)).st_mode & 0o777) == oct(permission)

    dirname = os.path.dirname(str(test_file))
    permission = 0o722
    chmod(str(dirname), permission, recursive=True)

    assert oct(os.stat(str(test_file)).st_mode & 0o777) == oct(permission)
    assert oct(os.stat(dirname).st_mode & 0o777) == oct(permission)


def test_chmod_recursive(test_file):
    dirname = os.path.dirname(str(test_file))
    mkdir(os.path.join(dirname, "new_dir"))
    permission = 0o721
    fpermission = 0o720
    chmod(str(dirname), permission, fmode=fpermission, recursive=True)

    assert oct(os.stat(str(test_file)).st_mode & 0o777) == oct(fpermission)
    assert oct(os.stat(dirname).st_mode & 0o777) == oct(permission)


def test_chmod_exception(test_file, mocker):
    error = "foobar"

    mocker.patch("os.chmod", side_effect=Exception(error))
    with pytest.raises(YunohostError) as exception:
        chmod(str(test_file), 0o000)

    translation = m18n.n(
        "error_changing_file_permissions", path=str(test_file), error=str(error)
    )
    expected_msg = translation.format(path=str(test_file), error=str(error))
    assert expected_msg in exception.value.content()


def test_remove_file(test_file):
    assert os.path.exists(str(test_file))
    rm(str(test_file))
    assert not os.path.exists(str(test_file))


def test_remove_file_bad_perms(test_file, mocker):
    error = "foobar"

    mocker.patch("os.remove", side_effect=OSError(error))
    with pytest.raises(YunohostError) as exception:
        rm(str(test_file))

    translation = m18n.n("error_removing", path=str(test_file), error=error)
    expected_msg = translation.format(path=str(test_file), error=error)
    assert expected_msg in exception.value.content()


def test_remove_directory(tmp_path):
    test_dir = tmp_path / "foo"
    test_dir.mkdir()

    assert os.path.exists(str(test_dir))
    rm(str(test_dir), recursive=True)
    assert not os.path.exists(str(test_dir))


def test_download(test_url):
    with requests_mock.Mocker() as mock:
        mock.register_uri("GET", test_url, text="some text")
        fetched_text = download_text(test_url)
    assert fetched_text == "some text"


def test_download_bad_url():
    with pytest.raises(YunohostError):
        download_text("Nowhere")


def test_download_404(test_url):
    with requests_mock.Mocker() as mock:
        mock.register_uri("GET", test_url, status_code=404)
        with pytest.raises(YunohostError):
            download_text(test_url)


def test_download_ssl_error(test_url):
    with requests_mock.Mocker() as mock:
        exception = requests.exceptions.SSLError
        mock.register_uri("GET", test_url, exc=exception)
        with pytest.raises(YunohostError):
            download_text(test_url)


def test_download_connection_error(test_url):
    with requests_mock.Mocker() as mock:
        exception = requests.exceptions.ConnectionError
        mock.register_uri("GET", test_url, exc=exception)
        with pytest.raises(YunohostError):
            download_text(test_url)


def test_download_timeout(test_url):
    with requests_mock.Mocker() as mock:
        exception = requests.exceptions.Timeout
        mock.register_uri("GET", test_url, exc=exception)
        with pytest.raises(YunohostError):
            download_text(test_url)


def test_download_json(test_url):
    with requests_mock.Mocker() as mock:
        mock.register_uri("GET", test_url, text='{"foo":"bar"}')
        fetched_json = download_json(test_url)
    assert "foo" in fetched_json.keys()
    assert fetched_json["foo"] == "bar"


def test_download_json_bad_json(test_url):
    with requests_mock.Mocker() as mock:
        mock.register_uri("GET", test_url, text="notjsonlol")
        with pytest.raises(YunohostError):
            download_json(test_url)
