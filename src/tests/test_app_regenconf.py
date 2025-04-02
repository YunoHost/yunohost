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

import glob
import os
import pytest

from moulinette.utils.filesystem import read_file, write_to_file
from yunohost.app import app_setting, _get_app_settings, _set_app_settings
from yunohost.utils.error import YunohostError
from yunohost.utils.configurations import (
    BaseConfiguration,
    ConfigurationClassesByType,
    AppConfigurationsManager,
    DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED,
)
from .conftest import message


class DummyAppConfiguration(BaseConfiguration):

    type: str = "dummy"

    def __init__(self, *args, **kwargs):

        # Default values for template and path
        if "template" not in kwargs:
            kwargs["template"] = "dummy.conf" if kwargs["id"] == "main" else "dummy-__CONF_ID__.conf"
        if "path" not in kwargs:
            kwargs["path"] = "/tmp/dummyconfs/" + ("__APP__.conf" if kwargs["id"] == "main" else "__APP__-__CONF_ID__.conf")

        super().__init__(*args, **kwargs)

    def reload():
        pass


ConfigurationClassesByType["dummy"] = DummyAppConfiguration


def setup_function(function):
    clean()

    os.system("mkdir /etc/yunohost/apps/testapp")
    os.system("mkdir /etc/yunohost/apps/testapp/conf")
    os.system("mkdir /tmp/dummyconfs/")
    os.system("echo 'id: testapp' > /etc/yunohost/apps/testapp/settings.yml")
    os.system("echo 'foo: bar' >> /etc/yunohost/apps/testapp/settings.yml")
    dummy_manifest = '\n'.join([
        'packaging_format = 3',
        'id = "testapp"',
        'version = "0.1"',
        'description.en = "A dummy app to test app resources"'
    ])
    write_to_file("/etc/yunohost/apps/testapp/manifest.toml", dummy_manifest)
    dummy_conf = '\n'.join([
        '# This is a dummy conf file',
        'APP = __APP__',
        'FOO = __FOO__'
    ])
    write_to_file("/etc/yunohost/apps/testapp/conf/dummy.conf", dummy_conf)


def teardown_function(function):
    clean()


def clean():
    os.system("rm -rf /etc/yunohost/apps/testapp")
    os.system("rm -rf /tmp/dummyconfs/")
    os.system(f"rm -rf {DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED}/testapp/")
    os.system("userdel testapp 2>/dev/null")


def test_conf_dummy_new():
    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    settings = _get_app_settings("testapp")
    assert settings.get("_configurations", {}).get("dummy.main")


def test_conf_dummy_remove():
    conf = "/tmp/dummyconfs/testapp.conf"
    settings = _get_app_settings("testapp")
    settings["_configurations"] = {"dummy.main": {"path": conf, "md5": "abcdef0123456789"}}
    _set_app_settings("testapp", settings)
    write_to_file(conf, "FOO = bar")
    assert os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted={}).apply()
    assert not os.path.exists(conf)


def test_conf_dummy_different_template():

    write_to_file("/etc/yunohost/apps/testapp/conf/dummy2.conf", "This is another template")
    wanted = {"configurations": {"dummy": {"main": {"template": "dummy2.conf"}}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" not in read_file(conf).strip()
    assert "This is another template" in read_file(conf).strip()


def test_conf_dummy_with_extra():

    write_to_file("/etc/yunohost/apps/testapp/conf/dummy-extra.conf", "This is another template")
    wanted = {"configurations": {"dummy": {"extra": {}}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    conf2 = "/tmp/dummyconfs/testapp-extra.conf"
    assert not os.path.exists(conf)
    assert not os.path.exists(conf2)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()
    assert "This is another template" in read_file(conf2).strip()


def test_conf_dummy_missingvar():

    app_setting("testapp", "foo", delete=True)
    wanted = {"configurations": {"dummy": {}}}

    with pytest.raises(YunohostError):
        with message("app_uninitialized_variables"):
            AppConfigurationsManager("testapp", wanted=wanted).apply()


def test_conf_dummy_update_after_var_change():

    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    app_setting("testapp", "foo", "nyah")

    wanted = {"configurations": {"dummy": {}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert "FOO = nyah" in read_file(conf).strip()


def test_conf_dummy_update_after_path_change():

    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    conf2 = "/tmp/dummyconfs/wat.conf"
    wanted = {"configurations": {"dummy": {"main": {"path": conf2}}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert not os.path.exists(conf)
    assert "FOO = bar" in read_file(conf2).strip()


def test_conf_dummy_update_after_template_change():

    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    write_to_file("/etc/yunohost/apps/testapp/conf/dummy.conf", "# This is the updated conf template")

    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert read_file(conf).strip() == "# This is the updated conf template"


def test_conf_dummy_manualchange_mergeable():

    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    write_to_file(conf, "# Manual comment on top of file\n" + read_file(conf))

    app_setting("testapp", "foo", "nyah")

    wanted = {"configurations": {"dummy": {}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert "# Manual comment on top of file" in read_file(conf).strip()
    assert "FOO = nyah" in read_file(conf).strip()

    backup_conf_glob = f"{DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED}/testapp/{conf}.backup.*"
    assert len(glob.glob(backup_conf_glob)) == 1
    backup_content = read_file(list(glob.glob(backup_conf_glob))[0])
    assert "# Manual comment on top of file" in backup_content
    assert "FOO = bar" in backup_content


def test_conf_dummy_manualchange_nonmergeable():

    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    write_to_file(conf, read_file(conf).replace("FOO = bar", "FOO = manual_value"))

    app_setting("testapp", "foo", "nyah")

    wanted = {"configurations": {"dummy": {}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert "FOO = nyah" in read_file(conf).strip()

    backup_conf_glob = f"{DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED}/testapp/{conf}.backup.*"
    assert len(glob.glob(backup_conf_glob)) == 1
    backup_content = read_file(list(glob.glob(backup_conf_glob))[0])
    assert "FOO = manual_value" in backup_content


def test_conf_dummy_dryrun():

    wanted = {"configurations": {"dummy": {}}}
    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "FOO = bar" in read_file(conf).strip()

    todos = AppConfigurationsManager("testapp", wanted=wanted).dry_run(with_diff=True)
    assert todos == {}

    os.system(f"chmod 000 {conf}")

    todos = AppConfigurationsManager("testapp", wanted=wanted).dry_run(with_diff=True)

    assert "dummy.main" in todos
    assert "diff" not in todos["dummy.main"][0]
    assert "permissions" in todos["dummy.main"][0]

    app_setting("testapp", "foo", "nyah")

    todos = AppConfigurationsManager("testapp", wanted=wanted).dry_run(with_diff=True)

    assert "dummy.main" in todos
    assert "FOO = nyah" in todos["dummy.main"][0]["diff"]
    assert "FOO = bar" in read_file(conf).strip()
    assert "FOO = nyah" not in read_file(conf).strip()

    todos = AppConfigurationsManager("testapp", wanted={}).dry_run(with_diff=True)

    assert "dummy.main" in todos
    assert todos["dummy.main"][0]["action"] == "remove"



@pytest.mark.skip
def test_conf_dummy_unexposed_property():
    raise NotImplementedError


@pytest.mark.skip
def test_conf_dummy_ifclause():
    raise NotImplementedError


@pytest.mark.skip
def test_conf_dummy_reload_fails():
    raise NotImplementedError
