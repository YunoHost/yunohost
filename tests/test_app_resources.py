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
import tempfile
from subprocess import check_call

import pytest

from yunohost.app import app_setting
from yunohost.domain import _get_maindomain
from yunohost.firewall import firewall_list
from yunohost.permission import permission_delete, user_permission_list
from yunohost.utils.process import check_output
from yunohost.utils.resources import (
    AppResource,
    AppResourceClassesByType,
    AppResourceManager,
    N_INSTALL_DIR,
    RBENV_ROOT,
    GOENV_ROOT,
)

dummyfile = "/tmp/dummyappresource-testapp"
env = {"YNH_HELPERS_VERSION": 2.1, "app": "testapp"}


class DummyAppResource(AppResource):
    type = "dummy"

    file: str = "/tmp/dummyappresource-__APP__"
    content: str = "foo"

    exposed_properties: list[str] = ["file", "content"]

    def provision_or_update(self):
        open(self.file, "w").write(self.content)

        if self.content == "forbiddenvalue":
            raise Exception("Emeged you used the forbidden value!1!£&")

    def deprovision(self):
        os.system(f"rm -f {self.file}")


AppResourceClassesByType["dummy"] = DummyAppResource


def setup_function(function):
    clean()

    os.system("mkdir /etc/yunohost/apps/testapp")
    os.system("echo 'id: testapp' > /etc/yunohost/apps/testapp/settings.yml")
    os.system("echo 'packaging_format = 2' > /etc/yunohost/apps/testapp/manifest.toml")
    os.system("echo 'id = \"testapp\"' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system("echo 'version = \"0.1\"' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'description.en = \"A dummy app to test app resources\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )


def teardown_function(function):
    clean()


def clean():
    os.system(f"rm -f {dummyfile}")
    os.system("rm -rf /etc/yunohost/apps/testapp")
    os.system("rm -rf /var/www/testapp")
    os.system("rm -rf /home/yunohost.app/testapp")
    os.system("apt remove lolcat sl nyancat influxdb2 >/dev/null 2>/dev/null")
    os.system("userdel testapp 2>/dev/null")

    for p in user_permission_list()["permissions"]:
        if p.startswith("testapp."):
            permission_delete(p, force=True, sync_perm=False)


def test_provision_dummy():
    current = {"resources": {}}
    wanted = {"resources": {"dummy": {}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted, env=env).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "foo"


def test_deprovision_dummy():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted, env=env).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert not os.path.exists(dummyfile)


def test_provision_dummy_nondefaultvalue():
    current = {"resources": {}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted, env=env).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted, env=env).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy_failwithrollback():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "forbiddenvalue"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    with pytest.raises(Exception):
        AppResourceManager("testapp", current=current, wanted=wanted, env=env).apply(
            rollback_and_raise_exception_if_failure=True
        )
    assert open(dummyfile).read().strip() == "foo"


def test_resource_system_user():
    r = AppResourceClassesByType["system_user"]

    conf = {}

    assert os.system("getent passwd testapp 2>/dev/null") != 0

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.system("getent passwd testapp >/dev/null") == 0
    assert os.system("groups testapp | grep -q 'sftp.app'") != 0

    conf["allow_sftp"] = True
    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.system("getent passwd testapp >/dev/null") == 0
    assert os.system("groups testapp | grep -q 'sftp.app'") == 0

    r(**conf, id="main", app="testapp", env=env).deprovision()

    assert os.system("getent passwd testapp 2>/dev/null") != 0


def test_resource_install_dir():

    AppResourceClassesByType["system_user"](id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    conf = {}

    # FIXME: should also check settings ?
    # FIXME: should also check automigrate from final_path
    # FIXME: should also test changing the install folder location ?

    assert not os.path.exists("/var/www/testapp")

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.path.exists("/var/www/testapp")
    unixperms = check_output("ls -ld /var/www/testapp").split()
    assert unixperms[0] == "drwxr-x---"
    assert unixperms[2] == "testapp"
    assert unixperms[3] == "testapp"

    # NB : following the rework of the resources during packaging v3,
    # the "owner" prop is ignored
    # and "group" prop is auto-translatd into paths_for_www_data if the group is www-data
    # Also the r/w/x modes are ignored and 750 / rwxr-x--- is used instead
    conf["group"] = "www-data:r-x"

    r.convert_packaging_v2_props(conf)
    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.path.exists("/var/www/testapp")
    unixperms = check_output("ls -ld /var/www/testapp").split()
    assert unixperms[0] == "drwxr-x---"
    assert unixperms[2] == "testapp"
    assert unixperms[3] == "www-data"

    r(**conf, id="main", app="testapp", env=env).deprovision()

    assert not os.path.exists("/var/www/testapp")


def test_resource_data_dir():

    AppResourceClassesByType["system_user"](id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["data_dir"]
    conf = {}
    r.convert_packaging_v2_props(conf)

    assert not os.path.exists("/home/yunohost.app/testapp")

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.path.exists("/home/yunohost.app/testapp")
    unixperms = check_output("ls -ld /home/yunohost.app/testapp").split()
    assert unixperms[0] == "drwxr-x---"
    assert unixperms[2] == "testapp"
    assert unixperms[3] == "testapp"

    # NB : following the rework of the resources during packaging v3,
    # the "owner" prop is ignored
    # and "group" prop is auto-translatd into paths_for_www_data if the group is www-data
    # Also the r/w/x modes are ignored and 750 / rwxr-x--- is used instead
    conf["group"] = "www-data:rx"

    r.convert_packaging_v2_props(conf)
    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.path.exists("/home/yunohost.app/testapp")
    unixperms = check_output("ls -ld /home/yunohost.app/testapp").split()
    assert unixperms[0] == "drwxr-x---"
    assert unixperms[2] == "testapp"
    assert unixperms[3] == "www-data"

    r(**conf, id="main", app="testapp", env=env).deprovision()

    # FIXME : implement and check purge option
    # assert not os.path.exists("/home/yunohost.app/testapp")


def test_resource_ports():
    r = AppResourceClassesByType["ports"]
    conf = {}

    assert not app_setting("testapp", "port")

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert app_setting("testapp", "port")

    r(**conf, id="main", app="testapp", env=env).deprovision()

    assert not app_setting("testapp", "port")


def test_resource_ports_several():
    r = AppResourceClassesByType["ports"]
    conf = {"main": {"default": 12345}, "foobar": {"default": 23456}}

    assert not app_setting("testapp", "port")
    assert not app_setting("testapp", "port_foobar")

    r1 = r(**conf["main"], id="main", app="testapp", env=env)
    r1.provision_or_update()
    r2 = r(**conf["foobar"], id="foobar", app="testapp", env=env)
    r2.provision_or_update()

    assert app_setting("testapp", "port")
    assert app_setting("testapp", "port_foobar")

    r1.deprovision()
    r2.deprovision()

    assert not app_setting("testapp", "port")
    assert not app_setting("testapp", "port_foobar")


def test_resource_ports_firewall():
    r = AppResourceClassesByType["ports"]
    conf = {"main": {"default": 12345}}

    r1 = r(**conf["main"], id="main", app="testapp", env=env)
    r1.provision_or_update()
    r.grouped_trigger_after_apply([r1])

    assert 12345 not in firewall_list(protocol="tcp")["tcp"]

    conf = {"main": {"default": 12345, "exposed": "TCP"}}

    r1 = r(**conf["main"], id="main", app="testapp", env=env)
    r1.provision_or_update()
    r.grouped_trigger_after_apply([r1])

    assert 12345 in firewall_list(protocol="tcp")["tcp"]

    r1.deprovision()
    r.grouped_trigger_after_apply([r1])

    assert 12345 not in firewall_list(protocol="tcp")["tcp"]


def test_resource_database():
    r = AppResourceClassesByType["database"]
    # NB: in real-life, packagers set 'type' which is autoconverted to 'dbtype' inside the resource manager
    conf = {"dbtype": "mysql"}

    assert os.system("mysqlshow 'testapp' >/dev/null 2>/dev/null") != 0
    assert not app_setting("testapp", "db_name")
    assert not app_setting("testapp", "db_user")
    assert not app_setting("testapp", "db_pwd")

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.system("mysqlshow 'testapp' >/dev/null 2>/dev/null") == 0
    assert app_setting("testapp", "db_name")
    assert app_setting("testapp", "db_user")
    assert app_setting("testapp", "db_pwd")

    r(**conf, id="main", app="testapp", env=env).deprovision()

    assert os.system("mysqlshow 'testapp' >/dev/null 2>/dev/null") != 0
    assert not app_setting("testapp", "db_name")
    assert not app_setting("testapp", "db_user")
    assert not app_setting("testapp", "db_pwd")


def test_resource_apt():
    r = AppResourceClassesByType["apt"]
    conf = {
        "packages": "nyancat, sl",
        "extras": {
            "influxdb": {
                "repo": "deb https://repos.influxdata.com/debian stable main",
                "key": "https://repos.influxdata.com/influxdata-archive_compat.key",
                "packages": "influxdb2",
            }
        },
    }

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") != 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") != 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") != 0

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") == 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") == 0
    assert (
        os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    )  # Lolcat shouldnt be installed yet
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") == 0

    conf["packages"] += ", lolcat"
    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") == 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") == 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") == 0

    r(**conf, id="main", app="testapp", env=env).deprovision()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") != 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") != 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") != 0


def test_resource_permissions():
    maindomain = _get_maindomain()
    os.system(f"echo 'domain: {maindomain}' >> /etc/yunohost/apps/testapp/settings.yml")
    os.system("echo 'path: /testapp' >> /etc/yunohost/apps/testapp/settings.yml")

    r = AppResourceClassesByType["permissions"]
    conf = {
        "main": {
            "url": "/",
            "allowed": "visitors",
        },
    }

    res = user_permission_list(full=True)["permissions"]
    # Nowadays there's always an implicit "main" perm but with default stuff such as empty url
    assert res["testapp.main"]["url"] is None
    assert res["testapp.main"]["allowed"] == []

    r(**conf["main"], id="main", app="testapp", env=env).provision_or_update()

    res = user_permission_list(full=True)["permissions"]
    assert "testapp.main" in res
    assert "visitors" in res["testapp.main"]["allowed"]
    assert res["testapp.main"]["url"] == "/"
    assert "testapp.admin" not in res

    conf["admin"] = {"url": "/admin", "allowed": ""}

    r(**conf["admin"], id="admin", app="testapp", env=env).provision_or_update()

    res = user_permission_list(full=True)["permissions"]

    assert "testapp.main" in list(res.keys())
    assert "visitors" in res["testapp.main"]["allowed"]
    assert res["testapp.main"]["url"] == "/"

    assert "testapp.admin" in res
    assert not res["testapp.admin"]["allowed"]
    assert res["testapp.admin"]["url"] == "/admin"

    conf["admin"]["url"] = "/adminpanel"

    radmin = r(**conf["admin"], id="admin", app="testapp", env=env)
    radmin.provision_or_update()

    res = user_permission_list(full=True)["permissions"]

    assert res["testapp.admin"]["url"] == "/adminpanel"

    radmin.deprovision()

    res = user_permission_list(full=True)["permissions"]

    assert "testapp.admin" not in res
    # The main permission is still forced to exist
    assert "testapp.main" in res


def test_resource_nodejs():

    AppResourceClassesByType["system_user"](id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["nodejs"]
    assert not app_setting("testapp", "nodejs_version")
    conf = {
        "version": "20",
    }

    rnode = r(**conf, id="main", app="testapp", env=env)
    rnode.provision_or_update()

    nodejs_version = app_setting("testapp", "nodejs_version")
    assert nodejs_version
    nodejs_dir = f"{N_INSTALL_DIR}/n/versions/node/{nodejs_version}/bin"
    assert os.path.exists(nodejs_dir)

    env_cmd = {
        "N_PREFIX": N_INSTALL_DIR,
        "PATH": f"{nodejs_dir}:{os.environ['PATH']}",
    }

    assert check_output("which node", env=env_cmd).startswith(nodejs_dir)
    installed_version = check_output("node --version", env=env_cmd)
    assert installed_version.startswith("v20.")
    with tempfile.TemporaryDirectory(prefix="ynh_") as d:
        # Install a random simple package to validate npm is in the path and working
        check_call(["npm", "install", "ansi-styles"], cwd=d, env=env_cmd)
        # FIXME: the resource should install stuff as non-root probably ?
        assert os.path.exists(f"{d}/node_modules/")

    rnode.deprovision()
    assert not app_setting("testapp", "nodejs_version")
    assert not os.path.exists(nodejs_dir)


def test_resource_ruby():
    os.system("echo '[integration]' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'helpers_version = \"2.1\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )

    r = AppResourceClassesByType["system_user"]
    r(id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    r(id="main", app="testapp", env=env).provision_or_update()
    # install_dir = app_setting("testapp", "install_dir")

    r = AppResourceClassesByType["apt"]
    conf = {
        "packages": "make, gcc, libjemalloc-dev, libffi-dev, libyaml-dev, zlib1g-dev"
    }
    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["ruby"]
    assert not app_setting("testapp", "ruby_version")
    conf = {
        "version": "3.3.5",
    }

    try:
        r(**conf, id="main", app="testapp", env=env).provision_or_update()
        r(**conf, id="main", app="testapp", env=env).provision_or_update()
    except Exception:
        os.system("tail -n 40 /tmp/ruby-build*.log")
        raise

    ruby_version = app_setting("testapp", "ruby_version")
    assert ruby_version
    ruby_dir = f"{RBENV_ROOT}/versions/testapp/bin"
    ruby_dir2 = f"{RBENV_ROOT}/versions/{ruby_version}/bin"
    assert os.path.exists(ruby_dir)
    assert os.path.exists(ruby_dir2)

    env_cmd = {
        "PATH": f"{ruby_dir}:{os.environ['PATH']}",
    }

    assert check_output("which ruby", env=env_cmd).startswith(ruby_dir)
    assert check_output("which gem", env=env_cmd).startswith(ruby_dir)
    assert "3.3.5" in check_output("ruby --version", env=env_cmd)
    with tempfile.TemporaryDirectory(prefix="ynh_") as d:
        # Install a random simple package to validate the path etc
        check_call(
            "gem install bundler passenger --no-document".split(), cwd=d, env=env_cmd
        )
        check_call(
            "bundle config set --local without 'development test'".split(),
            cwd=d,
            env=env_cmd,
        )
        # FIXME: the resource should install stuff as non-root probably ?

    r(id="main", app="testapp", env=env).deprovision()
    assert not app_setting("testapp", "ruby_version")
    assert not os.path.exists(ruby_dir)
    assert not os.path.exists(ruby_dir2)


def test_resource_go():
    os.system("echo '[integration]' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'helpers_version = \"2.1\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )

    r = AppResourceClassesByType["system_user"]
    r(id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    r(id="main", app="testapp", env=env).provision_or_update()
    # install_dir = app_setting("testapp", "install_dir")

    r = AppResourceClassesByType["go"]
    assert not app_setting("testapp", "go_version")
    conf = {
        "version": "1.22",
    }

    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    go_version = app_setting("testapp", "go_version")
    assert go_version and go_version.startswith("1.22.")
    go_dir = f"{GOENV_ROOT}/versions/{go_version}/bin"
    assert os.path.exists(go_dir)

    env_cmd = {
        "PATH": f"{go_dir}:{os.environ['PATH']}",
    }

    assert check_output("go version", env=env_cmd).startswith(
        f"go version go{go_version} linux/"
    )

    with tempfile.TemporaryDirectory(prefix="ynh_") as d:
        with open(f"{d}/helloworld.go", "w") as f:
            f.write(
                """
                package main
                import "fmt"
                func main() { fmt.Println("hello world") }
            """
            )
        env["HOME"] = d
        check_call("go build helloworld.go".split(), cwd=d, env=env_cmd)
        assert os.path.exists(f"{d}/helloworld")
        assert "hello world" in check_output("./helloworld", cwd=d)

    r(id="main", app="testapp", env=env_cmd).deprovision()
    assert not app_setting("testapp", "go_version")
    assert not os.path.exists(go_dir)


def test_resource_composer():
    os.system("echo '[integration]' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'helpers_version = \"2.1\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )

    r = AppResourceClassesByType["system_user"]
    r(id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    r(id="main", app="testapp", env=env).provision_or_update()
    install_dir = app_setting("testapp", "install_dir")

    r = AppResourceClassesByType["apt"]
    conf = {"packages": "php8.2-fpm"}
    r(**conf, id="main", app="testapp", env=env).provision_or_update()

    r = AppResourceClassesByType["composer"]
    assert not app_setting("testapp", "composer_version")
    conf = {
        "version": "2.8.3",
    }

    r(**conf, id="main", app="testapp", env=env).provision_or_update()
    assert app_setting("testapp", "composer_version")
    assert os.path.exists(install_dir + "/composer.phar")

    r(**conf, id="main", app="testapp", env=env)._run_script(
        "test_composer_exec",
        f"cd {install_dir}; ynh_composer_exec require symfony/polyfill-mbstring 1.31.0",
    )

    assert os.path.exists(install_dir + "/.composer")
    assert os.path.exists(install_dir + "/vendor/symfony/polyfill-mbstring")

    r(**conf, id="main", app="testapp", env=env).deprovision()
    assert not app_setting("testapp", "composer_version")
    assert not os.path.exists(install_dir + "/composer.phar")
