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

import pytest
from moulinette.utils.process import check_output
from subprocess import check_call

from yunohost.app import app_setting
from yunohost.domain import _get_maindomain
from yunohost.firewall import firewall_list
from yunohost.permission import permission_delete, user_permission_list
from yunohost.utils.resources import (
    AppResource,
    AppResourceClassesByType,
    AppResourceManager,
)

dummyfile = "/tmp/dummyappresource-testapp"


class DummyAppResource(AppResource):
    type = "dummy"

    default_properties = {
        "file": "/tmp/dummyappresource-__APP__",
        "content": "foo",
    }

    def provision_or_update(self, context):
        open(self.file, "w").write(self.content)

        if self.content == "forbiddenvalue":
            raise Exception("Emeged you used the forbidden value!1!£&")

    def deprovision(self, context):
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
    os.system('apt install redis-server -y')


def teardown_function(function):
    clean()


def clean():
    os.system(f"rm -f {dummyfile}")
    os.system("rm -rf /etc/yunohost/apps/testapp")
    os.system("rm -rf /var/www/testapp")
    os.system("rm -rf /home/yunohost.app/testapp")
    os.system("apt remove lolcat sl nyancat influxdb2 >/dev/null 2>/dev/null")
    os.system("userdel testapp 2>/dev/null")
    os.system("redis-cli flushall > /dev/null")

    for p in user_permission_list()["permissions"]:
        if p.startswith("testapp."):
            permission_delete(p, force=True, sync_perm=False)


def test_provision_dummy():
    current = {"resources": {}}
    wanted = {"resources": {"dummy": {}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "foo"


def test_deprovision_dummy():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert not os.path.exists(dummyfile)


def test_provision_dummy_nondefaultvalue():
    current = {"resources": {}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy_failwithrollback():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "forbiddenvalue"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    with pytest.raises(Exception):
        AppResourceManager("testapp", current=current, wanted=wanted).apply(
            rollback_and_raise_exception_if_failure=True
        )
    assert open(dummyfile).read().strip() == "foo"


def test_resource_system_user():
    r = AppResourceClassesByType["system_user"]

    conf = {}

    assert os.system("getent passwd testapp 2>/dev/null") != 0

    r(conf, "testapp").provision_or_update()

    assert os.system("getent passwd testapp >/dev/null") == 0
    assert os.system("groups testapp | grep -q 'sftp.app'") != 0

    conf["allow_sftp"] = True
    r(conf, "testapp").provision_or_update()

    assert os.system("getent passwd testapp >/dev/null") == 0
    assert os.system("groups testapp | grep -q 'sftp.app'") == 0

    r(conf, "testapp").deprovision()

    assert os.system("getent passwd testapp 2>/dev/null") != 0


def test_resource_install_dir():
    r = AppResourceClassesByType["install_dir"]
    conf = {"owner": "nobody:rx", "group": "nogroup:rx"}

    # FIXME: should also check settings ?
    # FIXME: should also check automigrate from final_path
    # FIXME: should also test changing the install folder location ?

    assert not os.path.exists("/var/www/testapp")

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/var/www/testapp")
    unixperms = check_output("ls -ld /var/www/testapp").split()
    assert unixperms[0] == "dr-xr-x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "nogroup"

    conf["owner"] = "nobody:rwx"
    conf["group"] = "www-data:x"

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/var/www/testapp")
    unixperms = check_output("ls -ld /var/www/testapp").split()
    assert unixperms[0] == "drwx--x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "www-data"

    r(conf, "testapp").deprovision()

    assert not os.path.exists("/var/www/testapp")


def test_resource_data_dir():
    r = AppResourceClassesByType["data_dir"]
    conf = {"owner": "nobody:rx", "group": "nogroup:rx"}

    assert not os.path.exists("/home/yunohost.app/testapp")

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/home/yunohost.app/testapp")
    unixperms = check_output("ls -ld /home/yunohost.app/testapp").split()
    assert unixperms[0] == "dr-xr-x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "nogroup"

    conf["owner"] = "nobody:rwx"
    conf["group"] = "www-data:x"

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/home/yunohost.app/testapp")
    unixperms = check_output("ls -ld /home/yunohost.app/testapp").split()
    assert unixperms[0] == "drwx--x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "www-data"

    r(conf, "testapp").deprovision()

    # FIXME : implement and check purge option
    # assert not os.path.exists("/home/yunohost.app/testapp")


def test_resource_ports():
    r = AppResourceClassesByType["ports"]
    conf = {}

    assert not app_setting("testapp", "port")

    r(conf, "testapp").provision_or_update()

    assert app_setting("testapp", "port")

    r(conf, "testapp").deprovision()

    assert not app_setting("testapp", "port")


def test_resource_ports_several():
    r = AppResourceClassesByType["ports"]
    conf = {"main": {"default": 12345}, "foobar": {"default": 23456}}

    assert not app_setting("testapp", "port")
    assert not app_setting("testapp", "port_foobar")

    r(conf, "testapp").provision_or_update()

    assert app_setting("testapp", "port")
    assert app_setting("testapp", "port_foobar")

    r(conf, "testapp").deprovision()

    assert not app_setting("testapp", "port")
    assert not app_setting("testapp", "port_foobar")


def test_resource_ports_firewall():
    r = AppResourceClassesByType["ports"]
    conf = {"main": {"default": 12345}}

    r(conf, "testapp").provision_or_update()

    assert 12345 not in firewall_list(protocol="tcp")["tcp"]

    conf = {"main": {"default": 12345, "exposed": "TCP"}}

    r(conf, "testapp").provision_or_update()

    assert 12345 in firewall_list(protocol="tcp")["tcp"]

    r(conf, "testapp").deprovision()

    assert 12345 not in firewall_list(protocol="tcp")["tcp"]


def test_resource_database():
    r = AppResourceClassesByType["database"]
    conf = {"type": "mysql"}

    assert os.system("mysqlshow 'testapp' >/dev/null 2>/dev/null") != 0
    assert not app_setting("testapp", "db_name")
    assert not app_setting("testapp", "db_user")
    assert not app_setting("testapp", "db_pwd")

    r(conf, "testapp").provision_or_update()

    assert os.system("mysqlshow 'testapp' >/dev/null 2>/dev/null") == 0
    assert app_setting("testapp", "db_name")
    assert app_setting("testapp", "db_user")
    assert app_setting("testapp", "db_pwd")

    r(conf, "testapp").deprovision()

    assert os.system("mysqlshow 'testapp' >/dev/null 2>/dev/null") != 0
    assert not app_setting("testapp", "db_name")
    assert not app_setting("testapp", "db_user")
    assert not app_setting("testapp", "db_pwd")

def test_resource_redis():
    r = AppResourceClassesByType["redis"]
    conf = {}
    assert os.system("redis-cli INFO keyspace | grep -q '^db'") != 0
    assert not app_setting("testapp", "redis_db")

    r(conf, "testapp").provision_or_update()
    assert os.system("redis-cli INFO keyspace | grep -q '^db0'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db1'") != 0
    assert app_setting("testapp", "redis_db") ==  0

    conf = {
        "redis_db": {},
        "celery_db": {}
    }
    r(conf, "testapp").provision_or_update()
    assert os.system("redis-cli INFO keyspace | grep -q '^db0'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db1'") == 0
    assert app_setting("testapp", "redis_db") == 0
    assert app_setting("testapp", "celery_db") == 1

    conf = {
        "redis_db": {},
        "celery_redis_db": {
            "previous_names": "celery_db" # Check that it works with a str instead of a list[str]
        }
    }
    r(conf, "testapp").provision_or_update()
    assert os.system("redis-cli INFO keyspace | grep -q '^db0'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db1'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db2'") != 0
    assert app_setting("testapp", "redis_db") == 0
    assert app_setting("testapp", "celery_redis_db") == 1
    assert not app_setting("testapp", "celery_db")

    conf = {
        "celery_redis_db_renamed": {
            "previous_names": ["celery_db", "celery_redis_db"] # Check with an array
        }
    }
    r(conf, "testapp").provision_or_update()
    assert os.system("redis-cli INFO keyspace | grep -q '^db0'") != 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db1'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db2'") != 0
    assert app_setting("testapp", "redis_db") is None
    assert app_setting("testapp", "celery_redis_db") is None
    assert app_setting("testapp", "celery_redis_db_renamed") == 1

    conf = {
        "takes_redis_db_place": {},
        "celery_redis_db_renamed": {
            "previous_names": ["celery_db", "celery_redis_db"]
        }
    }
    r(conf, "testapp").provision_or_update()
    assert os.system("redis-cli INFO keyspace | grep -q '^db0'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db1'") == 0
    assert os.system("redis-cli INFO keyspace | grep -q '^db2'") != 0
    assert app_setting("testapp", "celery_redis_db_renamed") == 1
    assert app_setting("testapp", "takes_redis_db_place") == 0

    r(conf, "testapp").deprovision()
    assert os.system("redis-cli INFO keyspace | grep -q '^db'") != 0
    assert app_setting("testapp", "redis_db") is None
    assert app_setting("testapp", "celery_redis_db") is None

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

    r(conf, "testapp").provision_or_update()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") == 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") == 0
    assert (
        os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    )  # Lolcat shouldnt be installed yet
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") == 0

    conf["packages"] += ", lolcat"
    r(conf, "testapp").provision_or_update()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") == 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") == 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") == 0

    r(conf, "testapp").deprovision()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") != 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") != 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") != 0


def test_resource_permissions():
    maindomain = _get_maindomain()
    os.system(f"echo 'domain: {maindomain}' >> /etc/yunohost/apps/testapp/settings.yml")
    os.system("echo 'path: /testapp' >> /etc/yunohost/apps/testapp/settings.yml")

    # A manager object is required to set the label of the app...
    manager = AppResourceManager("testapp", current={}, wanted={"name": "Test App"})
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

    r(conf, "testapp", manager).provision_or_update()

    res = user_permission_list(full=True)["permissions"]
    assert "testapp.main" in res
    assert "visitors" in res["testapp.main"]["allowed"]
    assert res["testapp.main"]["url"] == "/"
    assert "testapp.admin" not in res

    conf["admin"] = {"url": "/admin", "allowed": ""}

    r(conf, "testapp", manager).provision_or_update()

    res = user_permission_list(full=True)["permissions"]

    assert "testapp.main" in list(res.keys())
    assert "visitors" in res["testapp.main"]["allowed"]
    assert res["testapp.main"]["url"] == "/"

    assert "testapp.admin" in res
    assert not res["testapp.admin"]["allowed"]
    assert res["testapp.admin"]["url"] == "/admin"

    conf["admin"]["url"] = "/adminpanel"

    r(conf, "testapp", manager).provision_or_update()

    res = user_permission_list(full=True)["permissions"]

    assert res["testapp.admin"]["url"] == "/adminpanel"

    r(conf, "testapp").deprovision()

    res = user_permission_list(full=True)["permissions"]

    assert "testapp.admin" not in res
    # The main permission is still forced to exist
    assert "testapp.main" in res


def test_resource_nodejs():

    manager = AppResourceManager(
        "testapp",
        current={},
        wanted={"name": "Test App", "integration": {"helpers_version": "2.1"}},
    )

    r = AppResourceClassesByType["nodejs"]
    assert not app_setting("testapp", "nodejs_version")
    conf = {
        "version": "20",
    }

    r(conf, "testapp", manager).provision_or_update()

    nodejs_version = app_setting("testapp", "nodejs_version")
    assert nodejs_version
    nodejs_dir = f"{r.N_INSTALL_DIR}/n/versions/node/{nodejs_version}/bin"
    assert os.path.exists(nodejs_dir)

    env = {
        "N_PREFIX": r.N_INSTALL_DIR,
        "PATH": f"{nodejs_dir}:{os.environ['PATH']}",
    }

    assert check_output("which node", env=env).startswith(nodejs_dir)
    installed_version = check_output("node --version", env=env)
    assert installed_version.startswith("v20.")
    with tempfile.TemporaryDirectory(prefix="ynh_") as d:
        # Install a random simple package to validate npm is in the path and working
        check_call(["npm", "install", "ansi-styles"], cwd=d, env=env)
        # FIXME: the resource should install stuff as non-root probably ?
        assert os.path.exists(f"{d}/node_modules/")

    r({}, "testapp", manager).deprovision()
    assert not app_setting("testapp", "nodejs_version")
    assert not os.path.exists(nodejs_dir)


def test_resource_ruby():

    os.system("echo '[integration]' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'helpers_version = \"2.1\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )

    r = AppResourceClassesByType["system_user"]
    r({}, "testapp").provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    r({}, "testapp").provision_or_update()
    install_dir = app_setting("testapp", "install_dir")

    manager = AppResourceManager(
        "testapp",
        current={},
        wanted={"name": "Test App", "integration": {"helpers_version": "2.1"}},
    )

    r = AppResourceClassesByType["apt"]
    conf = {
        "packages": "make, gcc, libjemalloc-dev, libffi-dev, libyaml-dev, zlib1g-dev"
    }
    r(conf, "testapp", manager).provision_or_update()

    r = AppResourceClassesByType["ruby"]
    assert not app_setting("testapp", "ruby_version")
    conf = {
        "version": "3.3.5",
    }

    try:
        r(conf, "testapp", manager).provision_or_update()
    except Exception:
        os.system("tail -n 40 /tmp/ruby-build*.log")
        raise

    ruby_version = app_setting("testapp", "ruby_version")
    assert ruby_version
    ruby_dir = f"{r.RBENV_ROOT}/versions/testapp/bin"
    ruby_dir2 = f"{r.RBENV_ROOT}/versions/{ruby_version}/bin"
    assert os.path.exists(ruby_dir)
    assert os.path.exists(ruby_dir2)

    env = {
        "PATH": f"{ruby_dir}:{os.environ['PATH']}",
    }

    assert check_output("which ruby", env=env).startswith(ruby_dir)
    assert check_output("which gem", env=env).startswith(ruby_dir)
    assert "3.3.5" in check_output("ruby --version", env=env)
    with tempfile.TemporaryDirectory(prefix="ynh_") as d:
        # Install a random simple package to validate the path etc
        check_call(
            "gem install bundler passenger --no-document".split(), cwd=d, env=env
        )
        check_call(
            "bundle config set --local without 'development test'".split(),
            cwd=d,
            env=env,
        )
        # FIXME: the resource should install stuff as non-root probably ?

    r({}, "testapp", manager).deprovision()
    assert not app_setting("testapp", "ruby_version")
    assert not os.path.exists(ruby_dir)
    assert not os.path.exists(ruby_dir2)


def test_resource_go():

    os.system("echo '[integration]' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'helpers_version = \"2.1\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )

    r = AppResourceClassesByType["system_user"]
    r({}, "testapp").provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    r({}, "testapp").provision_or_update()
    install_dir = app_setting("testapp", "install_dir")

    r = AppResourceClassesByType["go"]
    assert not app_setting("testapp", "go_version")
    conf = {
        "version": "1.22",
    }

    r(conf, "testapp").provision_or_update()

    go_version = app_setting("testapp", "go_version")
    assert go_version and go_version.startswith("1.22.")
    go_dir = f"{r.GOENV_ROOT}/versions/{go_version}/bin"
    assert os.path.exists(go_dir)

    env = {
        "PATH": f"{go_dir}:{os.environ['PATH']}",
    }

    assert check_output("go version", env=env).startswith(
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
        check_call("go build helloworld.go".split(), cwd=d, env=env)
        assert os.path.exists(f"{d}/helloworld")
        assert "hello world" in check_output("./helloworld", cwd=d)

    r({}, "testapp").deprovision()
    assert not app_setting("testapp", "go_version")
    assert not os.path.exists(go_dir)


def test_resource_composer():

    os.system("echo '[integration]' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'helpers_version = \"2.1\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )

    r = AppResourceClassesByType["system_user"]
    r({}, "testapp").provision_or_update()

    r = AppResourceClassesByType["install_dir"]
    r({}, "testapp").provision_or_update()
    install_dir = app_setting("testapp", "install_dir")

    r = AppResourceClassesByType["apt"]
    manager = AppResourceManager(
        "testapp",
        current={},
        wanted={"name": "Test App", "integration": {"helpers_version": "2.1"}},
    )
    conf = {"packages": "php8.2-fpm"}
    r(conf, "testapp", manager).provision_or_update()

    r = AppResourceClassesByType["composer"]
    assert not app_setting("testapp", "composer_version")
    conf = {
        "version": "2.8.3",
    }

    r(conf, "testapp").provision_or_update()
    assert app_setting("testapp", "composer_version")
    assert os.path.exists(install_dir + "/composer.phar")

    r(conf, "testapp")._run_script(
        "test_composer_exec",
        f"cd {install_dir}; ynh_composer_exec require symfony/polyfill-mbstring 1.31.0",
    )

    assert os.path.exists(install_dir + "/.composer")
    assert os.path.exists(install_dir + "/vendor/symfony/polyfill-mbstring")

    r(conf, "testapp").deprovision()
    assert not app_setting("testapp", "composer_version")
    assert not os.path.exists(install_dir + "/composer.phar")
