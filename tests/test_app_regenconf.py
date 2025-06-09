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
import requests

from moulinette.utils.filesystem import read_file, write_to_file, write_to_yaml
from moulinette.utils.process import check_output
from yunohost.app import app_setting, _get_app_settings, _set_app_settings
from yunohost.service import _get_services, service_remove
from yunohost.utils.error import YunohostError
from yunohost.utils.configurations import (
    BaseConfiguration,
    ConfigurationClassesByType,
    AppConfigurationsManager,
    DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED,
)
from .conftest import message

MAIN_DOMAIN = read_file("/etc/yunohost/current_host").strip()


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

    write_to_yaml("/etc/yunohost/apps/testapp/settings.yml", {
        "id": "testapp",
        "foo": "bar",
        "domain": MAIN_DOMAIN,
        "path": "/",
        "install_dir": "/var/www/testapp",
    })
    write_to_file("/etc/yunohost/apps/testapp/manifest.toml", '\n'.join([
        'packaging_format = 3',
        'id = "testapp"',
        'version = "0.1"',
        'description.en = "A dummy app to test app resources"'
    ]))
    write_to_file("/etc/yunohost/apps/testapp/conf/dummy.conf", '\n'.join([
        '# This is a dummy conf file',
        'APP = __APP__',
        'FOO = __FOO__'
    ]))


def teardown_function(function):
    clean()


def clean():
    os.system("rm -rf /etc/yunohost/apps/testapp")
    os.system("rm -rf /tmp/dummyconfs/")
    os.system(f"rm -rf {DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED}/testapp/")
    os.system("userdel testapp 2>/dev/null")
    os.system("rm -rf /etc/nginx/conf.d/*/*testapp*")
    os.system("rm -rf /etc/nginx/conf.d/other_domain.test.d/")
    os.system("rm -rf /etc/php/*/fpm/pool.d/testapp.conf")
    os.system("rm -rf /etc/fail2ban/*/testapp.conf")
    os.system("rm -rf /etc/cron.d/testapp*")
    os.system("rm -rf /etc/sudoers.d/testapp*")
    os.system("rm -rf /etc/logrotate.d/testapp*")
    os.system("rm -rf /var/www/testapp")
    if os.system("systemctl --quiet is-active testapp") == 0:
        os.system("systemctl stop testapp")
    os.system("rm -rf /etc/systemd/system/testapp*.service")
    os.system("systemctl daemon-reload")
    if "testapp" in _get_services():
        service_remove("testapp")


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


def test_conf_dummy_unexposed_property():

    wanted = {"configurations": {"dummy": {"main": {"foo": "bar"}}}}
    with pytest.raises(YunohostError):
        AppConfigurationsManager("testapp", wanted=wanted).apply()

    wanted = {"configurations": {"dummy": {"main": {"type": "foobar"}}}}
    with pytest.raises(YunohostError):
        AppConfigurationsManager("testapp", wanted=wanted).apply()

    wanted = {"configurations": {"dummy": {"other": {"type": "foobar"}}}}
    with pytest.raises(YunohostError):
        AppConfigurationsManager("testapp", wanted=wanted).apply()


def test_conf_dummy_ifclause():

    # FIXME
    wanted = {"configurations": {"dummy": {"main": {"if": "foo == 'bar'"}}}}

    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert os.path.exists(conf)

    os.remove(conf)

    wanted = {"configurations": {"dummy": {"main": {"if": "'__FOO__' == 'bar'"}}}}

    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert os.path.exists(conf)


def test_conf_dummy_ifclause_not_fulfilled():

    # FIXME
    wanted = {"configurations": {"dummy": {"main": {"if": "foo == 'not the right value'"}}}}

    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert not os.path.exists(conf)

    # FIXME
    wanted = {"configurations": {"dummy": {"main": {"if": "\"__FOO__\" != 'bar'"}}}}

    conf = "/tmp/dummyconfs/testapp.conf"
    assert not os.path.exists(conf)
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert not os.path.exists(conf)


def test_conf_dummy_ifclause_syntaxissue():

    wanted = {"configurations": {"dummy": {"main": {"if": "__FOO__ == 'bar'"}}}}
    with pytest.raises(KeyError):
        AppConfigurationsManager("testapp", wanted=wanted).apply()


@pytest.mark.skip
def test_conf_dummy_reload_fails():
    raise NotImplementedError


####################################################################################


def test_conf_nginx():

    write_to_file("/etc/yunohost/apps/testapp/conf/nginx.conf", """
#sub_path_only rewrite ^__PATH__$ __PATH__/ permanent;
location __PATH__/ {
  alias __INSTALL_DIR__/;
  index index.html;
}
""")
    write_to_file("/etc/yunohost/apps/testapp/conf/nginx-foobar.conf", "# Foo bar")

    app_setting("testapp", "path", value="/")

    wanted = {"configurations": {"nginx": {}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists(f"/etc/nginx/conf.d/{MAIN_DOMAIN}.d/testapp.conf")
    content = read_file(f"/etc/nginx/conf.d/{MAIN_DOMAIN}.d/testapp.conf")
    assert "#sub_path_only" in content

    # Change url path where the app is installed
    app_setting("testapp", "path", value="/subpath")
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists(f"/etc/nginx/conf.d/{MAIN_DOMAIN}.d/testapp.conf")
    content = read_file(f"/etc/nginx/conf.d/{MAIN_DOMAIN}.d/testapp.conf")
    assert "#sub_path_only" not in content and "rewrite ^/subpath$" in content

    # Change domain where the app is installed
    os.system("mkdir -p /etc/nginx/conf.d/other_domain.test.d/")
    app_setting("testapp", "domain", value="other_domain.test")
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert not os.path.exists(f"/etc/nginx/conf.d/{MAIN_DOMAIN}.d/testapp.conf")
    assert os.path.exists("/etc/nginx/conf.d/other_domain.test.d/testapp.conf")

    # Remove nginx conf
    wanted = {"configurations": {}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert not os.path.exists(f"/etc/nginx/conf.d/{MAIN_DOMAIN}.d/testapp.conf")
    assert not os.path.exists("/etc/nginx/conf.d/other_domain.test.d/testapp.conf")

    # TODO / FIXME : also test the 'extra' nginx conf stuff


def test_conf_php():

    os.system("useradd testapp")
    os.system("mkdir -p /var/www/testapp")
    os.system("apt install php8.2-fpm php8.4-fpm --assume-yes")
    app_setting("testapp", "php_version", value="8.2")

    assert not os.path.exists("/etc/php/8.2/fpm/pool.d/testapp.conf")
    assert not os.path.exists("/etc/php/8.4/fpm/pool.d/testapp.conf")

    wanted = {"configurations": {"php": {}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists("/etc/php/8.2/fpm/pool.d/testapp.conf")
    assert not os.path.exists("/etc/php/8.4/fpm/pool.d/testapp.conf")

    app_setting("testapp", "php_version", value="8.4")
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert not os.path.exists("/etc/php/8.2/fpm/pool.d/testapp.conf")
    assert os.path.exists("/etc/php/8.4/fpm/pool.d/testapp.conf")

    write_to_file("/etc/yunohost/apps/testapp/conf/extra_php-fpm.conf", "\n\n; Foobar\n\n")

    assert "; Foobar" not in read_file("/etc/php/8.4/fpm/pool.d/testapp.conf")

    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert "; Foobar" in read_file("/etc/php/8.4/fpm/pool.d/testapp.conf")

    assert "php_admin_value[post_max_size] = 50M" in read_file("/etc/php/8.4/fpm/pool.d/testapp.conf")

    wanted = {"configurations": {"php": {"main": {"php_upload_max_filesize": "123M"}}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "php_admin_value[post_max_size] = 123M" in read_file("/etc/php/8.4/fpm/pool.d/testapp.conf")

    app_setting("testapp", "php_upload_max_filesize", value="321M")
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "php_admin_value[post_max_size] = 321M" in read_file("/etc/php/8.4/fpm/pool.d/testapp.conf")


def test_conf_systemd():

    os.system("useradd testapp")
    os.system("mkdir -p /var/www/testapp")
    os.system("mkdir -p /var/log/testapp/")
    os.system("mkdir -p /etc/yunohost/apps/testapp/conf/")

    # Use stuff from the "hellopy" test app (used for sso/portal/auth tests)
    # to have a template and service to actually run
    hellopy_dir = os.path.dirname(__file__) + "/apps/hellopy_ynh"
    os.system(f"sudo cp {hellopy_dir}/conf/server.py /var/www/testapp/")
    os.system(f"sudo cp {hellopy_dir}/conf/systemd.service /etc/yunohost/apps/testapp/conf/")
    os.system("chown -R testapp:testapp /var/www/testapp")
    os.system("chown -R testapp:testapp /var/log/testapp")

    app_setting("testapp", "port", value=1234)

    assert "testapp" not in _get_services().keys()
    assert os.system("systemctl --quiet is-active testapp") != 0

    wanted = {"configurations": {"systemd": {
        "main": {
            "main_log": "/var/log/__APP__/__APP__.log",
            "wait_until": "Server started"
        }
    }}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert "testapp" in _get_services().keys()
    assert os.system("systemctl --quiet is-active testapp") == 0
    assert requests.get("http://127.0.0.1:1234/").ok

    # FIXME / TODO : should also add test for "extra" conf

    # FIXME / TODO : ... and handle case where the systemd conf is managed externally but still want the yunohost integration and/or wait_until?


def test_conf_fail2ban():

    assert not os.path.exists("/etc/fail2ban/jail.d/testapp.conf")
    assert not os.path.exists("/etc/fail2ban/filter.d/testapp.conf")

    wanted = {"configurations": {"fail2ban": {
        "main": {
            "auth_route": "/login",
        }
    }}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists("/etc/fail2ban/jail.d/testapp.conf")
    assert os.path.exists("/etc/fail2ban/filter.d/testapp.conf")


def test_conf_cron():

    assert not os.path.exists("/etc/cron.d/testapp")
    assert not os.path.exists("/etc/cron.d/testapp-foobar")

    # Nominal case with a template
    write_to_file("/etc/yunohost/apps/testapp/conf/cron", '\n'.join([
        '# Some comment',
        '',
        '@weekly __APP__ /bin/true',
        '*/5 * * * * __APP__ /bin/ls'
    ]))

    wanted = {"configurations": {"cron": {}}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists("/etc/cron.d/testapp")
    assert "@weekly testapp /bin/true" in read_file("/etc/cron.d/testapp")

    # Invalid template (missing user part)
    write_to_file("/etc/yunohost/apps/testapp/conf/cron", '\n'.join([
        '@weekly /bin/true',
    ]))

    with pytest.raises(YunohostError):
        AppConfigurationsManager("testapp", wanted=wanted).apply()

    # Nominal case with the more declarative paradigm
    wanted = {"configurations": {"cron": {
        "main": {
            "timing": "*/15 * * * *",
            "command": "/bin/true",
        },
        "foobar": {
            "timing": "@yearly",
            "command": "/bin/false",
            "user": "root",
            "workdir": "/root",
        }
    }}}
    AppConfigurationsManager("testapp", wanted=wanted).apply()
    assert "*/15 * * * * testapp cd '/var/www/testapp' && /bin/true" in read_file("/etc/cron.d/testapp")
    assert "@yearly root cd '/root' && /bin/false" in read_file("/etc/cron.d/testapp-foobar")

    AppConfigurationsManager("testapp", wanted={}).apply()

    assert not os.path.exists("/etc/cron.d/testapp")
    assert not os.path.exists("/etc/cron.d/testapp-foobar")


def test_conf_sudoers():

    assert not os.path.exists("/etc/sudoers.d/testapp")

    wanted = {"configurations": {"sudoers": { "main": {
        "commands": ["/bin/true", "/bin/false"]
    }}}}

    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists("/etc/sudoers.d/testapp")
    assert "testapp ALL = (root) NOPASSWD: /bin/true\n" in read_file("/etc/sudoers.d/testapp")
    assert "testapp ALL = (root) NOPASSWD: /bin/false" in read_file("/etc/sudoers.d/testapp")

    AppConfigurationsManager("testapp", wanted={}).apply()

    assert not os.path.exists("/etc/sudoers.d/testapp")


def test_conf_logrotate():

    assert not os.path.exists("/etc/logrotate.d/testapp")

    app_setting("testapp", "log_dir", "/var/log/testapp/")

    # Nominal case
    wanted = {"configurations": {"logrotate": {}}}

    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists("/etc/logrotate.d/testapp")

    AppConfigurationsManager("testapp", wanted={}).apply()

    assert not os.path.exists("/etc/logrotate.d/testapp")


def test_conf_app():

    os.system("useradd testapp")
    os.system("mkdir -p /var/www/testapp")
    assert not os.path.exists("/var/www/testapp/conf.ini")

    write_to_file("/etc/yunohost/apps/testapp/conf/conf.ini.template", '\n'.join([
        '# This is a dummy conf file',
        'APP = __APP__',
        'FOO = __FOO__'
    ]))

    wanted = {"configurations": {"app": {"main": {
        "path": "conf.ini",
        "template": "conf.ini.template",
    }}}}

    AppConfigurationsManager("testapp", wanted=wanted).apply()

    assert os.path.exists("/var/www/testapp/conf.ini")
    assert check_output("ls -l /var/www/testapp/conf.ini").startswith("-r-------- 1 testapp testapp ")
