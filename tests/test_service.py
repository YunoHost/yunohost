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

from yunohost.service import (
    _get_services,
    _save_services,
    service_add,
    service_log,
    service_reload_or_restart,
    service_remove,
    service_status,
)

from .conftest import raiseYunohostError


def setup_function(function):
    clean()


def teardown_function(function):
    clean()


def clean():
    # To run these tests, we assume ssh(d) service exists and is running
    assert os.system("pgrep sshd >/dev/null") == 0

    services = _get_services()
    assert "ssh" in services

    if "dummyservice" in services:
        del services["dummyservice"]

    if "networking" in services:
        del services["networking"]

    _save_services(services)

    if os.path.exists("/etc/nginx/conf.d/broken.conf"):
        os.remove("/etc/nginx/conf.d/broken.conf")
        os.system("systemctl reload-or-restart nginx")


def test_service_status_all():
    status = service_status()
    assert "ssh" in status.keys()
    assert status["ssh"]["status"] == "running"


def test_service_status_single():
    status = service_status("ssh")
    assert "status" in status.keys()
    assert status["status"] == "running"


def test_service_log():
    logs = service_log("ssh")
    assert "journalctl" in logs.keys()
    assert "/var/log/auth.log" in logs.keys()


def test_service_status_unknown_service(mocker):
    with raiseYunohostError(mocker, "service_unknown"):
        service_status(["ssh", "doesnotexists"])


def test_service_add():
    service_add("dummyservice", description="A dummy service to run tests")
    assert "dummyservice" in service_status().keys()


def test_service_add_real_service():
    service_add("networking")
    assert "networking" in service_status().keys()


def test_service_remove():
    service_add("dummyservice", description="A dummy service to run tests")
    assert "dummyservice" in service_status().keys()
    service_remove("dummyservice")
    assert "dummyservice" not in service_status().keys()


def test_service_remove_service_that_doesnt_exists(mocker):
    assert "dummyservice" not in service_status().keys()

    with raiseYunohostError(mocker, "service_unknown"):
        service_remove("dummyservice")

    assert "dummyservice" not in service_status().keys()


def test_service_update_to_add_properties():
    service_add("dummyservice", description="dummy")
    assert not _get_services()["dummyservice"].get("test_status")
    service_add("dummyservice", description="dummy", test_status="true")
    assert _get_services()["dummyservice"].get("test_status") == "true"


def test_service_update_to_change_properties():
    service_add("dummyservice", description="dummy", test_status="false")
    assert _get_services()["dummyservice"].get("test_status") == "false"
    service_add("dummyservice", description="dummy", test_status="true")
    assert _get_services()["dummyservice"].get("test_status") == "true"


def test_service_update_to_remove_properties():
    service_add("dummyservice", description="dummy", test_status="false")
    assert _get_services()["dummyservice"].get("test_status") == "false"
    service_add("dummyservice", description="dummy", test_status="")
    assert not _get_services()["dummyservice"].get("test_status")


def test_service_conf_broken():
    os.system("echo pwet > /etc/nginx/conf.d/broken.conf")

    status = service_status("nginx")
    assert status["status"] == "running"
    assert status["configuration"] == "broken"
    assert "broken.conf" in status["configuration-details"][0]

    # Service reload-or-restart should check that the conf ain't valid
    # before reload-or-restart, hence the service should still be running
    service_reload_or_restart("nginx")
    assert status["status"] == "running"

    os.remove("/etc/nginx/conf.d/broken.conf")
