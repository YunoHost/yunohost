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

import logging
from typing import Any

import yaml

from yunohost.tools import Migration
from yunohost.app import app_list

from yunohost.firewall import YunoFirewall

logger = logging.getLogger("yunohost.migration")


class MyMigration(Migration):
    "Rework the firewall configuration"

    introduced_in_version = "12.1"
    mode = "auto"

    apps = app_list(full=True)

    def _app_comment_of_port(self, port: int) -> str:
        for app in self.apps["apps"]:
            settings = app["settings"]
            port_keys: list[str] = [
                key
                for key in settings.keys()
                if key.startswith("port_") or key == "port"
            ]
            for key in port_keys:
                if settings[key] not in [port, str(port)]:
                    continue
                port_name = "main" if key == "port" else key.removeprefix("port_")
                return f"App {app['id']}: {port_name} port"

        return ""

    def firewall_file_migrate(self) -> None:
        old_data = yaml.safe_load(
            YunoFirewall.FIREWALL_FILE.open("r", encoding="utf-8")
        )

        new_data: dict[str, Any] = {
            "router_forwarding_upnp": old_data["uPnP"]["enabled"],
            "tcp": {},
            "udp": {},
        }
        for proto in ["TCP", "UDP"]:
            new_data[proto.lower()] = {
                port: {
                    "open": True,
                    "upnp": port in old_data["uPnP"][proto],
                    "comment": self._app_comment_of_port(port),
                }
                for port in set(old_data["ipv4"][proto] + old_data["ipv6"][proto])
            }
        yaml.dump(new_data, YunoFirewall.FIREWALL_FILE.open("w", encoding="utf-8"))

    def run(self):
        self.firewall_file_migrate()

    def run_after_system_restore(self):
        self.run()
