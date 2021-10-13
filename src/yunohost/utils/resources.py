# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2021 YUNOHOST.ORG

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
import os
import copy
import psutil
from typing import Dict, Any

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.filesystem import free_space_in_directory


class AppResource:

    def __init__(self, properties: Dict[str, Any], app_id: str, app_settings):

        for key, value in self.default_properties.items():
            setattr(self, key, value)

        for key, value in properties:
            setattr(self. key, value)


M = 1024 ** 2
G = 1024 * M
sizes = {
    "10M": 10 * M,
    "20M": 20 * M,
    "40M": 40 * M,
    "80M": 80 * M,
    "100M": 100 * M,
    "200M": 200 * M,
    "400M": 400 * M,
    "800M": 800 * M,
    "1G": 1 * G,
    "2G": 2 * G,
    "4G": 4 * G,
    "8G": 8 * G,
    "10G": 10 * G,
    "20G": 20 * G,
    "40G": 40 * G,
    "80G": 80 * G,
}


class DiskAppResource(AppResource):
    type = "disk"

    default_properties = {
        "space": "10M",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        # FIXME: better error handling
        assert self.space in sizes

    def provision_or_update(self, context: Dict):

        if free_space_in_directory("/") <= sizes[self.space] \
        or free_space_in_directory("/var") <= sizes[self.space]:
            raise YunohostValidationError("Not enough disk space")  # FIXME: i18n / better messaging

    def deprovision(self, context: Dict):
        pass


class RamAppResource(AppResource):
    type = "ram"

    default_properties = {
        "build": "10M",
        "runtime": "10M",
        "include_swap": False
    }

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        # FIXME: better error handling
        assert self.build in sizes
        assert self.runtime in sizes
        assert isinstance(self.include_swap, bool)

    def provision_or_update(self, context: Dict):

        memory = psutil.virtual_memory().available
        if self.include_swap:
            memory += psutil.swap_memory().available

        max_size = max(sizes[self.build], sizes[self.runtime])

        if memory <= max_size:
            raise YunohostValidationError("Not enough RAM/swap")  # FIXME: i18n / better messaging

    def deprovision(self, context: Dict):
        pass


class WebpathAppResource(AppResource):
    type = "webpath"

    default_properties = {
        "url": "__DOMAIN____PATH__"
    }

    def provision_or_update(self, context: Dict):

        from yunohost.app import _assert_no_conflicting_apps

        # Check the url is available
        domain = context["app_settings"]["domain"]
        path = context["app_settings"]["path"] or "/"
        _assert_no_conflicting_apps(domain, path, ignore_app=context["app"])
        context["app_settings"]["path"] = path

        if context["app_action"] == "install":
            # Initially, the .main permission is created with no url at all associated
            # When the app register/books its web url, we also add the url '/'
            # (meaning the root of the app, domain.tld/path/)
            # and enable the tile to the SSO, and both of this should match 95% of apps
            # For more specific cases, the app is free to change / add urls or disable
            # the tile using the permission helpers.
            permission_url(app + ".main", url="/", sync_perm=False)
            user_permission_update(app + ".main", show_tile=True, sync_perm=False)
            permission_sync_to_user()

    def deprovision(self, context: Dict):
        del context["app_settings"]["domain"]
        del context["app_settings"]["path"]


class PortAppResource(AppResource):
    type = "port"

    default_properties = {
        "value": 1000
    }

    def _port_is_used(self, port):

        # FIXME : this could be less brutal than two os.system ...
        cmd1 = "ss --numeric --listening --tcp --udp | awk '{print$5}' | grep --quiet --extended-regexp ':%s$'" % port
        # This second command is mean to cover (most) case where an app is using a port yet ain't currently using it for some reason (typically service ain't up)
        cmd2 = f"grep -q \"port: '{port}'\" /etc/yunohost/apps/*/settings.yml"
        return os.system(cmd1) == 0 and os.system(cmd2) == 0

    def provision_or_update(self, context: str):

        # Don't do anything if port already defined ?
        if context["app_settings"].get("port"):
            return

        port = self.value
        while self._port_is_used(port):
            port += 1

        context["app_settings"]["port"] = port

    def deprovision(self, context: Dict):
        raise NotImplementedError()


class UserAppResource(AppResource):
    type = "user"

    default_properties = {
        "username": "__APP__",
        "home_dir": "/var/www/__APP__",
        "use_shell": False,
        "groups": []
    }

    def provision_or_update(self, context: str):
        raise NotImplementedError()

    def deprovision(self, context: Dict):
        raise NotImplementedError()


class InstalldirAppResource(AppResource):
    type = "installdir"

    default_properties = {
        "dir": "/var/www/__APP__",
        "alias": "final_path"
    }

    def provision_or_update(self, context: Dict):

        if context["app_action"] in ["install", "restore"]:
            if os.path.exists(self.dir):
                raise YunohostValidationError(f"Path {self.dir} already exists")

        if "installdir" not in context["app_settings"]:
            context["app_settings"]["installdir"] = self.dir
        context["app_settings"][self.alias] = context["app_settings"]["installdir"]

    def deprovision(self, context: Dict):
        # FIXME: should it rm the directory during remove/deprovision ?
        pass


class DatadirAppResource(AppResource):
    type = "datadir"

    default_properties = {
        "dir": "/home/yunohost.app/__APP__",
    }

    def provision_or_update(self, context: Dict):
        if "datadir" not in context["app_settings"]:
            context["app_settings"]["datadir"] = self.dir

    def deprovision(self, context: Dict):
        # FIXME: should it rm the directory during remove/deprovision ?
        pass


class DBAppResource(AppResource):
    type = "db"

    default_properties = {
        "type": "mysql"
    }

    def provision_or_update(self, context: str):
        raise NotImplementedError()

    def deprovision(self, context: Dict):
        raise NotImplementedError()
