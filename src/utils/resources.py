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
import shutil
from typing import Dict, Any

from moulinette.utils.process import check_output
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import mkdir, chown, chmod, write_to_file
from moulinette.utils.filesystem import (
    rm,
)

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.hook import hook_exec

logger = getActionLogger("yunohost.app_resources")


class AppResourceManager:

    def __init__(self, app: str, current: Dict, wanted: Dict):

        self.app = app
        self.current = current
        self.wanted = wanted

    def apply(self, rollback_if_failure, **context):

        todos = list(self.compute_todos())
        completed = []
        rollback = False
        exception = None

        for todo, name, old, new in todos:
            try:
                if todo == "deprovision":
                    # FIXME : i18n, better info strings
                    logger.info(f"Deprovisionning {name} ...")
                    old.deprovision(context=context)
                elif todo == "provision":
                    logger.info(f"Provisionning {name} ...")
                    new.provision_or_update(context=context)
                elif todo == "update":
                    logger.info(f"Updating {name} ...")
                    new.provision_or_update(context=context)
            except Exception as e:
                exception = e
                # FIXME: better error handling ? display stacktrace ?
                logger.warning(f"Failed to {todo} for {name} : {e}")
                if rollback_if_failure:
                    rollback = True
                    completed.append((todo, name, old, new))
                    break
                else:
                    pass
            else:
                completed.append((todo, name, old, new))

        if rollback:
            for todo, name, old, new in completed:
                try:
                    # (NB. here we want to undo the todo)
                    if todo == "deprovision":
                        # FIXME : i18n, better info strings
                        logger.info(f"Reprovisionning {name} ...")
                        old.provision_or_update(context=context)
                    elif todo == "provision":
                        logger.info(f"Deprovisionning {name} ...")
                        new.deprovision(context=context)
                    elif todo == "update":
                        logger.info(f"Reverting {name} ...")
                        old.provision_or_update(context=context)
                except Exception as e:
                    # FIXME: better error handling ? display stacktrace ?
                    logger.error(f"Failed to rollback {name} : {e}")

        if exception:
            raise exception

    def compute_todos(self):

        for name, infos in reversed(self.current["resources"].items()):
            if name not in self.wanted["resources"].keys():
                resource = AppResourceClassesByType[name](infos, self.app, self)
                yield ("deprovision", name, resource, None)

        for name, infos in self.wanted["resources"].items():
            wanted_resource = AppResourceClassesByType[name](infos, self.app, self)
            if name not in self.current["resources"].keys():
                yield ("provision", name, None, wanted_resource)
            else:
                infos_ = self.current["resources"][name]
                current_resource = AppResourceClassesByType[name](infos_, self.app, self)
                yield ("update", name, current_resource, wanted_resource)


class AppResource:

    def __init__(self, properties: Dict[str, Any], app: str, manager: str):

        self.app = app
        self.manager = manager

        for key, value in self.default_properties.items():
            if isinstance(value, str):
                value = value.replace("__APP__", self.app)
            setattr(self, key, value)

        for key, value in properties.items():
            if isinstance(value, str):
                value = value.replace("__APP__", self.app)
            setattr(self, key, value)

    def get_setting(self, key):
        from yunohost.app import app_setting
        return app_setting(self.app, key)

    def set_setting(self, key, value):
        from yunohost.app import app_setting
        app_setting(self.app, key, value=value)

    def delete_setting(self, key):
        from yunohost.app import app_setting
        app_setting(self.app, key, delete=True)

    def _run_script(self, action, script, env={}, user="root"):

        from yunohost.app import _make_tmp_workdir_for_app, _make_environment_for_app_script

        tmpdir = _make_tmp_workdir_for_app(app=self.app)

        env_ = _make_environment_for_app_script(self.app, workdir=tmpdir, action=f"{action}_{self.type}")
        env_.update(env)

        script_path = f"{tmpdir}/{action}_{self.type}"
        script = f"""
source /usr/share/yunohost/helpers
ynh_abort_if_errors

{script}
"""

        write_to_file(script_path, script)

        #print(env_)

        # FIXME : use the hook_exec_with_debug_instructions_stuff
        ret, _ = hook_exec(script_path, env=env_)

        #print(ret)


class PermissionsResource(AppResource):
    """
        is_provisioned -> main perm exists
        is_available   -> perm urls do not conflict

        update    -> refresh/update values for url/additional_urls/show_tile/auth/protected/... create new perms / delete any perm not listed
        provision -> same as update?

        deprovision -> delete permissions

        deep_clean  -> delete permissions for any __APP__.foobar where app not in app list...

        backup -> handled elsewhere by the core, should be integrated in there (dump .ldif/yml?)
        restore -> handled by the core, should be integrated in there (restore .ldif/yml?)
    """

    type = "permissions"
    priority = 10

    default_properties = {
    }

    default_perm_properties = {
        "url": None,
        "additional_urls": [],
        "auth_header": True,
        "allowed": None,
        "show_tile": None,  # To be automagically set to True by default if an url is defined and show_tile not provided
        "protected": False,
    }

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):

        for perm, infos in properties.items():
            properties[perm] = copy.copy(self.default_perm_properties)
            properties[perm].update(infos)
            if properties[perm]["show_tile"] is None:
                properties[perm]["show_tile"] = bool(properties[perm]["url"])

        if isinstance(properties["main"]["url"], str) and properties["main"]["url"] != "/":
            raise YunohostError("URL for the 'main' permission should be '/' for webapps (or undefined/None for non-webapps). Note that / refers to the install url of the app")

        super().__init__({"permissions": properties}, *args, **kwargs)

    def provision_or_update(self, context: Dict):

        from yunohost.permission import (
            permission_create,
            #permission_url,
            permission_delete,
            user_permission_list,
            user_permission_update,
            permission_sync_to_user,
        )

        # Delete legacy is_public setting if not already done
        self.delete_setting("is_public")

        existing_perms = user_permission_list(short=True, apps=[self.app])["permissions"]
        for perm in existing_perms:
            if perm.split(".") not in self.permissions.keys():
                permission_delete(perm, force=True, sync_perm=False)

        for perm, infos in self.permissions.items():
            if f"{self.app}.{perm}" not in existing_perms:
                # Use the 'allowed' key from the manifest,
                # or use the 'init_{perm}_permission' from the install questions
                # which is temporarily saved as a setting as an ugly hack to pass the info to this piece of code...
                init_allowed = infos["allowed"] or self.get_setting(f"init_{perm}_permission") or []
                permission_create(
                    f"{self.app}.{perm}",
                    allowed=init_allowed,
                    # This is why the ugly hack with self.manager exists >_>
                    label=self.manager.wanted["name"] if perm == "main" else perm,
                    url=infos["url"],
                    additional_urls=infos["additional_urls"],
                    auth_header=infos["auth_header"],
                    sync_perm=False,
                )
                self.delete_setting(f"init_{perm}_permission")

                user_permission_update(
                    f"{self.app}.{perm}",
                    show_tile=infos["show_tile"],
                    protected=infos["protected"],
                    sync_perm=False
                )
            else:
                pass
                # FIXME : current implementation of permission_url is hell for
                # easy declarativeness of additional_urls >_> ...
                #permission_url(f"{self.app}.{perm}", url=infos["url"], auth_header=infos["auth_header"], sync_perm=False)

        permission_sync_to_user()

    def deprovision(self, context: Dict):

        from yunohost.permission import (
            permission_delete,
            user_permission_list,
            permission_sync_to_user,
        )

        existing_perms = user_permission_list(short=True, apps=[self.app])["permissions"]
        for perm in existing_perms:
            permission_delete(perm, force=True, sync_perm=False)

        permission_sync_to_user()


class SystemuserAppResource(AppResource):
    """
        is_provisioned -> user __APP__ exists
        is_available   -> user and group __APP__ doesn't exists

        provision -> create user
        update    -> update values for home / shell / groups

        deprovision -> delete user

        deep_clean  -> uuuuh ? delete any user that could correspond to an app x_x ?

        backup -> nothing
        restore -> provision
    """

    type = "system_user"
    priority = 20

    default_properties = {
        "allow_ssh": [],
        "allow_sftp": []
    }

    def provision_or_update(self, context: Dict):

        # FIXME : validate that no yunohost user exists with that name?
        # and/or that no system user exists during install ?

        if not check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            # FIXME: improve error handling ?
            cmd = f"useradd --system --user-group {self.app}"
            os.system(cmd)

        if not check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            raise YunohostError(f"Failed to create system user for {self.app}", raw_msg=True)

        groups = set(check_output(f"groups {self.app}").strip().split()[2:])

        if self.allow_ssh:
            groups.add("ssh.app")
        if self.allow_sftp:
            groups.add("sftp.app")

        os.system(f"usermod -G {','.join(groups)} {self.app}")

    def deprovision(self, context: Dict):

        if check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            os.system(f"deluser {self.app} >/dev/null")
        if check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            raise YunohostError(f"Failed to delete system user for {self.app}")

        if check_output(f"getent group {self.app} &>/dev/null || true").strip():
            os.system(f"delgroup {self.app} >/dev/null")
        if check_output(f"getent group {self.app} &>/dev/null || true").strip():
            raise YunohostError(f"Failed to delete system user for {self.app}")

        # FIXME : better logging and error handling, add stdout/stderr from the deluser/delgroup commands...


#    # Check if the user exists on the system
#if os.system(f"getent passwd {self.username} &>/dev/null") != 0:
#    if ynh_system_user_exists "$username"; then
#        deluser $username
#    fi
#    # Check if the group exists on the system
#if os.system(f"getent group {self.username} &>/dev/null") != 0:
#    if ynh_system_group_exists "$username"; then
#        delgroup $username
#    fi
#

class InstalldirAppResource(AppResource):
    """
        is_provisioned -> setting install_dir exists + /dir/ exists
        is_available   -> /dir/ doesn't exists

        provision -> create setting + create dir
        update    -> update perms ?

        deprovision -> delete dir + delete setting

        deep_clean  -> uuuuh ? delete any dir in /var/www/ that would not correspond to an app x_x ?

        backup -> cp install dir
        restore -> cp install dir
    """

    type = "install_dir"
    priority = 30

    default_properties = {
        "dir": "/var/www/__APP__",    # FIXME or choose to move this elsewhere nowadays idk...
        "alias": None,
        "owner": "__APP__:rx",
        "group": "__APP__:rx",
    }

    # FIXME: change default dir to /opt/stuff if app ain't a webapp ...
    # FIXME: what do in a scenario where the location changed

    def provision_or_update(self, context: Dict):

        current_install_dir = self.get_setting("install_dir")

        # If during install, /var/www/$app already exists, assume that it's okay to remove and recreate it
        # FIXME : is this the right thing to do ?
        if not current_install_dir and os.path.isdir(self.dir):
            rm(self.dir, recursive=True)

        if not os.path.isdir(self.dir):
            # Handle case where install location changed, in which case we shall move the existing install dir
            if current_install_dir and os.path.isdir(current_install_dir):
                shutil.move(current_install_dir, self.dir)
            else:
                mkdir(self.dir)

        owner, owner_perm = self.owner.split(":")
        group, group_perm = self.group.split(":")
        owner_perm_octal = (4 if "r" in owner_perm else 0) + (2 if "w" in owner_perm else 0) + (1 if "x" in owner_perm else 0)
        group_perm_octal = (4 if "r" in group_perm else 0) + (2 if "w" in group_perm else 0) + (1 if "x" in group_perm else 0)
        perm_octal = str(owner_perm_octal) + str(group_perm_octal) + "0"

        chmod(self.dir, int(perm_octal))
        chown(self.dir, owner, group)

        self.set_setting("install_dir", self.dir)
        if self.alias:
            self.set_setting(self.alias, self.dir)

    def deprovision(self, context: Dict):
        # FIXME : check that self.dir has a sensible value to prevent catastrophes
        if os.path.isdir(self.dir):
            rm(self.dir, recursive=True)


class DatadirAppResource(AppResource):
    """
        is_provisioned -> setting data_dir exists + /dir/ exists
        is_available   -> /dir/ doesn't exists

        provision -> create setting + create dir
        update    -> update perms ?

        deprovision -> (only if purge enabled...) delete dir + delete setting

        deep_clean  -> zblerg idk nothing

        backup -> cp data dir ? (if not backup_core_only)
        restore -> cp data dir ? (if in backup)
    """

    type = "data_dir"
    priority = 40

    default_properties = {
        "dir": "/home/yunohost.app/__APP__",    # FIXME or choose to move this elsewhere nowadays idk...
        "owner": "__APP__:rx",
        "group": "__APP__:rx",
    }

    def provision_or_update(self, context: Dict):

        current_data_dir = self.get_setting("data_dir")

        if not os.path.isdir(self.dir):
            # Handle case where install location changed, in which case we shall move the existing install dir
            if current_data_dir and os.path.isdir(current_data_dir):
                shutil.move(current_data_dir, self.dir)
            else:
                mkdir(self.dir)

        owner, owner_perm = self.owner.split(":")
        group, group_perm = self.group.split(":")
        owner_perm_octal = (4 if "r" in owner_perm else 0) + (2 if "w" in owner_perm else 0) + (1 if "x" in owner_perm else 0)
        group_perm_octal = (4 if "r" in group_perm else 0) + (2 if "w" in group_perm else 0) + (1 if "x" in group_perm else 0)
        perm_octal = str(owner_perm_octal) + str(group_perm_octal) + "0"

        chmod(self.dir, int(perm_octal))
        chown(self.dir, owner, group)

        self.set_setting("data_dir", self.dir)

    def deprovision(self, context: Dict):
        # FIXME: This should rm the datadir only if purge is enabled
        pass
        #if os.path.isdir(self.dir):
        #    rm(self.dir, recursive=True)


#
#class SourcesAppResource(AppResource):
#    """
#        is_provisioned -> (if pre_download,) cache exists with appropriate checksum
#        is_available   -> curl HEAD returns 200
#
#        update    -> none?
#        provision ->  full download + check checksum
#
#        deprovision -> remove cache for __APP__ ?
#
#        deep_clean  -> remove all cache
#
#        backup -> nothing
#        restore -> nothing
#    """
#
#    type = "sources"
#
#    default_properties = {
#        "main": {"url": "?", "sha256sum": "?", "predownload": True}
#    }
#
#    def validate_availability(self, context):
#        # ? FIXME
#        # call request.head on the url idk
#        pass
#
#    def provision_or_update(self, context: Dict):
#        # FIXME
#        return
#

class AptDependenciesAppResource(AppResource):
    """
        is_provisioned -> package __APP__-ynh-deps exists  (ideally should check the Depends: but hmgn)
        is_available   -> True? idk

        update -> update deps on __APP__-ynh-deps
        provision -> create/update deps on __APP__-ynh-deps

        deprovision -> remove __APP__-ynh-deps (+autoremove?)

        deep_clean  -> remove any __APP__-ynh-deps for app not in app list

        backup -> nothing
        restore = provision
    """

    type = "apt"
    priority = 50

    default_properties = {
        "packages": [],
        "extras": {}
    }

    def validate_availability(self, context):
        # ? FIXME
        # call helpers idk ...
        pass

    def provision_or_update(self, context: Dict):

        # FIXME : implement 'extras' management
        self._run_script("provision_or_update",
                         "ynh_install_app_dependencies $apt_dependencies",
                         {"apt_dependencies": self.packages})

    def deprovision(self, context: Dict):

        self._run_script("deprovision",
                         "ynh_remove_app_dependencies")


class PortResource(AppResource):
    """
        is_provisioned -> port setting exists and is not the port used by another app (ie not in another app setting)
        is_available   -> true

        update    -> true
        provision -> find a port not used by any app

        deprovision -> delete the port setting

        deep_clean  -> ?

        backup -> nothing (backup port setting)
        restore -> nothing (restore port setting)
    """

    type = "port"
    priority = 70

    default_properties = {
        "default": 1000,
        "expose": False,    # FIXME : implement logic for exposed port (allow/disallow in firewall ?)
    }

    def _port_is_used(self, port):

        # FIXME : this could be less brutal than two os.system ...
        cmd1 = "ss --numeric --listening --tcp --udp | awk '{print$5}' | grep --quiet --extended-regexp ':%s$'" % port
        # This second command is mean to cover (most) case where an app is using a port yet ain't currently using it for some reason (typically service ain't up)
        cmd2 = f"grep --quiet \"port: '{port}'\" /etc/yunohost/apps/*/settings.yml"
        return os.system(cmd1) == 0 and os.system(cmd2) == 0

    def provision_or_update(self, context: str):

        # Don't do anything if port already defined ?
        if self.get_setting("port"):
            return

        port = self.default
        while self._port_is_used(port):
            port += 1

        self.set_setting("port", port)

    def deprovision(self, context: Dict):

        self.delete_setting("port")


#class DBAppResource(AppResource):
#    """
#        is_provisioned -> setting db_user, db_name, db_pwd exists
#        is_available   -> db doesn't already exists ( ... also gotta make sure that mysql / postgresql is indeed installed ... or will be after apt provisions it)
#
#        provision -> setup the db + init the setting
#        update    -> ??
#
#        deprovision -> delete the db
#
#        deep_clean  -> ... idk look into any db name that would not be related to any app ...
#
#        backup -> dump db
#        restore -> setup + inject db dump
#    """
#
#    type = "db"
#
#    default_properties = {
#        "type": "mysql"
#    }
#
#    def validate_availability(self, context):
#        # FIXME : checking availability sort of imply that mysql / postgresql is installed
#        # or we gotta make sure mariadb-server or postgresql is gonna be installed (apt resource)
#        pass
#
#    def provision_or_update(self, context: str):
#        raise NotImplementedError()
#
#    def deprovision(self, context: Dict):
#        raise NotImplementedError()
#

AppResourceClassesByType = {c.type: c for c in AppResource.__subclasses__()}
