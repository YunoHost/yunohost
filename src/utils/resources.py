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
from typing import Dict, Any

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import mkdir, chown, chmod, write_to_file

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.hook import hook_exec

logger = getActionLogger("yunohost.app_resources")


class AppResourceManager(object):

    def __init__(self, app: str, manifest: str):

        self.app = app
        self.resources = {name: AppResourceClassesByType[name](infos, app)
                          for name, infos in resources_dict.items()}

    def apply(self):






    def validate_resource_availability(self):

        for name, resource in self.resources.items():
            resource.validate_availability(context={})

    def provision_or_update_resources(self):

        for name, resource in self.resources.items():
            logger.info("Running provision_or_upgrade for {self.type}")
            resource.provision_or_update(context={})


class AppResource(object):

    def __init__(self, properties: Dict[str, Any], app: str):

        self.app = app

        for key, value in self.default_properties.items():
            setattr(self, key, value)

        for key, value in properties.items():
            setattr(self, key, value)

    def get_setting(self, key):
        from yunohost.app import app_setting
        return app_setting(self.app, key)

    def set_setting(self, key, value):
        from yunohost.app import app_setting
        app_setting(self.app, key, value=value)

    def delete_setting(self, key, value):
        from yunohost.app import app_setting
        app_setting(self.app, key, delete=True)

    def validate_availability(self, context: Dict):
        pass

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

        print(env_)

        # FIXME : use the hook_exec_with_debug_instructions_stuff
        ret, _ = hook_exec(script_path, env=env_)
        print(ret)


class WebpathResource(AppResource):
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

    type = "webpath"
    priority = 10

    default_properties = {
        "full_domain": False,
    }

    def validate_availability(self, context):

        from yunohost.app import _assert_no_conflicting_apps

        domain = self.get_setting("domain")
        path = self.get_setting("path") if not self.full_domain else "/"
        _assert_no_conflicting_apps(domain, path, ignore_app=self.app)

    def provision_or_update(self, context: Dict):

        # Nothing to do ? Just setting the domain/path during install
        # already provisions it ...
        return  # FIXME

    def deprovision(self, context: Dict):
        self.delete_setting("domain")
        self.delete_setting("path")


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
        "allow_ssh": []
        "allow_sftp": []
    }

    def validate_availability(self, context):
        pass
        # FIXME : do we care if user already exists ? shouldnt we assume that user $app corresponds to the app ...?

        # FIXME : but maybe we should at least check that no corresponding yunohost user exists

        #if os.system(f"getent passwd {self.username} &>/dev/null") != 0:
        #    raise YunohostValidationError(f"User {self.username} already exists")
        #if os.system(f"getent group {self.username} &>/dev/null") != 0:
        #    raise YunohostValidationError(f"Group {self.username} already exists")

    def provision_or_update(self, context: Dict):

        if os.system(f"getent passwd {self.app} &>/dev/null") != 0:
            cmd = f"useradd --system --user-group {self.app}"
            os.system(cmd)

        if os.system(f"getent passwd {self.app} &>/dev/null") == 0:
            raise YunohostError(f"Failed to create system user for {self.app}")

        groups = []
        if self.allow_ssh:
            groups.append("ssh.app")
        if self.allow_sftp:
            groups.append("sftp.app")
        groups =

        cmd = f"usermod -a -G {groups} {self.app}"
        # FIXME : handle case where group gets removed
        os.system(cmd)

#        useradd $user_home_dir --system --user-group $username $shell || ynh_die --message="Unable to create $username system account"
#    for group in $groups; do
#        usermod -a -G "$group" "$username"
#    done


# | arg: -g, --groups       - Add the user to system groups. Typically meant to add the user to the ssh.app / sftp.app group (e.g. for borgserver, my_webapp)


    def deprovision(self, context: Dict):

        self._run_script("deprovision",
                         f'ynh_system_user_delete "{self.username}"')

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

    def validate_availability(self, context):
        pass

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

        chmod(self.dir, oct(int(perm_octal)))
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

    def validate_availability(self, context):
        pass
        # Nothing to do ? If datadir already exists then it may be legit data
        # from a previous install

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

        chmod(self.dir, oct(int(perm_octal)))
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


class PortAppResource(AppResource):
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
        "type": "internal",    # FIXME : implement logic for exposed port (allow/disallow in firewall ?)
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
