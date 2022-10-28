#
# Copyright (c) 2022 YunoHost Contributors
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
import json

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import rm

from yunohost.hook import hook_callback, hook_exec
from yunohost.utils.error import YunohostError
from yunohost.repository import LocalBackupRepository, BackupArchive, HOOK_METHOD_DIR
logger = getActionLogger("yunohost.repository")


def hook_backup_call(self, action, chdir=None, **kwargs):
    """ Call a submethod of backup method hook

    Exceptions:
    backup_custom_ACTION_error -- Raised if the custom script failed
    """
    if isinstance(self, LocalBackupRepository):
        repository = self
        args = [action, "", "", repository.location, "", repository.description]
    else:
        repository = self.repository
        args = [action, self.work_dir, self.name, repository.location, "", ""]
    args += kwargs.values()

    env = {"YNH_BACKUP_" + key.upper(): str(value)
           for key, value in list(kwargs.items()) + list(repository.values.items())}

    return_code, return_data = hook_exec(
            f"{HOOK_METHOD_DIR}/{repository.method}",
            args=args,
            raise_on_error=False,
            chdir=chdir,
            env=env,
    )

    if return_code == 38:
        raise NotImplementedError()
    elif return_code != 0:
        raise YunohostError("backup_" + action + "_error")

    return return_code, return_data


class HookBackupRepository(LocalBackupRepository):
    method_name = "hook"

    # =================================================
    # Repository actions
    # =================================================
    def install(self):
        _, return_data = hook_backup_call(self, "install")
        if return_data.get("super"):
            super().install()

    def update(self):
        hook_backup_call(self, "update")

    def purge(self):
        _, return_data = hook_backup_call(self, "purge")
        if return_data.get("super"):
            super().purge()

    def list_archives_names(self, prefix=""):
        _, return_data = hook_backup_call(self, "list_archives_names",
                                          prefix=prefix)
        return return_data


class HookBackupArchive(BackupArchive):
    # =================================================
    # Archive actions
    # =================================================
    def need_organized_files(self):
        return_code, _ = hook_backup_call(self, "need_mount")
        return int(return_code) == 0

    def backup(self):
        hook_backup_call(self, "backup")
        #self._call('backup', self.work_dir, self.name, self.repo.location, self.manager.size, self.manager.description)

    def delete(self):
        hook_backup_call(self, "delete")

    def list(self, with_info=False):
        return_code, return_data = hook_backup_call(self, "list_files",
                                                    with_info=with_info)

        return return_data

    def download(self, exclude_paths=[]):
        hook_backup_call(self, "download")

    def extract(self, paths=[], target=None, exclude_paths=[]):
        paths, destination, exclude_paths = super().extract(paths, target, exclude_paths)
        hook_backup_call(self, "extract",
                         chdir=target,
                         paths=",".join(paths),
                         exclude=",".join(exclude_paths))

    def mount(self, path):
        hook_backup_call(self, "mount", path=path)
