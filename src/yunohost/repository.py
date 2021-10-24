# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 Yunohost

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

""" yunohost_repository.py

    Manage backup repositories
"""
import os
import re
import time
import subprocess
import re
import urllib.parse

from moulinette import Moulinette, m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, read_yaml, write_to_json, rm, mkdir, chmod, chown
from moulinette.utils.network import download_text, download_json


from yunohost.utils.config import ConfigPanel, Question
from yunohost.utils.error import YunohostError
from yunohost.utils.filesystem import space_used_in_directory, disk_usage, binary_to_human
from yunohost.utils.network import get_ssh_public_key, shf_request, SHF_BASE_URL
from yunohost.log import OperationLogger, is_unit_operation

logger = getActionLogger('yunohost.repository')
REPOSITORIES_DIR = '/etc/yunohost/repositories'
CACHE_INFO_DIR = "/var/cache/yunohost/{repository}"
REPOSITORY_CONFIG_PATH = "/usr/share/yunohost/other/config_repository.toml"
# TODO split ConfigPanel.get to extract "Format result" part and be able to override it
# TODO Migration
# TODO Remove BackupRepository.get_or_create()
# TODO Backup method
# TODO API params to get description of forms
# TODO tests
# TODO detect external hard drive already mounted and suggest it
# TODO F2F client delete
# TODO F2F server
# TODO i18n pattern error

class BackupRepository(ConfigPanel):
    """
    BackupRepository manage all repository the admin added to the instance
    """
    entity_type = "backup_repository"
    save_path_tpl = "/etc/yunohost/backup/repositories/{entity}.yml"
    save_mode = "full"
    need_organized_files = True
    method_name = ""

    @staticmethod
    def split_location(location):
        """
        Split a repository location into protocol, user, domain and path
        """
        if "/" not in location:
            return { "domain": location }

        location_regex = r'^((?P<protocol>ssh://)?(?P<user>[^@ ]+)@(?P<domain>[^: ]+):((?P<port>\d+)/)?)?(?P<path>[^:]+)$'
        location_match = re.match(location_regex, location)

        if location_match is None:
            raise YunohostError('backup_repositories_invalid_location',
                                location=location)
        return {
            'protocol': location_match.group('protocol'),
            'user': location_match.group('user'),
            'domain': location_match.group('domain'),
            'port': location_match.group('port'),
            'path': location_match.group('path')
        }

    @classmethod
    def list(cls, space_used=False, full=False):
        """
        List available repositories where put archives
        """
        repositories = super().list()

        if not full:
            return repositories

        for repo in repositories:
            try:
                repositories[repo] = BackupRepository(repo).info(space_used)
            except Exception as e:
                logger.error(f"Unable to open repository {repo}")

        return repositories


    # =================================================
    # Config Panel Hooks
    # =================================================

    def post_ask__domain(self, question):
        """ Detect if the domain support Self-Hosting Federation protocol
        """
        #import requests
        # FIXME What if remote server is self-signed ?
        # FIXME What if remote server is unreachable temporarily ?
        url = SHF_BASE_URL.format(domain=question.value) + "/"
        try:
            #r = requests.get(url, timeout=10)
            download_text(url, timeout=10)
        except MoulinetteError as e:
            logger.debug("SHF not running")
            return { 'is_shf': False }
        logger.debug("SHF running")
        return { 'is_shf': True }


    # =================================================
    # Config Panel Override
    # =================================================
    def _get_default_values(self):
        values = super()._get_default_values()
        # TODO move that in a getter hooks ?
        values["public_key"] = get_ssh_public_key()
        return values

    def _load_current_values(self):
        super()._load_current_values()

        if 'location' in self.values:
            self.values.update(BackupRepository.split_location(self.values['location']))
        self.values['is_remote'] = bool(self.values.get('domain'))

        if self.values.get('method') == 'tar' and self.values['is_remote']:
            raise YunohostError("repository_tar_only_local")

        if 'shf_id' in self.values:
            self.values['is_shf'] = bool(self.values['shf_id'])
        self._cast_by_method()

    def _parse_pre_answered(self, *args):
        super()._parse_pre_answered(*args)
        if 'location'  in self.args:
            self.args.update(BackupRepository.split_location(self.args['location']))
        if 'domain' in self.args:
            self.args['is_remote'] = bool(self.args['domain'])
            self.args['method'] = "borg"
        elif self.args.get('method') == 'tar':
            self.args['is_remote'] = False
        self._cast_by_method()

    def _apply(self):
        # Activate / update services
        if not os.path.exists(self.save_path):
            self.install()
        else:
            self.update()

        # Clean redundant values before to register
        for prop in ['is_remote', 'domain', 'port', 'user', 'path',
                     'creation', 'is_shf', 'shortname']:
            self.values.pop(prop, None)
            self.new_values.pop(prop, None)
        super()._apply()


    # =================================================
    # BackupMethod encapsulation
    # =================================================
    @property
    def location(self):
        if not self.future_values:
            return None

        if not self.is_remote:
            return self.path

        return f"ssh://{self.user}@{self.domain}:{self.port}/{self.path}"

    def _cast_by_method(self):
        if not self.future_values:
            return

        if self.__class__ == BackupRepository:
            if self.method == 'tar':
                self.__class__ = TarBackupRepository
            elif self.method == 'borg':
                self.__class__ = BorgBackupRepository
            else:
                self.__class__ = HookBackupRepository

    def _check_is_enough_free_space(self):
        """
        Check free space in repository or output directory before to backup
        """
        # TODO How to do with distant repo or with deduplicated backup ?
        backup_size = self.manager.size

        free_space = free_space_in_directory(self.repo)

        if free_space < backup_size:
            logger.debug(
                "Not enough space at %s (free: %s / needed: %d)",
                self.repo,
                free_space,
                backup_size,
            )
            raise YunohostValidationError("not_enough_disk_space", path=self.repo)

    def remove(self, purge=False):
        if purge:
            self._load_current_values()
            self.purge()

        rm(self.save_path, force=True)
        logger.success(m18n.n("repository_removed", repository=self.shortname))

    def info(self, space_used=False):
        result = super().get(mode="export")

        if self.__class__ == BackupRepository and space_used == True:
            result["space_used"] = self.compute_space_used()

        return {self.shortname: result}

    def list(self, with_info):
        archives = self.list_archive_name()
        if with_info:
            d = OrderedDict()
            for archive in archives:
                try:
                    d[archive] = BackupArchive(repo=self, name=archive).info()
                except YunohostError as e:
                    logger.warning(str(e))
                except Exception:
                    import traceback

                    logger.warning(
                        "Could not check infos for archive %s: %s"
                        % (archive, "\n" + traceback.format_exc())
                    )

            archives = d

        return archives

    # =================================================
    # Repository abstract actions
    # =================================================
    def install(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    def purge(self):
        raise NotImplementedError()

    def list_archives_names(self):
        raise NotImplementedError()

    def compute_space_used(self):
        raise NotImplementedError()

    def prune(self):
        raise NotImplementedError() # TODO prune

class LocalBackupRepository(BackupRepository):
    def install(self):
        self.new_values['location'] = self.location
        mkdir(self.location, mode=0o0750, parents=True, uid="admin", gid="root", force=True)

    def update(self):
        self.install()

    def purge(self):
        rm(self.location, recursive=True, force=True)


class BackupArchive:
    def __init__(self, repo, name=None, manager=None):
        self.manager = manager
        self.name = name or manager.name
        if self.name.endswith(".tar.gz"):
            self.name = self.name[: -len(".tar.gz")]
        elif self.name.endswith(".tar"):
            self.name = self.name[: -len(".tar")]
        self.repo = repo

        # Cast
        if self.repo.method_name == 'tar':
            self.__class__ = TarBackupArchive
        elif self.repo.method_name == 'borg':
            self.__class__ = BorgBackupArchive
        else:
            self.__class__ = HookBackupArchive

        # Assert archive exists
        if not isinstance(self.manager, BackupManager) and self.name not in self.repo.list():
            raise YunohostValidationError("backup_archive_name_unknown", name=name)

    @property
    def archive_path(self):
        """Return the archive path"""
        return self.repo.location + '::' + self.name

    @property
    def work_dir(self):
        """
        Return the working directory

        For a BackupManager, it is the directory where we prepare the files to
        backup

        For a RestoreManager, it is the directory where we mount the archive
        before restoring
        """
        return self.manager.work_dir

    # This is not a property cause it could be managed in a hook
    def need_organized_files(self):
        return self.repo.need_organised_files

    def organize_and_backup(self):
        """
        Run the backup on files listed by  the BackupManager instance

        This method shouldn't be overrided, prefer overriding self.backup() and
        self.clean()
        """
        if self.need_organized_files():
            self._organize_files()

        self.repo.install()

        # Check free space in output
        self._check_is_enough_free_space()
        try:
            self.backup()
        finally:
            self.clean()

    def select_files(self):
        files_in_archive = self.list()

        if "info.json" in files_in_archive:
            leading_dot = ""
            yield "info.json"
        elif "./info.json" in files_in_archive:
            leading_dot = "./"
            yield "./info.json"
        else:
            logger.debug(
                "unable to retrieve 'info.json' inside the archive", exc_info=1
            )
            raise YunohostError(
                "backup_archive_cant_retrieve_info_json", archive=self.archive_path
            )
        extract_paths = []
        if f"{leading_dot}backup.csv" in files_in_archive:
            yield f"{leading_dot}backup.csv"
        else:
            # Old backup archive have no backup.csv file
            pass

        # Extract system parts backup
        conf_extracted = False

        system_targets = self.manager.targets.list("system", exclude=["Skipped"])
        apps_targets = self.manager.targets.list("apps", exclude=["Skipped"])

        for system_part in system_targets:
            if system_part.startswith("conf_"):
                if conf_extracted:
                    continue
                system_part = "conf/"
                conf_extracted = True
            else:
                system_part = system_part.replace("_", "/") + "/"
            yield leading_dot + system_part
        yield f"{leading_dot}hook/restore/"

        # Extract apps backup
        for app in apps_targets:
            yield f"{leading_dot}apps/{app}"

    def _get_info_string(self):
        archive_file = "%s/%s.tar" % (self.repo.path, self.name)

        # Check file exist (even if it's a broken symlink)
        if not os.path.lexists(archive_file):
            archive_file += ".gz"
            if not os.path.lexists(archive_file):
                raise YunohostValidationError("backup_archive_name_unknown", name=name)

        # If symlink, retrieve the real path
        if os.path.islink(archive_file):
            archive_file = os.path.realpath(archive_file)

            # Raise exception if link is broken (e.g. on unmounted external storage)
            if not os.path.exists(archive_file):
                raise YunohostValidationError(
                    "backup_archive_broken_link", path=archive_file
                )
        info_file = CACHE_INFO_DIR.format(repository=self.repo.name)
        mkdir(info_file, mode=0o0700, parents=True, force=True)
        info_file += f"/{self.name}.info.json"

        if not os.path.exists(info_file):
            info_dir = tempfile.mkdtemp()
            try:
                files_in_archive = self.list()
                if "info.json" in files_in_archive:
                    self.extract("info.json")
                elif "./info.json" in files_in_archive:
                    self.extract("./info.json")
                else:
                    raise YunohostError(
                        "backup_archive_cant_retrieve_info_json", archive=archive_file
                    )
                shutil.move(os.path.join(info_dir, "info.json"), info_file)
            finally:
                os.rmdir(info_dir)

        try:
            return read_file(info_file)
        except MoulinetteError:
            logger.debug("unable to load '%s'", info_file, exc_info=1)
            raise YunohostError('backup_invalid_archive')

    def info(self):

        info_json = self._get_info_string()
        if not self._info_json:
            raise YunohostError('backup_info_json_not_implemented')
        try:
            info = json.load(info_json)
        except:
            logger.debug("unable to load info json", exc_info=1)
            raise YunohostError('backup_invalid_archive')

        # (legacy) Retrieve backup size
        # FIXME
        size = info.get("size", 0)
        if not size:
            tar = tarfile.open(
                archive_file, "r:gz" if archive_file.endswith(".gz") else "r"
            )
            size = reduce(
                lambda x, y: getattr(x, "size", x) + getattr(y, "size", y), tar.getmembers()
            )
            tar.close()
        result = {
            "path": repo.archive_path,
            "created_at": datetime.utcfromtimestamp(info["created_at"]),
            "description": info["description"],
            "size": size,
        }
        if human_readable:
            result['size'] = binary_to_human(result['size']) + 'B'

        if with_details:
            system_key = "system"
            # Historically 'system' was 'hooks'
            if "hooks" in info.keys():
                system_key = "hooks"

            if "size_details" in info.keys():
                for category in ["apps", "system"]:
                    for name, key_info in info[category].items():

                        if category == "system":
                            # Stupid legacy fix for weird format between 3.5 and 3.6
                            if isinstance(key_info, dict):
                                key_info = key_info.keys()
                            info[category][name] = key_info = {"paths": key_info}
                        else:
                            info[category][name] = key_info

                        if name in info["size_details"][category].keys():
                            key_info["size"] = info["size_details"][category][name]
                            if human_readable:
                                key_info["size"] = binary_to_human(key_info["size"]) + "B"
                        else:
                            key_info["size"] = -1
                            if human_readable:
                                key_info["size"] = "?"

            result["apps"] = info["apps"]
            result["system"] = info[system_key]
            result["from_yunohost_version"] = info.get("from_yunohost_version")

        return info

# TODO move this in BackupManager ?????
    def clean(self):
        """
        Umount sub directories of working dirextories and delete it if temporary
        """
        if self.need_organized_files():
            if not _recursive_umount(self.work_dir):
                raise YunohostError("backup_cleaning_failed")

        if self.manager.is_tmp_work_dir:
            filesystem.rm(self.work_dir, True, True)
    def _organize_files(self):
        """
        Mount all csv src in their related path

        The goal is to organize the files app by app and hook by hook, before
        custom backup method or before the restore operation (in the case of an
        unorganize archive).

        The usage of binding could be strange for a user because the du -sb
        command will return that the working directory is big.
        """
        paths_needed_to_be_copied = []
        for path in self.manager.paths_to_backup:
            src = path["source"]

            if self.manager is RestoreManager:
                # TODO Support to run this before a restore (and not only before
                # backup). To do that RestoreManager.unorganized_work_dir should
                # be implemented
                src = os.path.join(self.unorganized_work_dir, src)

            dest = os.path.join(self.work_dir, path["dest"])
            if dest == src:
                continue
            dest_dir = os.path.dirname(dest)

            # Be sure the parent dir of destination exists
            if not os.path.isdir(dest_dir):
                filesystem.mkdir(dest_dir, parents=True)

            # For directory, attempt to mount bind
            if os.path.isdir(src):
                filesystem.mkdir(dest, parents=True, force=True)

                try:
                    subprocess.check_call(["mount", "--rbind", src, dest])
                    subprocess.check_call(["mount", "-o", "remount,ro,bind", dest])
                except Exception:
                    logger.warning(m18n.n("backup_couldnt_bind", src=src, dest=dest))
                    # To check if dest is mounted, use /proc/mounts that
                    # escape spaces as \040
                    raw_mounts = read_file("/proc/mounts").strip().split("\n")
                    mounts = [m.split()[1] for m in raw_mounts]
                    mounts = [m.replace("\\040", " ") for m in mounts]
                    if dest in mounts:
                        subprocess.check_call(["umount", "-R", dest])
                else:
                    # Success, go to next file to organize
                    continue

            # For files, create a hardlink
            elif os.path.isfile(src) or os.path.islink(src):
                # Can create a hard link only if files are on the same fs
                # (i.e. we can't if it's on a different fs)
                if os.stat(src).st_dev == os.stat(dest_dir).st_dev:
                    # Don't hardlink /etc/cron.d files to avoid cron bug
                    # 'NUMBER OF HARD LINKS > 1' see #1043
                    cron_path = os.path.abspath("/etc/cron") + "."
                    if not os.path.abspath(src).startswith(cron_path):
                        try:
                            os.link(src, dest)
                        except Exception as e:
                            # This kind of situation may happen when src and dest are on different
                            # logical volume ... even though the st_dev check previously match...
                            # E.g. this happens when running an encrypted hard drive
                            # where everything is mapped to /dev/mapper/some-stuff
                            # yet there are different devices behind it or idk ...
                            logger.warning(
                                "Could not link %s to %s (%s) ... falling back to regular copy."
                                % (src, dest, str(e))
                            )
                        else:
                            # Success, go to next file to organize
                            continue

            # If mountbind or hardlink couldnt be created,
            # prepare a list of files that need to be copied
            paths_needed_to_be_copied.append(path)

        if len(paths_needed_to_be_copied) == 0:
            return
        # Manage the case where we are not able to use mount bind abilities
        # It could be just for some small files on different filesystems or due
        # to mounting error

        # Compute size to copy
        size = sum(disk_usage(path["source"]) for path in paths_needed_to_be_copied)
        size /= 1024 * 1024  # Convert bytes to megabytes

        # Ask confirmation for copying
        if size > MB_ALLOWED_TO_ORGANIZE:
            try:
                i = Moulinette.prompt(
                    m18n.n(
                        "backup_ask_for_copying_if_needed",
                        answers="y/N",
                        size=str(size),
                    )
                )
            except NotImplemented:
                raise YunohostError("backup_unable_to_organize_files")
            else:
                if i != "y" and i != "Y":
                    raise YunohostError("backup_unable_to_organize_files")

        # Copy unbinded path
        logger.debug(m18n.n("backup_copying_to_organize_the_archive", size=str(size)))
        for path in paths_needed_to_be_copied:
            dest = os.path.join(self.work_dir, path["dest"])
            if os.path.isdir(path["source"]):
                shutil.copytree(path["source"], dest, symlinks=True)
            else:
                shutil.copy(path["source"], dest)

    # =================================================
    # Archive abstract actions
    # =================================================
    def backup(self):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()

    def delete(self):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()

    def list(self):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()


    def download(self):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()
        if Moulinette.interface.type != "api":
            logger.error(
                "This option is only meant for the API/webadmin and doesn't make sense for the command line."
            )
            return

    def extract(self, paths=None, exclude_paths=[]):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()
        if isinstance(exclude_paths, str):
            paths = [paths]
        elif paths is None:
            paths = self.select_files()
        if isinstance(exclude_paths, str):
            exclude_paths = [exclude_paths]
        return paths, exclude_paths

    def mount(self):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()






