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
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from functools import reduce

from moulinette import Moulinette, m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, rm, mkdir
from moulinette.utils.network import download_text
from datetime import timedelta, datetime

import yunohost.repositories
from yunohost.utils.config import ConfigPanel
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.system import disk_usage, binary_to_human
from yunohost.utils.network import get_ssh_public_key, SHF_BASE_URL

logger = getActionLogger('yunohost.repository')
REPOSITORIES_DIR = '/etc/yunohost/backup/repositories'
CACHE_INFO_DIR = "/var/cache/yunohost/repositories/{repository}"
REPOSITORY_CONFIG_PATH = "/usr/share/yunohost/other/config_repository.toml"
MB_ALLOWED_TO_ORGANIZE = 10
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
    save_path_tpl = REPOSITORIES_DIR + "/{entity}.yml"
    save_mode = "full"
    need_organized_files = True
    method_name = ""

    @staticmethod
    def split_location(location):
        """
        Split a repository location into protocol, user, domain and path
        """
        if "/" not in location:
            return {"domain": location}

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

        full_repositories = {}
        for repo in repositories:
            try:
                full_repositories.update(BackupRepository(repo).info(space_used))
            except Exception as e:
                logger.error(f"Unable to open repository {repo}: {e}")

        return full_repositories

    def __init__(self, entity, config_path=None, save_path=None, creation=False):

        super().__init__(entity, config_path, save_path, creation)

        self._load_current_values()

        self._cast_by_backup_method()

    def _cast_by_backup_method(self):
        try:
            if self.method == 'tar':
                from yunohost.repositories.tar import TarBackupRepository
                self.__class__ = TarBackupRepository
            elif self.method == 'borg':
                from yunohost.repositories.borg import BorgBackupRepository
                self.__class__ = BorgBackupRepository
            else:
                from yunohost.repositories.hook import HookBackupRepository
                self.__class__ = HookBackupRepository
        except KeyError:
            pass

    # =================================================
    # Config Panel Hooks
    # =================================================

    def post_ask__domain(self, question):
        """ Detect if the domain support Self-Hosting Federation protocol
        """
        # import requests
        # FIXME What if remote server is self-signed ?
        # FIXME What if remote server is unreachable temporarily ?
        url = SHF_BASE_URL.format(domain=question.value) + "/"
        try:
            # r = requests.get(url, timeout=10)
            download_text(url, timeout=10)
        except MoulinetteError:
            logger.debug("SHF not running")
            return {'is_shf': False}
        logger.debug("SHF running")
        return {'is_shf': True}

    def post_ask__is_remote(self, question):
        if question.value:
            self.method = 'borg'
        self._cast_by_backup_method()
        return {}

    def post_ask__method(self, question):
        self._cast_by_backup_method()
        return {}

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

        self.values['is_shf'] = bool(self.values['shf_id']) if 'shf_id' in self.values else False

    def _parse_pre_answered(self, *args):
        super()._parse_pre_answered(*args)
        if 'location' in self.args:
            self.args.update(BackupRepository.split_location(self.args['location']))
        if 'domain' in self.args:
            self.args['is_remote'] = bool(self.args['domain'])
            self.args['method'] = "borg"
        elif self.args.get('method') == 'tar':
            self.args['is_remote'] = False

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

    @property
    def is_deduplicated(self):
        return True

    def check_is_enough_free_space(self, backup_size):
        """
        Check free space in repository or output directory before to backup
        """
        if self.is_deduplicated:
            return

        free_space = self.compute_free_space(self)

        if free_space < backup_size:
            logger.debug(
                "Not enough space at %s (free: %s / needed: %d)",
                self.entity,
                free_space,
                backup_size,
            )
            raise YunohostValidationError("not_enough_disk_space", path=self.entity)

    def remove(self, purge=False):
        if purge:
            self._load_current_values()
            self.purge()

        rm(CACHE_INFO_DIR.format(repository=self.entity), recursive=True, force=True)
        rm(self.save_path, force=True)
        logger.success(m18n.n("repository_removed", repository=self.entity))

    def info(self, space_used=False):
        result = super().get(mode="export")

        if space_used is True:
            result["space_used"] = self.compute_space_used()

        return {self.entity: result}

    def list_archives(self, with_info=False):
        archives = self.list_archives_names()
        if with_info:
            d = {}
            for archive in archives:
                try:
                    d[archive] = BackupArchive(repo=self, name=archive).info(with_details=with_info)
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

    def prune(self, prefix=None, **kwargs):

        # List archives with creation date
        archives = {}
        for archive_name in self.list_archives_names(prefix):
            archive = BackupArchive(repo=self, name=archive_name)
            created_at = archive.info()["created_at"]
            archives[created_at] = archive

        if not archives:
            return

        # Generate periods in which keep one archive
        now = datetime.utcnow()
        now -= timedelta(
            minutes=now.minute,
            seconds=now.second,
            microseconds=now.microsecond
        )
        periods = set([])

        for unit, qty in kwargs:
            if not qty:
                continue
            period = timedelta(**{unit: 1})
            periods += set([(now - period * i, now - period * (i - 1))
                           for i in range(qty)])

        # Delete unneeded archive
        for created_at in sorted(archives, reverse=True):
            created_at = datetime.utcfromtimestamp(created_at)
            keep_for = set(filter(lambda period: period[0] <= created_at <= period[1], periods))

            if keep_for:
                periods -= keep_for
                continue

            archive.delete()

    # =================================================
    # Repository abstract actions
    # =================================================
    def install(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    def purge(self):
        raise NotImplementedError()

    def list_archives_names(self, prefix=None):
        raise NotImplementedError()

    def compute_space_used(self):
        raise NotImplementedError()

    def compute_free_space(self):
        raise NotImplementedError()


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
            self.__class__ = yunohost.repositories.tar.TarBackupArchive
        elif self.repo.method_name == 'borg':
            self.__class__ = yunohost.repositories.borg.BorgBackupArchive
        else:
            self.__class__ = yunohost.repositories.hook.HookBackupArchive

        # Assert archive exists
        if self.manager.__class__.__name__ != "BackupManager" and self.name not in self.repo.list_archives(False):
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
        return self.repo.need_organized_files

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
        self.repo.check_is_enough_free_space(self.manager.size)
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
        """Extract info file from archive if needed and read it"""

        cache_info_dir = CACHE_INFO_DIR.format(repository=self.repo.entity)
        mkdir(cache_info_dir, mode=0o0700, parents=True, force=True)
        info_file = f"{cache_info_dir}/{self.name}.info.json"

        if not os.path.exists(info_file):
            tmp_dir = tempfile.mkdtemp()
            try:
                files_in_archive = self.list()
                if "info.json" in files_in_archive:
                    self.extract("info.json", destination=tmp_dir)
                elif "./info.json" in files_in_archive:
                    self.extract("./info.json", destination=tmp_dir)
                else:
                    raise YunohostError(
                        "backup_archive_cant_retrieve_info_json", archive=self.archive_path
                    )
                    # FIXME should we cache there is no info.json ?
                shutil.move(os.path.join(tmp_dir, "info.json"), info_file)
            finally:
                os.rmdir(tmp_dir)

        try:
            return read_file(info_file)
        except MoulinetteError as e:
            logger.debug("unable to load '%s'", info_file, exc_info=1)
            raise YunohostError('backup_invalid_archive', error=e)

    def info(self, with_details=False, human_readable=False):

        info_json = self._get_info_string()
        if not info_json:
            raise YunohostError('backup_info_json_not_implemented')
        try:
            info = json.loads(info_json)
        except Exception as e:
            logger.debug("unable to load info json", exc_info=1)
            raise YunohostError('backup_invalid_archive', error=e)

        # (legacy) Retrieve backup size
        # FIXME
        size = info.get("size", 0)
        if not size:
            tar = tarfile.open(
                self.archive_file, "r:gz" if self.archive_file.endswith(".gz") else "r"
            )
            size = reduce(
                lambda x, y: getattr(x, "size", x) + getattr(y, "size", y), tar.getmembers()
            )
            tar.close()
        result = {
            "path": self.archive_path,
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

    def clean(self):
        """
        Umount sub directories of working dirextories and delete it if temporary
        """
        self.manager.clean_work_dir(self.need_organized_files())

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

            if self.manager.__class__.__name__ == "RestoreManager":
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
                mkdir(dest_dir, parents=True)

            # For directory, attempt to mount bind
            if os.path.isdir(src):
                mkdir(dest, parents=True, force=True)

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

    def extract(self, paths=None, destination=None, exclude_paths=[]):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()
        if isinstance(paths, str):
            paths = [paths]
        elif paths is None:
            paths = self.select_files()
        if isinstance(exclude_paths, str):
            exclude_paths = [exclude_paths]
        return paths, destination, exclude_paths

    def mount(self):
        if self.__class__ == BackupArchive:
            raise NotImplementedError()
