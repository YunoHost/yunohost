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
import glob
import os
import tarfile
import shutil

from moulinette.utils.log import getActionLogger
from moulinette import m18n

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.repository import LocalBackupRepository
from yunohost.backup import BackupManager
from yunohost.utils.filesystem import space_used_in_directory
from yunohost.settings import settings_get
logger = getActionLogger("yunohost.repository")


class TarBackupRepository(LocalBackupRepository):
    need_organized_files = False
    method_name = "tar"

    def list_archives_names(self):
        # Get local archives sorted according to last modification time
        # (we do a realpath() to resolve symlinks)
        archives = glob(f"{self.location}/*.tar.gz") + glob(f"{self.location}/*.tar")
        archives = set([os.path.realpath(archive) for archive in archives])
        archives = sorted(archives, key=lambda x: os.path.getctime(x))

        # Extract only filename without the extension
        def remove_extension(f):
            if f.endswith(".tar.gz"):
                return os.path.basename(f)[: -len(".tar.gz")]
            else:
                return os.path.basename(f)[: -len(".tar")]

        return [remove_extension(f) for f in archives]

    def compute_space_used(self):
        return space_used_in_directory(self.location)

    def prune(self):
        raise NotImplementedError()


class TarBackupArchive:
    @property
    def archive_path(self):

        if isinstance(self.manager, BackupManager) and settings_get(
            "backup.compress_tar_archives"
        ):
            return os.path.join(self.repo.location, self.name + ".tar.gz")

        f = os.path.join(self.repo.path, self.name + ".tar")
        if os.path.exists(f + ".gz"):
            f += ".gz"
        return f

    def backup(self):
        # Open archive file for writing
        try:
            tar = tarfile.open(
                self.archive_path,
                "w:gz" if self.archive_path.endswith(".gz") else "w",
            )
        except Exception:
            logger.debug(
                "unable to open '%s' for writing", self.archive_path, exc_info=1
            )
            raise YunohostError("backup_archive_open_failed")

        # Add files to the archive
        try:
            for path in self.manager.paths_to_backup:
                # Add the "source" into the archive and transform the path into
                # "dest"
                tar.add(path["source"], arcname=path["dest"])
        except IOError:
            logger.error(
                m18n.n(
                    "backup_archive_writing_error",
                    source=path["source"],
                    archive=self._archive_file,
                    dest=path["dest"],
                ),
                exc_info=1,
            )
            raise YunohostError("backup_creation_failed")
        finally:
            tar.close()

        # Move info file
        shutil.copy(
            os.path.join(self.work_dir, "info.json"),
            os.path.join(self.repo.location, self.name + ".info.json"),
        )

        # If backuped to a non-default location, keep a symlink of the archive
        # to that location
        link = os.path.join(self.repo.path, self.name + ".tar")
        if not os.path.isfile(link):
            os.symlink(self.archive_path, link)

    def copy(self, file, target):
        tar = tarfile.open(
            self._archive_file, "r:gz" if self._archive_file.endswith(".gz") else "r"
        )
        file_to_extract = tar.getmember(file)
        # Remove the path
        file_to_extract.name = os.path.basename(file_to_extract.name)
        tar.extract(file_to_extract, path=target)
        tar.close()

    def delete(self):
        archive_file = f"{self.repo.location}/{self.name}.tar"
        info_file = f"{self.repo.location}/{self.name}.info.json"
        if os.path.exists(archive_file + ".gz"):
            archive_file += ".gz"

        files_to_delete = [archive_file, info_file]

        # To handle the case where archive_file is in fact a symlink
        if os.path.islink(archive_file):
            actual_archive = os.path.realpath(archive_file)
            files_to_delete.append(actual_archive)

        for backup_file in files_to_delete:
            if not os.path.exists(backup_file):
                continue
            try:
                os.remove(backup_file)
            except Exception:
                logger.debug("unable to delete '%s'", backup_file, exc_info=1)
                logger.warning(m18n.n("backup_delete_error", path=backup_file))

    def list(self):
        try:
            tar = tarfile.open(
                self.archive_path,
                "r:gz" if self.archive_path.endswith(".gz") else "r",
            )
        except Exception:
            logger.debug(
                "cannot open backup archive '%s'", self.archive_path, exc_info=1
            )
            raise YunohostError("backup_archive_open_failed")

        try:
            return tar.getnames()
        except (IOError, EOFError, tarfile.ReadError) as e:
            tar.close()
            raise YunohostError(
                "backup_archive_corrupted", archive=self.archive_path, error=str(e)
            )

    def download(self):
        super().download()
        # If symlink, retrieve the real path
        archive_file = self.archive_path
        if os.path.islink(archive_file):
            archive_file = os.path.realpath(archive_file)

            # Raise exception if link is broken (e.g. on unmounted external storage)
            if not os.path.exists(archive_file):
                raise YunohostValidationError(
                    "backup_archive_broken_link", path=archive_file
                )

        # We return a raw bottle HTTPresponse (instead of serializable data like
        # list/dict, ...), which is gonna be picked and used directly by moulinette
        from bottle import static_file

        archive_folder, archive_file_name = archive_file.rsplit("/", 1)
        return static_file(archive_file_name, archive_folder, download=archive_file_name)

    def extract(self, paths=None, exclude_paths=[]):
        paths, exclude_paths = super().extract(paths, exclude_paths)
        # Mount the tarball
        try:
            tar = tarfile.open(
                self.archive_path,
                "r:gz" if self.archive_path.endswith(".gz") else "r",
            )
        except Exception:
            logger.debug(
                "cannot open backup archive '%s'", self.archive_path, exc_info=1
            )
            raise YunohostError("backup_archive_open_failed")

        subdir_and_files = [
            tarinfo
            for tarinfo in tar.getmembers()
            if (
               any([tarinfo.name.startswith(path) for path in paths])
               and all([not tarinfo.name.startswith(path) for path in exclude_paths])
            )
        ]
        tar.extractall(members=subdir_and_files, path=self.work_dir)
        tar.close()

    def mount(self):
        raise NotImplementedError()

    def _archive_exists(self):
        return os.path.lexists(self.archive_path)

    def _assert_archive_exists(self):
        if not self._archive_exists():
            raise YunohostError('backup_archive_name_unknown', name=self.name)

        # If symlink, retrieve the real path
        if os.path.islink(self.archive_path):
            archive_file = os.path.realpath(self.archive_path)

            # Raise exception if link is broken (e.g. on unmounted external storage)
            if not os.path.exists(archive_file):
                raise YunohostError('backup_archive_broken_link',
                                    path=archive_file)
