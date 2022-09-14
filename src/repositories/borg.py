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
import os
import subprocess
import json

from datetime import datetime, timedelta

from moulinette.utils.log import getActionLogger

from yunohost.utils.error import YunohostError
from yunohost.utils.network import shf_request
from yunohost.repository import LocalBackupRepository, BackupArchive
logger = getActionLogger("yunohost.repository")


class BorgBackupRepository(LocalBackupRepository):
    need_organized_files = True
    method_name = "borg"

    # TODO logs
    def _run_borg_command(self, cmd, stdout=None):
        """ Call a submethod of borg with the good context
        """
        env = dict(os.environ)

        if self.domain:
            # TODO Use the best/good key
            private_key = "/root/.ssh/ssh_host_ed25519_key"

            # Don't check ssh fingerprint strictly the first time
            # TODO improve this by publishing and checking this with DNS
            strict = 'yes' if self.domain in open('/root/.ssh/known_hosts').read() else 'no'
            env['BORG_RSH'] = "ssh -i %s -oStrictHostKeyChecking=%s"
            env['BORG_RSH'] = env['BORG_RSH'] % (private_key, strict)

        # In case, borg need a passphrase to get access to the repo
        if "passphrase" in self.future_values:
            env['BORG_PASSPHRASE'] = self.passphrase

        # Authorize to move the repository (borgbase do this)
        env["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "yes"

        return subprocess.Popen(cmd, env=env, stdout=stdout)

    def _call(self, action, cmd, json_output=False):
        borg = self._run_borg_command(cmd)
        return_code = borg.wait()
        if return_code:
            raise YunohostError(f"backup_borg_{action}_error")

        out, _ = borg.communicate()
        if json_output:
            try:
                return json.loads(out)
            except (json.decoder.JSONDecodeError, TypeError):
                raise YunohostError(f"backup_borg_{action}_error")
        return out

    # =================================================
    # Repository actions
    # =================================================

    def install(self):
        # Remote
        if self.is_remote:
            if self.is_shf and not self.future_values.get('user'):
                services = {
                    'borg': 'borgbackup'
                }

                response = shf_request(
                    domain=self.domain,
                    service=services[self.method],
                    shf_id=self.values.pop('shf_id', None),
                    data={
                        'origin': self.domain,
                        'public_key': self.public_key,
                        'quota': self.quota,
                        'alert': self.alert,
                        'alert_delay': self.alert_delay,
                        # password: "XXXXXXXX",
                    }
                )
                self.new_values['shf_id'] = response['id']
                self.new_values['location'] = response['repository']
            elif not self.is_shf:
                self.new_values['location'] = self.location

            if not self.future_values.get('user'):
                raise YunohostError("")
        # Local
        else:
            super().install()

        # Initialize borg repo
        cmd = ["borg", "init", "--encryption", "repokey", self.location]

        if "quota" in self.future_values:
            cmd += ['--storage-quota', self.quota]
        self._call('init', cmd)

    def update(self):
        raise NotImplementedError()

    def purge(self):
        if self.is_shf:
            shf_request(
                domain=self.domain,
                service="borgbackup",
                shf_id=self.values.pop('shf_id', None),
                data={
                    'origin': self.domain,
                    # password: "XXXXXXXX",
                }
            )
        else:
            cmd = ["borg", "delete", self.location]
            self._call('purge', cmd)
            if not self.is_remote:
                super().purge()

    def list_archives_names(self, prefix=None):
        cmd = ["borg", "list", "--json", self.location]
        if prefix:
            cmd += ["-P", prefix]
        response = self._call('list', cmd, True)
        return [archive["name"] for archive in response['archives']]

    def compute_space_used(self):
        if not self.is_remote:
            return super().purge()
        else:
            cmd = ["borg", "info", "--json", self.location]
            response = self._call('info', cmd)
            return response["cache"]["stats"]["unique_size"]

    def prune(self, prefix=None, **kwargs):

        # List archives with creation date
        archives = {}
        for archive_name in self.list_archive_name(prefix):
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


class BorgBackupArchive(BackupArchive):
    """ Backup prepared files with borg """

    def backup(self):
        cmd = ['borg', 'create', self.archive_path, './']
        self.repo._call('backup', cmd)

    def delete(self):
        cmd = ['borg', 'delete', '--force', self.archive_path]
        self.repo._call('delete_archive', cmd)

    def list(self):
        """ Return a list of archives names

        Exceptions:
        backup_borg_list_error -- Raised if the borg script failed
        """
        cmd = ["borg", "list", "--json-lines", self.archive_path]
        out = self.repo._call('list_archive', cmd)
        result = [json.loads(out) for line in out.splitlines()]
        return result

    def download(self, exclude_paths=[]):
        super().download()
        paths = self.select_files()
        if isinstance(exclude_paths, str):
            exclude_paths = [exclude_paths]
        # Here tar archive are not compressed, if we want to compress we
        # should add --tar-filter=gzip.
        cmd = ["borg", "export-tar", self.archive_path, "-"] + paths
        for path in exclude_paths:
            cmd += ['--exclude', path]
        reader = self.repo._run_borg_command(cmd, stdout=subprocess.PIPE)

        # We return a raw bottle HTTPresponse (instead of serializable data like
        # list/dict, ...), which is gonna be picked and used directly by moulinette
        from bottle import response, HTTPResponse
        response.content_type = "application/x-tar"
        return HTTPResponse(reader, 200)

    def extract(self, paths=None, exclude_paths=[]):
        paths, exclude_paths = super().extract(paths, exclude_paths)
        cmd = ['borg', 'extract', self.archive_path] + paths
        for path in exclude_paths:
            cmd += ['--exclude', path]
        return self.repo._call('extract_archive', cmd)

    def mount(self, path):
        # FIXME How to be sure the place where we mount is secure ?
        cmd = ['borg', 'mount', self.archive_path, path]
        self.repo._call('mount_archive', cmd)
