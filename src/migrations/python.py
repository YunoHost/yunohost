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
from logging import getLogger
from pathlib import Path
import re
import subprocess
import tempfile

from moulinette import m18n

from ..tools import Migration, tools_migrations_state
from ..utils.file_utils import read_file, rm
from ..utils.process import call_async_output
from ..utils.system import debian_version

logger = getLogger("yunohost.migration")


class PythonMigration(Migration):
    """
    After the update, recreate a python virtual env based on the previously
    generated requirements file
    """

    ignored_python_apps = [
        "diacamma",  # Does an ugly sed in the sites-packages/django_auth_ldap3_ad
        "django-for-runners",  # pip-sync is used, I'm not sure if it's a problem
        "django-fritzconnection",  # same, pip-sync
        "funkwhale",  # install from a folder ./api?
        "homeassistant",  # uses a custom version of Python
        "immich",  # uses a custom version of Python
        "indico",  # symlink between venv and static web pages
        "kresus",  # uses virtualenv instead of venv, with --system-site-packages (?)
        "lasuite-docs",  # moving stuff into the venv
        "librephotos",  # runs a setup.py ? not sure pip freeze / pip install -r requirements.txt is gonna be equivalent ..
        "mautrix_telegram",  # install stuff from a .tar.gz
        "microblogpub",  # uses poetry ? x_x
        "microblogpub",  # uses poetry
        "pgadmin",  # bunch of manual patches
        "pretalx",  # ynh_replace into the venv
        "synapse",  # specific stuff for ARM to prevent local compiling etc
        "synapse",  # ynh_setup_source into the venv
        "tracim",  # pip install -e .
        "weblate",  # weblate settings are .. inside the venv T_T
        "yunohost_appgenerator",  # uses pdm
    ]

    migration_id: str
    state = None
    py_version_re = re.compile(
        r"version\s*=\s*(?P<version>\d+\.\d+)"
    )  # Omit the patch number of the version

    def extract_app_from_venv_path(self, venv_path: str) -> str:
        venv_path = venv_path.replace("/var/www/", "")
        venv_path = venv_path.replace("/opt/yunohost/", "")
        venv_path = venv_path.replace("/opt/", "")
        return venv_path.split("/")[0]

    def _get_all_venvs(self, dir: str, level: int = 0, maxlevel: int = 3) -> list[str]:
        """
        Returns the list of all python virtual env directories recursively

        Arguments:
            dir - the directory to scan in
            maxlevel - the depth of the recursion
            level - do not edit this, used as an iterator
        """
        if not os.path.exists(dir):
            return []

        # Using os functions instead of glob, because glob doesn't support hidden
        # folders, and we need recursion with a fixed depth
        result: list[str] = []
        for file in os.listdir(dir):
            path = os.path.join(dir, file)
            if os.path.isdir(path):
                pyvenv_path = os.path.join(path, "pyvenv.cfg")
                if os.path.isfile(pyvenv_path):
                    result.append(path)
                    continue
                if level < maxlevel:
                    result += self._get_all_venvs(path, level=level + 1)
        return result

    def is_pending(self):
        if not self.state:
            self.state = tools_migrations_state()["migrations"].get(
                self.migration_id, "pending"
            )
        return self.state == "pending"

    @property
    def mode(self):
        if not self.is_pending():
            return "auto"

        if self._get_all_venvs("/opt/") + self._get_all_venvs("/var/www/"):
            return "manual"
        else:
            return "auto"

    @property
    def disclaimer(self):
        # Avoid having a super long disclaimer to generate if migrations has
        # been done
        if not self.is_pending():
            return None

        # Disclaimer should be empty if in auto, otherwise it excepts the --accept-disclaimer option during debian postinst
        if self.mode == "auto":
            return None

        ignored_apps = []
        rebuild_apps = []

        venvs = self._get_all_venvs("/opt/") + self._get_all_venvs("/var/www/")
        for venv in venvs:
            app_corresponding_to_venv = self.extract_app_from_venv_path(venv)

            # Search for ignore apps
            if any(
                app_corresponding_to_venv.startswith(app)
                for app in self.ignored_python_apps
            ):
                ignored_apps.append(app_corresponding_to_venv)
            else:
                rebuild_apps.append(app_corresponding_to_venv)

        msg = m18n.n(
            "migration_python_venv_rebuild_disclaimer_base",
            debian_pretty=debian_version().title(),
        )
        if rebuild_apps:
            msg += "\n\n" + m18n.n(
                "migration_python_venv_rebuild_disclaimer_rebuild",
                rebuild_apps="\n    - " + "\n    - ".join(rebuild_apps),
            )
        if ignored_apps:
            msg += "\n\n" + m18n.n(
                "migration_python_venv_rebuild_disclaimer_ignored",
                ignored_apps="\n    - " + "\n    - ".join(ignored_apps),
            )

        return msg

    def run(self):
        if self.mode == "auto":
            return

        venvs = self._get_all_venvs("/opt/") + self._get_all_venvs("/var/www/")
        for venv in venvs:
            venv_path = Path(venv)
            app_corresponding_to_venv = self.extract_app_from_venv_path(venv)

            # Search for ignore apps
            if any(
                app_corresponding_to_venv.startswith(app)
                for app in self.ignored_python_apps
            ):
                logger.info(
                    m18n.n(
                        "migration_python_venv_rebuild_broken_app",
                        app=app_corresponding_to_venv,
                    )
                )
                continue

            logger.info(
                m18n.n(
                    "migration_python_venv_rebuild_in_progress",
                    app=app_corresponding_to_venv,
                )
            )

            old_python_version = self._extract_venv_python_version(venv_path)
            if not old_python_version:
                logger.warn(
                    m18n.n(
                        "migration_python_venv_cant_read_pyvenv",
                        app=app_corresponding_to_venv,
                    )
                )
                continue

            # Recreate the venv
            callbacks = (
                lambda l: logger.debug("+ " + l.rstrip() + "\r"),
                lambda l: logger.warning(l.rstrip()),
            )
            call_async_output(["python", "-m", "venv", "--upgrade", venv], callbacks)

            pip_freeze_output = subprocess.check_output(
                [
                    venv_path / "bin/pip",
                    "freeze",
                    "--path",
                    venv_path / f"lib/python{old_python_version}/site-packages",
                ]
            )

            with tempfile.NamedTemporaryFile() as fp:
                fp.write(pip_freeze_output)
                fp.flush()
                status = call_async_output(
                    [venv_path / "bin/pip", "install", "-r", fp.name], callbacks
                )

            if status != 0:
                logger.error(
                    m18n.n(
                        "migration_python_venv_rebuild_failed",
                        app=app_corresponding_to_venv,
                    )
                )
            self._cleanup(venv_path, old_python_version)

    def _extract_venv_python_version(self, venv_path: Path) -> None | str:
        py_version_match = self.py_version_re.search(
            read_file(venv_path / "pyvenv.cfg")
        )
        return py_version_match.group("version") if py_version_match else None

    def _cleanup(self, venv_path: Path, old_python_version: str):
        rm(venv_path / f"lib/python{old_python_version}", recursive=True)
        rm(venv_path / f"include/python{old_python_version}", recursive=True)
        rm(venv_path / f"bin/python{old_python_version}")
        rm(venv_path / f"bin/pip{old_python_version}")
