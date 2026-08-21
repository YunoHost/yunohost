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

from functools import cached_property
from logging import getLogger
import os
from pathlib import Path
import sys
from typing import Callable, Tuple
try:
    from pip import __version__ as PIP_VERSION
except ImportError:
    PIP_VERSION = ""
import re
import tempfile

from moulinette import m18n

from ..tools import Migration, tools_migrations_state
from ..utils.error import YunohostError
from ..utils.file_utils import read_file, rm
from ..utils.process import call_async_output, check_output
from ..utils.system import debian_version, dpkg_compare_version

type PipExecutionCallbacks = Tuple[Callable[[str], None], Callable[[str], None]]

logger = getLogger("yunohost.migration")

MAJOR_MINOR_PATCH_RE = r'\d+\.\d+\.\d+'


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
    pyenv_cfg_version_extractor = re.compile(
        r"version\s*=\s*(?P<version>\d+\.\d+)"  # Omit the patch number of the version
    )

    pip_version_requirement_extractor_re = re.compile(rf"""
        ^pip\s*==\s*
        (?P<version>{MAJOR_MINOR_PATCH_RE}) # Only get the major, minor and patch
        (?:[^\d].*)?$ # Also grab any residual characters that follows the patch,
                      # but don't process them, they will be removed if we skip the pip upgrade.
    """, re.VERBOSE)

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

    @cached_property
    def pip_version_normalized(self):
        match = re.match(rf'^(?P<version>{MAJOR_MINOR_PATCH_RE})', PIP_VERSION)
        if not match:
            raise YunohostError(f"cannot parse pip system version: {PIP_VERSION}", raw_msg=True)
        return match.group("version")

    @cached_property
    def python_version(self):
        """ Returns the python version without the patch """
        return f"{sys.version_info.major}.{sys.version_info.minor}"

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

        if not self.pip_version_normalized:
            logger.info("No pip version found, skipping")
            return

        venvs = self._get_all_venvs("/opt/") + self._get_all_venvs("/var/www/")
        for venv in venvs:
            venv_path = Path(venv)
            pip_path = venv_path / "bin/pip"
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

            if dpkg_compare_version(old_python_version, self.python_version) in [0, 1]:
                logger.info(f"The {app_corresponding_to_venv} app looks already migrated, skipping")
                continue

            # Recreate the venv
            callbacks: PipExecutionCallbacks = (
                lambda line: logger.debug("+ " + line.rstrip() + "\r"),
                lambda line: logger.warning(line.rstrip()),
            )
            call_async_output(["python", "-m", "venv", "--upgrade", venv], callbacks)

            requirements = check_output(
                [
                    pip_path,
                    "freeze",
                    "--all",
                    "--path=" + str(venv_path / f"lib/python{old_python_version}/site-packages"),
                ],
                shell=False
            )

            requirements = self._remove_pip_if_not_newer_than_system_version(requirements)

            (requirements, editables_requirements) = self._split_editables(requirements)

            try:
                self._install_requirements(pip_path, requirements, app_corresponding_to_venv, callbacks)

                if editables_requirements:
                    logger.debug("Installing the editables")
                    self._install_requirements(
                        pip_path,
                        editables_requirements,
                        app_corresponding_to_venv,
                        callbacks,
                        extra_args=["--no-build-isolation"],
                    )

                self._cleanup_old_python_assets(venv_path, old_python_version)
            except YunohostError as e:
                logger.error(e)
                continue
            except Exception as e:
                raise e

    def _extract_venv_python_version(self, venv_path: Path) -> None | str:
        py_version_match = self.pyenv_cfg_version_extractor.search(
            read_file(venv_path / "pyvenv.cfg")
        )
        return py_version_match.group("version") if py_version_match else None

    def _cleanup_old_python_assets(self, venv_path: Path, old_python_version: str):
        rm(venv_path / f"lib/python{old_python_version}", recursive=True, force=True)
        rm(venv_path / f"include/python{old_python_version}", recursive=True, force=True)
        rm(venv_path / f"bin/python{old_python_version}", force=True)
        rm(venv_path / f"bin/pip{old_python_version}", force=True)

    def _remove_pip_if_not_newer_than_system_version(self, requirements: str):
        """
        In the requirements, look for line installing pip and either:
           - keep it if the pip version asked is newer than the one provided by the system
           - or empty the whole line otherwise

        For the sake of simplicity, we only compare the major, minor and patch.
        """
        def remove_if_not_newer_than_system_pip(match: re.Match[str]) -> str:
            # HACK: yeah, we use a tool meant for debian to compare versions for pip version…
            # We assume that such a tool does the job when comparing versions which includes only
            # a major, minor and patch.
            if dpkg_compare_version(match.group("version"), self.pip_version_normalized) > 0:
                return match.string
            return ""

        return re.sub(self.pip_version_requirement_extractor_re, remove_if_not_newer_than_system_pip, requirements)

    def _split_editables(self, requirements: str) -> Tuple[str, str]:
        new_requirements = []
        editables = []
        for line in requirements.splitlines():
            if line.startswith("-e"):
                editables.append(line)
            else:
                new_requirements.append(line)
        return (str.join("\n", new_requirements), str.join("\n", editables))

    def _install_requirements(self, pip_path: Path, requirements: str, app: str, callbacks: PipExecutionCallbacks, extra_args: list[str] = []):
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(requirements.encode("utf8"))
            fp.flush()
            status = call_async_output(
                [
                    pip_path,
                    "install",
                    "--use-pep517",  # Seems like a sane default nowadays: https://pip.pypa.io/en/stable/news/#id112
                    *extra_args,
                    "-r",
                    fp.name,
                ],
                callbacks,
            )

        if status != 0:
            raise YunohostError(
                "migration_python_venv_rebuild_failed",
                app=app,
            )
