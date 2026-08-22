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
from typing import Callable, Tuple
try:
    from pip import __version__ as PIP_VERSION
except ImportError:
    PIP_VERSION = ""
import re
import tempfile

from moulinette import m18n
from configparser import ConfigParser, UNNAMED_SECTION
from packaging.version import Version, VERSION_PATTERN
from packaging.markers import default_environment

from ..tools import Migration, tools_migrations_state
from ..utils.error import YunohostError
from ..utils.file_utils import rm
from ..utils.process import call_async_output, check_output
from ..utils.system import debian_version

type ExecutionCallback = Tuple[Callable[[str], None], Callable[[str], None]]

logger = getLogger("yunohost.migration")

MAJOR_MINOR_PATCH_RE = r'(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)'


class PyVenvConfig():
    def __init__(self, venv_path: Path):
        self.path = venv_path / "pyvenv.cfg"
        parser = ConfigParser(allow_unnamed_section=True)
        with open(self.path) as file:
            parser.read_file(file)
        self.data = parser[UNNAMED_SECTION]

    @property
    def include_system_site_packages(self) -> bool:
        return self.data.get('include-system-site-packages', None) == 'true'

    @cached_property
    def version(self) -> Version:
        return Version(self.data['version'])


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

    pip_version_requirement_extractor_re = re.compile(
        rf"^pip\s*==\s*(?P<version>{VERSION_PATTERN})\s*$",
        re.VERBOSE + re.MULTILINE  # VERBOSE is required by VERSION_PATTERN
    )

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
                pyvenv_cfg_path = os.path.join(path, "pyvenv.cfg")
                if os.path.isfile(pyvenv_cfg_path):
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
    def pip_version(self):
        return Version(PIP_VERSION) if PIP_VERSION else None

    @cached_property
    def python_version(self):
        return Version(default_environment()['python_full_version'])

    @property
    def mode(self):
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

        if not PIP_VERSION:
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

            try:
                venv_cfg = PyVenvConfig(venv_path)
            except Exception as e:
                logger.warn(e)
                continue

            if venv_cfg.version >= self.python_version:
                logger.info(f"The {app_corresponding_to_venv} app looks already migrated, skipping")
                continue

            # Recreate the venv
            callbacks: ExecutionCallback = (
                lambda line: logger.debug("+ " + line.rstrip() + "\r"),
                lambda line: logger.warning(line.rstrip()),
            )

            self._upgrade_venv(venv, venv_cfg.include_system_site_packages, callbacks)

            # store the old python version without the patch part
            old_python_version_major_minor = f"{venv_cfg.version.major}.{venv_cfg.version.minor}"

            requirements = check_output(
                [
                    pip_path,
                    "freeze",
                    "--all",
                    "--path",
                    venv_path / f"lib/python{old_python_version_major_minor}/site-packages",
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

                self._cleanup_old_python_assets(venv_path, old_python_version_major_minor)
            except YunohostError as e:
                logger.warn(e)
                continue
            except Exception as e:
                raise e

    def _cleanup_old_python_assets(self, venv_path: Path, old_python_version_major_minor: str):
        rm(venv_path / f"lib/python{old_python_version_major_minor}", recursive=True, force=True)
        rm(venv_path / f"include/python{old_python_version_major_minor}", recursive=True, force=True)
        rm(venv_path / f"bin/python{old_python_version_major_minor}", force=True)
        rm(venv_path / f"bin/pip{old_python_version_major_minor}", force=True)

    def _remove_pip_if_not_newer_than_system_version(self, requirements: str):
        """
        In the requirements, look for line installing pip and either:
           - keep it if the pip version asked is newer than the one provided by the system
           - or empty the whole line otherwise

        For the sake of simplicity, we only compare the major, minor and patch.
        """
        def maybe_empty(match: re.Match[str]) -> str:
            assert self.pip_version
            frozen_version = Version(match.group("version"))
            if frozen_version > self.pip_version:
                logger.debug(f"pip: Will reinstall the version required by the app: {frozen_version} (more recent than the system version: {self.pip_version})")
                return match.string
            logger.debug(f"pip: Will upgrade version from {frozen_version} to {self.pip_version} (the system version)")
            return ""

        return self.pip_version_requirement_extractor_re.sub(maybe_empty, requirements)

    def _split_editables(self, requirements: str) -> Tuple[str, str]:
        new_requirements = []
        editables = []
        for line in requirements.splitlines():
            if line.startswith("-e"):
                editables.append(line)
            else:
                new_requirements.append(line)
        return (str.join("\n", new_requirements), str.join("\n", editables))

    def _upgrade_venv(self, venv: str, include_system_site_packages: bool, callbacks: ExecutionCallback):
        venv_cmd = ["python", "-m", "venv", "--upgrade", venv]
        if include_system_site_packages:
            venv_cmd.append("--system-site-packages")
        return self._call_async_output(venv_cmd, callbacks)

    def _install_requirements(self, pip_path: Path, requirements: str, app: str, callbacks: ExecutionCallback, extra_args: list[str] = []):
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(requirements.encode("utf8"))
            fp.flush()
            status = self._call_async_output(
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

    def _call_async_output(self, args: list[str | Path], callbacks: ExecutionCallback):
        logger.debug(f"Running this command: {str.join(" ", [str(arg) for arg in args])}")
        return call_async_output(args, callbacks)
