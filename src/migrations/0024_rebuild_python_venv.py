import subprocess
import os

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import call_async_output

from yunohost.tools import Migration
from yunohost.utils.filesystem import read_file, rm

logger = getActionLogger("yunohost.migration")

VENV_REQUIREMENTS_SUFFIX = ".requirements_backup_for_bullseye_upgrade.txt"
VENV_IGNORE = "ynh_migration_no_regen"


def _get_all_venvs(dir, level=0, maxlevel=3):
    """
        Returns the list of all python virtual env directories recursively

        Arguments:
            dir - the directory to scan in
            maxlevel - the depth of the recursion
            level - do not edit this, used as an iterator
    """
    # Using os functions instead of glob, because glob doesn't support hidden
    # folders, and we need recursion with a fixed depth
    result = []
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isdir(path):
            if os.path.isfile(os.path.join(path, VENV_IGNORE)):
                continue
            activatepath = os.path.join(path, "bin", "activate")
            if os.path.isfile(activatepath):
                content = read_file(activatepath)
                if ("VIRTUAL_ENV" in content) and ("PYTHONHOME" in content):
                    result.append(path)
                    continue
            if level < maxlevel:
                result += _get_all_venvs(path, level=level + 1)
    return result


class MyMigration(Migration):
    """
    After the update, recreate a python virtual env based on the previously
    generated requirements file
    """

    dependencies = ["migrate_to_bullseye"]

    def run(self):

        venvs = _get_all_venvs("/opt/") + _get_all_venvs("/var/www/")
        for venv in venvs:
            if not os.path.isfile(venv + VENV_REQUIREMENTS_SUFFIX):
                continue

            # Recreate the venv
            rm(venv, recursive=True)
            callbacks = (
                lambda l: logger.info("+ " + l.rstrip() + "\r"),
                lambda l: logger.warning(l.rstrip())
            )
            call_async_output(["python", "-m", "venv", venv], callbacks)
            status = call_async_output([
                "{venv}/bin/pip", "install", "-r",
                venv + VENV_REQUIREMENTS_SUFFIX], callbacks)
            if status != 0:
                logger.warning(m18n.n("migration_0024_rebuild_python_venv",
                                      venv=venv))
            else:
                rm(venv + VENV_REQUIREMENTS_SUFFIX)
