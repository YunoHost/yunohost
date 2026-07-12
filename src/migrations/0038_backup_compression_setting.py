import os

from yunohost.utils.file_utils import read_yaml, write_to_yaml

from yunohost.settings import SETTINGS_PATH
from yunohost.tools import Migration


class MyMigration(Migration):
    "Convert the backup compression setting from boolean to gzip/zstd choice"

    introduced_in_version = "12.1"
    dependencies = []

    def run(self, *args):
        if not os.path.exists(SETTINGS_PATH):
            return

        settings = read_yaml(SETTINGS_PATH) or {}
        compress = settings.get("backup_compress_tar_archives")
        if not isinstance(compress, bool):
            return

        if compress:
            settings["backup_compress_tar_archives"] = "gzip"
        else:
            # "none" is the new default, no need to keep the key around
            del settings["backup_compress_tar_archives"]
        write_to_yaml(SETTINGS_PATH, settings)
