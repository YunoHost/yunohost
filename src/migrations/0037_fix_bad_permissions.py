from logging import DEBUG, ERROR, WARNING, getLogger

from moulinette import m18n

from ..tools import Migration
from ..utils.error import YunohostError
from ..utils.process import call_async_output

logger = getLogger("yunohost.migration")


class MyMigration(Migration):
    introduced_in_version = "12.1"
    dependencies = []

    @property
    def mode(self):
        return "manual"

    @property
    def disclaimer(self) -> str | None:
        return m18n.n("migration_0037_fix_bad_permissions_disclaimer")

    def run(self, *args):
        from psutil import disk_partitions
        # Find all directories, files and socket with writable permissions
        # for others and not in excluded scope and remove this writable
        # permissions.

        logger.debug("Removing others writable permissions for the following paths:")
        # Count number of files protected (or not if it failed to protect it)
        nb_paths_protected = 0
        nb_paths_unprotected = 0

        def log(level, line):
            if level == DEBUG:
                nonlocal nb_paths_protected
                nb_paths_protected += 1
            elif level >= WARNING:
                nonlocal nb_paths_unprotected
                nb_paths_unprotected += 1
            logger.log(level, line.rstrip() + "\r")

        callbacks = (
            lambda line: log(DEBUG, line),
            lambda line: log(WARNING, line),
            lambda line: log(ERROR, line),
        )

        # Exclude some directories
        exclude_dirs = [
            "/tmp",  # If not in ram, it's wiped at reboot and regularly
            "/var/spool/postfix",  # Postfix public socket seems okish
            "/ynh-dev",  # We don't want to explore /ynh-dev for that
        ]
        exclude_conditions = [
            arg for directory in exclude_dirs for arg in ["-path", directory, "-o"]
        ]
        exclude_conditions = " ".join(exclude_conditions)

        # Exclude BTRFS snapshots (probably in readonly mode anyway)
        exclude_conditions += (
            " ( -regextype posix-extended -regex .*/.snapshots(/.*)? )"
        )

        # Define which FS we want to explore
        fstypes_selected = ["ext2", "ext3", "ext4", "btrfs", "xfs", "zfs"]

        # Run a find command on each mountpoint binded to a selected FS
        for partition in disk_partitions(True):
            if (
                partition.fstype not in fstypes_selected
                or not partition.mountpoint
                or "ro" in partition.opts.split(",")
            ):
                continue

            # Build the find command
            # Parenthesis are voluntarily unescaped with \ cause we do
            # not use shell=True call_async_output option
            cmd = f"/usr/bin/find <PATH> -mount ( {exclude_conditions} ) -prune"
            cmd += " -o ( -type f -or -type d -or -type s ) -perm -o+w ! -perm /o+t"
            # If chmod succeed, print the file (default AND operator of find cmd)
            # else let chmod display a warning but avoid to display the file
            cmd += " -exec chmod o-w {} ; -print"
            cmd = cmd.split(" ")
            cmd[1] = partition.mountpoint
            logger.debug(cmd)

            # Call the command and display what happens in logs
            ret = call_async_output(cmd, callbacks)

        # Give some summarized info to the instance admin
        if nb_paths_protected:
            logger.info(
                m18n.n(
                    "migration_0037_fix_bad_permissions_protected",
                    nb=nb_paths_protected,
                )
            )

        if nb_paths_unprotected:
            logger.warning(
                m18n.n(
                    "migration_0037_fix_bad_permissions_unprotected",
                    nb=nb_paths_unprotected,
                )
            )

        if ret != 0:
            raise YunohostError(
                f"The find command fails for an unknow reasons (return code: {ret})",
                raw_msg=True,
            )

        if not nb_paths_unprotected and not nb_paths_protected:
            logger.success(m18n.n("migration_0037_fix_bad_permissions_safe_system"))
