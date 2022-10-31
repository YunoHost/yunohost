import os

from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration

logger = getActionLogger("yunohost.migration")

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):
    """
    Create default backup repository
    """

    introduced_in_version = "11.2"
    dependencies = []

    @Migration.ldap_migration
    def run(self, *args):

        from yunohost.repository import BackupRepository
        
        # Move old tar archives in a subdir
        # Think to people doing symbolik links or mount point on archives dir
        OLD_TAR_ARCHIVES_PATH = "/home/yunohost.backup/archives"
        NEW_TAR_ARCHIVES_PATH = f"{OLD_TAR_ARCHIVES_PATH}/tar"

        mkdir(NEW_TAR_ARCHIVES_PATH)
        archives = glob(f"{OLD_TAR_ARCHIVES_PATH}/*.tar.gz") + glob(f"{OLD_TAR_ARCHIVES_PATH}/*.tar")
        for archive in archives:
            os.rename(archive, NEW_TAR_ARCHIVES_PATH + archive.replace(OLD_TAR_ARCHIVES_PATH, ""))
        
        # Create a new local borg repository
        NEW_BORG_ARCHIVES_PATH = f"{OLD_TAR_ARCHIVES_PATH}/borg"
        args = {
            name="Local borg archives",
            location=NEW_BORG_ARCHIVES_PATH,
            method="borg",
            alert="root",
            passphrase=None
        }
        repository = BackupRepository("local-borg", creation=True).set(
            args=urllib.parse.urlencode(args, doseq=True)
        )
        
        # Add the legagy tar repository
        args = {
            name="Local tar archives (legacy)",
            location=NEW_TAR_ARCHIVES_PATH,
            method="tar",
            alert="root",
        }
        repository = BackupRepository("local-tar", creation=True).set(
            args=urllib.parse.urlencode(args, doseq=True)
        )
