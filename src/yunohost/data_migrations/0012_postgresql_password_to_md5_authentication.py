import glob
import re
from yunohost.tools import Migration
from moulinette.utils.filesystem import read_file, write_to_file


class MyMigration(Migration):

    "Force authentication in md5 for local connexions"

    all_hba_files = glob.glob("/etc/postgresql/*/*/pg_hba.conf")

    def run(self):
        for filename in self.all_hba_files:
            pg_hba_in = read_file(filename)
            write_to_file(filename, re.sub(r"local(\s*)all(\s*)all(\s*)password", "local\\1all\\2all\\3md5", pg_hba_in))
