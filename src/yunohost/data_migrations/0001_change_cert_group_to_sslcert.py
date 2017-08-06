import subprocess
import glob
from yunohost.tools import Migration
from moulinette.utils.filesystem import chown

class MyMigration(Migration):
    "Change certificates group permissions from 'metronome' to 'ssl-cert'"

    all_certificate_files = glob.glob("/etc/yunohost/certs/*/*.pem")

    def forward(self):
        for filename in self.all_certificate_files:
            chown(filename, uid="root", gid="ssl-cert")

    def backward(self):
        for filename in self.all_certificate_files:
            chown(filename, uid="root", gid="metronome")
