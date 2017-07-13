import subprocess
from yunohost.migrations import Migration


class MyMigration(Migration):
    "Remove archivemount because we don't use it anymore"

    def forward(self):
        subprocess.check_call("apt-get remove archivemount")

    def backward(self):
        subprocess.check_call("apt-get install archivemount")
