import subprocess
from yunohost.tools import Migration, tools_update
from yunohost.service import service_regen_conf
from moulinette.utils.filesystem import write_to_file, chown, rm


class MyMigration(Migration):
    def forward(self):

        # Add Prosody repository and install it
        write_to_file("/etc/apt/sources.list.d/prosody.list", "deb http://packages.prosody.im/debian jessie main")
        subprocess.call("wget https://prosody.im/files/prosody-debian-packages.key -O- | sudo apt-key add -", shell=True)
        subprocess.call("apt update", shell=True)
        subprocess.call("apt install prosody -y", shell=True)

        # Copy and change premissions of data storage: rosters, vcard
        subprocess.call("cp -r /var/lib/metronome/* /var/lib/prosody/", shell=True)
        chown("/var/lib/prosody", "prosody", "prosody", True)

        # Generate Prosody configuration
        service_regen_conf(["prosody"])

    def backward(self):
        # Remove Prosody repository and key
        rm("/etc/apt/sources.list.d/prosody.list")

        # https://askubuntu.com/a/107189
        subprocess.call("apt-key del 74D9DBB5", shell=True)

        # Copy and change premissions of data storage: rosters, vcard
        subprocess.call("cp -r /var/lib/prosody/* /var/lib/metronome/", shell=True)
        chown("/var/lib/metronome", "metronome", "metronome", True)

        # Generate Metronome configuration
        # Can't work as Metronome regen-conf scripts are no more present
        # service_regen_conf(["metronome"])
