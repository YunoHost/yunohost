import re
import os

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import chown

from yunohost.tools import Migration
from yunohost.service import service_regen_conf

command = "nice -n 19 openssl dhparam -out /etc/ssl/private/dh2048.pem -outform PEM -2 2048 -dsaparam 2> /var/log/yunohost/dhparam_generation.log && chown root:ssl-cert /etc/ssl/private/dh2048.pem && yunohost service regen-conf >> /var/log/yunohost/dhparam_generation.log && rm /etc/cron.hourly/yunohost-generate-dh-params\n"
dhparams_file = "/etc/ssl/private/dh2048.pem"

class MyMigration(Migration):
    "This migration will add dh_params line and generate it in installed instance"

    def migrate(self):

        if os.path.exists(dhparams_file):
            service_regen_conf(['nginx'])
        else:
            with open(cron_job_file, "w") as f:
                        f.write("#!/bin/bash\n")
                        f.write(command)

            _set_permissions(cron_job_file, "root", "root", 0o755)


    def backward(self):
        if os.path.exists(dhparams_file):
            os.remove(dhparams_file)
