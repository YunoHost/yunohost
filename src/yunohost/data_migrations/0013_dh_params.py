import re
import os

from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import chown

from yunohost.tools import Migration
from yunohost.certificate import _set_permissions
from yunohost.tools import cron_add

cron_job_file = "/etc/cron.hourly/yunohost-generate-dh-params"
command = "nice -n 19 openssl dhparam -out /etc/ssl/private/dh2048.pem -outform PEM -2 2048 -dsaparam 2> /var/log/yunohost/dhparam_generation.log && chown root:ssl-cert /etc/ssl/private/dh2048.pem && yunohost service regen-conf >> /var/log/yunohost/dhparam_generation.log && rm /etc/cron.hourly/yunohost-generate-dh-params\n"
dhparams_file = "/etc/ssl/private/dh2048.pem"

class MyMigration(Migration):
    
    "Add dh_params line and generate it in installed instance"

    def run(self):
        if not os.path.exists(dhparams_file):
            cron_add(command, cron_job_file)


    def backward(self):
        if os.path.exists(dhparams_file):
            os.remove(dhparams_file)
