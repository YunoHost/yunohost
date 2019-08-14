import os
import glob
from shutil import copy2

from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.service import _run_service_command

logger = getActionLogger('yunohost.migration')

PHP5_POOLS = "/etc/php5/fpm/pool.d"
PHP7_POOLS = "/etc/php/7.0/fpm/pool.d"

PHP5_SOCKETS_PREFIX = "/var/run/php5-fpm"
PHP7_SOCKETS_PREFIX = "/run/php/php7.0-fpm"

MIGRATION_COMMENT = "; YunoHost note : this file was automatically moved from {}".format(PHP5_POOLS)


class MyMigration(Migration):

    "Migrate php5-fpm 'pool' conf files to php7 stuff"

    dependencies = ["migrate_to_stretch"]

    def run(self):
        # Get list of php5 pool files
        php5_pool_files = glob.glob("{}/*.conf".format(PHP5_POOLS))

        # Keep only basenames
        php5_pool_files = [os.path.basename(f) for f in php5_pool_files]

        # Ignore the "www.conf" (default stuff, probably don't want to touch it ?)
        php5_pool_files = [f for f in php5_pool_files if f != "www.conf"]

        for f in php5_pool_files:

            # Copy the files to the php7 pool
            src = "{}/{}".format(PHP5_POOLS, f)
            dest = "{}/{}".format(PHP7_POOLS, f)
            copy2(src, dest)

            # Replace the socket prefix if it's found
            c = "sed -i -e 's@{}@{}@g' {}".format(PHP5_SOCKETS_PREFIX, PHP7_SOCKETS_PREFIX, dest)
            os.system(c)

            # Also add a comment that it was automatically moved from php5
            # (for human traceability and backward migration)
            c = "sed -i '1i {}' {}".format(MIGRATION_COMMENT, dest)
            os.system(c)

            # Some old comments starting with '#' instead of ';' are not
            # compatible in php7
            c = "sed -i 's/^#/;#/g' {}".format(dest)
            os.system(c)

        # Reload/restart the php pools
        _run_service_command("restart", "php7.0-fpm")
        _run_service_command("enable", "php7.0-fpm")
        os.system("systemctl stop php5-fpm")
        os.system("systemctl disable php5-fpm")
        os.system("rm /etc/logrotate.d/php5-fpm")  # We remove this otherwise the logrotate cron will be unhappy

        # Get list of nginx conf file
        nginx_conf_files = glob.glob("/etc/nginx/conf.d/*.d/*.conf")
        for f in nginx_conf_files:
            # Replace the socket prefix if it's found
            c = "sed -i -e 's@{}@{}@g' {}".format(PHP5_SOCKETS_PREFIX, PHP7_SOCKETS_PREFIX, f)
            os.system(c)

        # Reload nginx
        _run_service_command("reload", "nginx")

    def backward(self):

        # Get list of php7 pool files
        php7_pool_files = glob.glob("{}/*.conf".format(PHP7_POOLS))

        # Keep only files which have the migration comment
        php7_pool_files = [f for f in php7_pool_files if open(f).readline().strip() == MIGRATION_COMMENT]

        # Delete those files
        for f in php7_pool_files:
            os.remove(f)

        # Reload/restart the php pools
        _run_service_command("stop", "php7.0-fpm")
        os.system("systemctl start php5-fpm")

        # Get list of nginx conf file
        nginx_conf_files = glob.glob("/etc/nginx/conf.d/*.d/*.conf")
        for f in nginx_conf_files:
            # Replace the socket prefix if it's found
            c = "sed -i -e 's@{}@{}@g' {}".format(PHP7_SOCKETS_PREFIX, PHP5_SOCKETS_PREFIX, f)
            os.system(c)

        # Reload nginx
        _run_service_command("reload", "nginx")
