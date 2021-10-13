import os
import glob
from shutil import copy2

from moulinette.utils.log import getActionLogger

from yunohost.app import _is_installed
from yunohost.utils.legacy import _patch_legacy_php_versions_in_settings
from yunohost.tools import Migration
from yunohost.service import _run_service_command

logger = getActionLogger("yunohost.migration")

PHP70_POOLS = "/etc/php/7.0/fpm/pool.d"
PHP73_POOLS = "/etc/php/7.3/fpm/pool.d"

PHP70_SOCKETS_PREFIX = "/run/php/php7.0-fpm"
PHP73_SOCKETS_PREFIX = "/run/php/php7.3-fpm"

MIGRATION_COMMENT = (
    "; YunoHost note : this file was automatically moved from {}".format(PHP70_POOLS)
)


class MyMigration(Migration):

    "Migrate php7.0-fpm 'pool' conf files to php7.3"

    dependencies = ["migrate_to_buster"]

    def run(self):
        # Get list of php7.0 pool files
        php70_pool_files = glob.glob("{}/*.conf".format(PHP70_POOLS))

        # Keep only basenames
        php70_pool_files = [os.path.basename(f) for f in php70_pool_files]

        # Ignore the "www.conf" (default stuff, probably don't want to touch it ?)
        php70_pool_files = [f for f in php70_pool_files if f != "www.conf"]

        for f in php70_pool_files:

            # Copy the files to the php7.3 pool
            src = "{}/{}".format(PHP70_POOLS, f)
            dest = "{}/{}".format(PHP73_POOLS, f)
            copy2(src, dest)

            # Replace the socket prefix if it's found
            c = "sed -i -e 's@{}@{}@g' {}".format(
                PHP70_SOCKETS_PREFIX, PHP73_SOCKETS_PREFIX, dest
            )
            os.system(c)

            # Also add a comment that it was automatically moved from php7.0
            # (for human traceability and backward migration)
            c = "sed -i '1i {}' {}".format(MIGRATION_COMMENT, dest)
            os.system(c)

            app_id = os.path.basename(f)[: -len(".conf")]
            if _is_installed(app_id):
                _patch_legacy_php_versions_in_settings(
                    "/etc/yunohost/apps/%s/" % app_id
                )

            nginx_conf_files = glob.glob("/etc/nginx/conf.d/*.d/%s.conf" % app_id)
            for f in nginx_conf_files:
                # Replace the socket prefix if it's found
                c = "sed -i -e 's@{}@{}@g' {}".format(
                    PHP70_SOCKETS_PREFIX, PHP73_SOCKETS_PREFIX, f
                )
                os.system(c)

        os.system(
            "rm /etc/logrotate.d/php7.0-fpm"
        )  # We remove this otherwise the logrotate cron will be unhappy

        # Reload/restart the php pools
        _run_service_command("restart", "php7.3-fpm")
        _run_service_command("enable", "php7.3-fpm")
        os.system("systemctl stop php7.0-fpm")
        os.system("systemctl disable php7.0-fpm")

        # Reload nginx
        _run_service_command("reload", "nginx")
