#!/usr/bin/env bash
#
# Copyright (c) 2026 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

# c.f. https://manpages.debian.org/bullseye/init-system-helpers/deb-systemd-invoke.1p.en.html
# and zcat /usr/share/doc/init-system-helpers/README.policy-rc.d.gz
# and the code inside /usr/bin/deb-systemd-invoke to see how it calls /usr/sbin/policy-rc.d ...
# and also invoke-rc.d ...
services="yunohost-api nginx"
if [ -e /var/run/yunohost/services-to-restart-after-upgrade ];
then
    services="$services $(cat /var/run/yunohost/services-to-restart-after-upgrade)"
fi
for service in $services
do
    if [[ "$1" == "${service}.service" || "$1" == "${service}" ]] && [ -e /var/run/moulinette_yunohost.lock ]; then
       if ! pgrep $service; then
           exit 101
       fi
        cat << EOF | at -M now >/dev/null 2>&1
# Wait for apt / dpkg / yunohost to not be up anymore, hence the upgrade finished

while pgrep -x apt || pgrep -x apt-get || pgrep dpkg || test -e /var/run/moulinette_yunohost.lock;
do
   sleep 3
done

# Restart the service, though only if it wasnt already restarted by something else in the last 60 secs

API_START_TIMESTAMP="\$(date --date="\$(systemctl show $service | grep ExecMainStartTimestamp= | awk -F= '{print \$2}')" +%s)"

if [ "\$(( \$(date +%s) - \$API_START_TIMESTAMP ))" -ge 60 ];
then
    systemctl restart $service
fi
EOF
        exit 101
    fi
done
exit 0
