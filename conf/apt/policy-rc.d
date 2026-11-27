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

# Here you can find some resources to understand policy-rc.d
# https://manpages.debian.org/bullseye/init-system-helpers/deb-systemd-invoke.1p.en.html
# and zcat /usr/share/doc/init-system-helpers/README.policy-rc.d.gz
# and the code inside /usr/bin/deb-systemd-invoke to see how it calls /usr/sbin/policy-rc.d ...
# and also invoke-rc.d code too ...

[[ "$1" == "--quiet" ]] && shift 1
[[ "$1" == "--list" ]] && exit 0

id=$1
actions=$2

# We just want to control "restart" operations
# Here we voluntarily avoid to forbid nginx 'upgrade' custom action
# cause this action should not cut any connection.
# FIXME Properly managed the multiactions case
[[ " $actions " =~ " restart " || " $actions " =~ " try-restart " ]] || exit 0

DELAYED_SERVICES_FILE=/var/run/yunohost/policy-rc.d.delayed-restarts

# nginx is in this list in the case the custom upgrade action fail
# in this case the postinst try a restart action
services="yunohost-api nginx $(cat $DELAYED_SERVICES_FILE 2>/dev/null)"
for service in $services
do
    if [[ "$id" == "${service}.service" || "$id" == "${service}" ]] \
       && fuser /var/run/moulinette_yunohost.lock &>/dev/null
    then
        systemctl is-enabled --quiet "$service" \
          || systemctl is-active --quiet "$service" || exit 101
        
        # Wait for apt / dpkg / yunohost to not be up anymore, hence the upgrade finished
        # to try to restart the service if it's still enabled
        # SECONDS is a specific bash var, see https://tldp.org/LDP/abs/html/internalvariables.html
        restart_after=$(cat <<EOF 
SECONDS=0
while (( SECONDS < 86400 )) && ( \
          fuser /var/run/unattended-upgrades.lock &>/dev/null \
          || fuser /var/lib/dpkg/lock-frontend &>/dev/null \
          || fuser /var/run/moulinette_yunohost.lock &>/dev/null \
      )
do
   sleep 5
done

systemctl is-enabled --quiet "$service" \
  || systemctl is-active --quiet "$service" || exit 1
systemctl restart $service
EOF
)
        systemd-run --no-block --quiet bash -c "$restart_after"
        exit 101
    fi
done
exit 0
