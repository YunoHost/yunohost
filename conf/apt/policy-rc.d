#!/bin/bash
if [[ "$1" =~ "nginx" ]] && [ -e /var/run/moulinette_yunohost.lock ]; then
    echo "(Delaying the restart of nginx, this should automatically happen after the end of this upgrade)"
    cat << EOF | at -M now >/dev/null 2>&1
# Wait for apt / dpkg / yunohost to not be up anymore, hence the upgrade finished

while pgrep -x apt || pgrep -x apt-get || pgrep dpkg || test -e /var/run/moulinette_yunohost.lock;
do
   sleep 3
done

# Restart nginx, though only if it wasnt already restarted by something else in the last 60 secs

API_START_TIMESTAMP="\$(date --date="\$(systemctl show nginx | grep ExecMainStartTimestamp= | awk -F= '{print \$2}')" +%s)"

if [ "\$(( \$(date +%s) - \$API_START_TIMESTAMP ))" -ge 60 ];
then
    systemctl restart nginx
fi
EOF
    exit 101
fi
exit 0
