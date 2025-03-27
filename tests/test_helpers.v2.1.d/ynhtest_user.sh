#!/usr/bin/env bash

ynhtest_system_user_create() {
    username=$(head -c 12 /dev/urandom | md5sum | head -c 12)

    ! ynh_system_user_exists --username="$username"

    ynh_system_user_create --username="$username"

    ynh_system_user_exists --username="$username"

    ynh_system_user_delete --username="$username"

    ! ynh_system_user_exists --username="$username"
}

ynhtest_system_user_with_group() {
    username=$(head -c 12 /dev/urandom | md5sum | head -c 12)

    ynh_system_user_create --username="$username" --groups="ssl-cert,ssh.app"

    grep -q "^ssl-cert:.*$username" /etc/group
    grep -q "^ssh.app:.*$username" /etc/group

    ynh_system_user_delete --username="$username"
}
