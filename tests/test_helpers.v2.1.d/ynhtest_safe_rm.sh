#!/usr/bin/env bash

ynhtest_acceptable_path_to_delete() {

    mkdir -p "/home/someuser"
    mkdir -p "/home/${app:?}"
    mkdir -p "/home/yunohost.app/$app"
    mkdir -p "/var/www/$app"
    touch "/var/www/$app/bar"
    touch "/etc/cron.d/$app"

    ! _acceptable_path_to_delete /
    ! _acceptable_path_to_delete ////
    ! _acceptable_path_to_delete "    ////   "
    ! _acceptable_path_to_delete "/var"
    ! _acceptable_path_to_delete "/var/www"
    ! _acceptable_path_to_delete "/var/cache"
    ! _acceptable_path_to_delete "/usr"
    ! _acceptable_path_to_delete "/usr/bin"
    ! _acceptable_path_to_delete "/home"
    ! _acceptable_path_to_delete "/home/yunohost.backup"
    ! _acceptable_path_to_delete "/home/yunohost.app"
    ! _acceptable_path_to_delete "/home/yunohost.app/"
    ! _acceptable_path_to_delete "///home///yunohost.app///"
    ! _acceptable_path_to_delete "/home/yunohost.app/$app/.."
    ! _acceptable_path_to_delete "///home///yunohost.app///$app///..//"
    ! _acceptable_path_to_delete "/home/yunohost.app/../$app/.."
    ! _acceptable_path_to_delete "/home/someuser"
    ! _acceptable_path_to_delete "/home/yunohost.app//../../$app"
    ! _acceptable_path_to_delete "  /home/yunohost.app///  "
    ! _acceptable_path_to_delete "/etc/cron.d/"
    ! _acceptable_path_to_delete "/etc/yunohost/"

    _acceptable_path_to_delete "/home/yunohost.app/$app"
    _acceptable_path_to_delete "/home/yunohost.app/$app/bar"
    _acceptable_path_to_delete "/etc/cron.d/$app"
    _acceptable_path_to_delete "/var/www/$app/bar"
    _acceptable_path_to_delete "/var/www/$app"

    rm "/var/www/$app/bar"
    rm "/etc/cron.d/$app"
    rmdir "/home/yunohost.app/$app"
    rmdir "/home/$app"
    rmdir "/home/someuser"
    rmdir "/var/www/$app"
}

ynhtest_safe_rm() {

    mkdir -p "/home/someuser"
    mkdir -p "/home/yunohost.app/$app"
    mkdir -p "/var/www/$app"
    mkdir -p "/var/whatever"
    touch "/var/www/$app/bar"
    touch "/etc/cron.d/$app"

    ! ynh_safe_rm "/home/someuser"
    ! ynh_safe_rm "/home/yunohost.app/"
    ! ynh_safe_rm "/var/whatever"
    ynh_safe_rm "/home/yunohost.app/$app"
    ynh_safe_rm "/var/www/$app"
    ynh_safe_rm "/etc/cron.d/$app"

    test -e "/home/someuser"
    test -e "/home/yunohost.app"
    test -e "/var/whatever"
    ! test -e "/home/yunohost.app/$app"
    ! test -e "/var/www/$app"
    ! test -e "/etc/cron.d/$app"

    rmdir /home/someuser
    rmdir /var/whatever
}
