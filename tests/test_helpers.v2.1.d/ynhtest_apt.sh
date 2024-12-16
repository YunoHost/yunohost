#!/usr/bin/env bash

ynhtest_apt_install_apt_deps_regular() {

    cat << EOF > ../manifest.toml
packaging_format = 2
id = "${app:?}"
version = "0.1~ynh2"
EOF

    if dpkg --list | grep -q "ii *$app-ynh-deps "; then
        apt remove "$app-ynh-deps" --assume-yes
    fi
    if dpkg --list | grep -q 'ii *nyancat '; then
        apt remove nyancat --assume-yes
    fi
    if dpkg --list | grep -q 'ii *sl '; then
        apt remove sl --assume-yes
    fi

    ! _ynh_apt_package_is_installed "$app-ynh-deps"
    ! _ynh_apt_package_is_installed "nyancat"
    ! _ynh_apt_package_is_installed "sl"

    ynh_apt_install_dependencies "nyancat sl"

    _ynh_apt_package_is_installed "$app-ynh-deps"
    _ynh_apt_package_is_installed "nyancat"
    _ynh_apt_package_is_installed "sl"

    ynh_apt_remove_dependencies

    ! _ynh_apt_package_is_installed "$app-ynh-deps"
    ! _ynh_apt_package_is_installed "nyancat"
    ! _ynh_apt_package_is_installed "sl"
}
