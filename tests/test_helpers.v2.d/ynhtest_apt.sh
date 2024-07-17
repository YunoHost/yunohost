ynhtest_apt_install_apt_deps_regular() {

    dpkg --list | grep -q "ii *$app-ynh-deps" && apt remove $app-ynh-deps --assume-yes || true
    dpkg --list | grep -q 'ii *nyancat' && apt remove nyancat --assume-yes || true
    dpkg --list | grep -q 'ii *sl' && apt remove sl --assume-yes || true

    ! ynh_package_is_installed "$app-ynh-deps"
    ! ynh_package_is_installed "nyancat"
    ! ynh_package_is_installed "sl"

    ynh_install_app_dependencies "nyancat sl"

    ynh_package_is_installed "$app-ynh-deps"
    ynh_package_is_installed "nyancat"
    ynh_package_is_installed "sl"
    
    ynh_remove_app_dependencies

    ! ynh_package_is_installed "$app-ynh-deps"
    ! ynh_package_is_installed "nyancat"
    ! ynh_package_is_installed "sl"
}
