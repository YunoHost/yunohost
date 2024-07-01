ynhtest_apt_install_apt_deps_regular() {

    dpkg --list | grep -q "ii *$app-ynh-deps" && apt remove $app-ynh-deps --assume-yes || true
    dpkg --list | grep -q 'ii *nyancat' && apt remove nyancat --assume-yes || true
    dpkg --list | grep -q 'ii *sl' && apt remove sl --assume-yes || true

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
