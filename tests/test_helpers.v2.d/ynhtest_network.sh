ynhtest_port_80_aint_available() {
    ! ynh_port_available 80 
}

ynhtest_port_12345_is_available() {
    ynh_port_available 12345
}

ynhtest_port_12345_is_booked_by_other_app() {

    ynh_port_available 12345
    ynh_port_available 12346

    mkdir -p /etc/yunohost/apps/block_port/
    echo "port: '12345'" > /etc/yunohost/apps/block_port/settings.yml
    ! ynh_port_available 12345

    echo "other_port: '12346'" > /etc/yunohost/apps/block_port/settings.yml
    ! ynh_port_available 12346

    rm -rf /etc/yunohost/apps/block_port
}
