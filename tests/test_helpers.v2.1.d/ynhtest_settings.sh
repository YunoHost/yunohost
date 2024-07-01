ynhtest_settings() {

    test -n "$app"

    mkdir -p "/etc/yunohost/apps/$app"
    echo "label: $app" > "/etc/yunohost/apps/$app/settings.yml"

    test -z "$(ynh_app_setting_get --key="foo")"
    test -z "$(ynh_app_setting_get --key="bar")"
    test -z "$(ynh_app_setting_get --app="$app" --key="baz")"

    ynh_app_setting_set --key="foo" --value="foovalue"
    ynh_app_setting_set --app="$app" --key="bar" --value="barvalue"
    ynh_app_setting_set "$app" baz bazvalue
    
    test "$(ynh_app_setting_get --key="foo")" == "foovalue"
    test "$(ynh_app_setting_get --key="bar")" == "barvalue"
    test "$(ynh_app_setting_get --app="$app" --key="baz")" == "bazvalue"
    
    ynh_app_setting_delete --key="foo"
    ynh_app_setting_delete --app="$app" --key="bar"
    ynh_app_setting_delete "$app" baz

    test -z "$(ynh_app_setting_get --key="foo")"
    test -z "$(ynh_app_setting_get --key="bar")"
    test -z "$(ynh_app_setting_get --app="$app" --key="baz")"

    rm -rf "/etc/yunohost/apps/$app"
}

ynhtest_setting_set_default() {

    test -n "$app"

    mkdir -p "/etc/yunohost/apps/$app"
    echo "label: $app" > "/etc/yunohost/apps/$app/settings.yml"

    test -z "$(ynh_app_setting_get --key="foo")"
    test -z "${foo:-}"

    ynh_app_setting_set_default --key="foo" --value="foovalue"

    test "${foo:-}" == "foovalue"
    test "$(ynh_app_setting_get --key="foo")" == "foovalue"
    
    ynh_app_setting_set_default --key="foo" --value="bar"

    test "${foo:-}" == "foovalue"
    test "$(ynh_app_setting_get --key="foo")" == "foovalue"
    
    ynh_app_setting_delete --key="foo"

    test "${foo:-}" == "foovalue"
    test -z "$(ynh_app_setting_get --key="foo")"

    ynh_app_setting_set_default --key="foo" --value="bar"

    # Hmmm debatable ? But that's how it works right now because the var still exists
    test "${foo:-}" == "foovalue"
    test -z "$(ynh_app_setting_get --key="foo")"

    rm -rf "/etc/yunohost/apps/$app"
}
