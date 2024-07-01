ynhtest_simple_template_app_config() {

    mkdir -p /etc/yunohost/apps/$app/
    echo "id: $app" > /etc/yunohost/apps/$app/settings.yml

    template="$(mktemp -d -p $VAR_WWW)/template.txt"
    cat << EOF > $template 
app=__APP__
foo=__FOO__
EOF

    foo="bar"
    install_dir="$VAR_WWW"
    
    ynh_config_add --template="$template" --destination="$VAR_WWW/config.txt"

    test "$(cat $VAR_WWW/config.txt)" == "$(echo -ne 'app=ynhtest\nfoo=bar')"
    test "$(ls -l $VAR_WWW/config.txt | cut -d' ' -f1-4)" == "-rw------- 1 ynhtest ynhtest"
}

ynhtest_simple_template_system_config() {

    mkdir -p /etc/yunohost/apps/$app/
    echo "id: $app" > /etc/yunohost/apps/$app/settings.yml

    rm -f /etc/cron.d/ynhtest_config

    template="$(mktemp -d -p $VAR_WWW)/template.txt"
    cat << EOF > $template 
app=__APP__
foo=__FOO__
EOF

    foo="bar"
    
    ynh_config_add --template="$template" --destination="/etc/cron.d/ynhtest_config"

    test "$(cat /etc/cron.d/ynhtest_config)" == "$(echo -ne 'app=ynhtest\nfoo=bar')"
    test "$(ls -l /etc/cron.d/ynhtest_config | cut -d' ' -f1-4)" == "-r-------- 1 root root"

    rm -f /etc/cron.d/ynhtest_config
}

ynhtest_jinja_template_app_config() {

    mkdir -p /etc/yunohost/apps/$app/
    echo "id: $app" > /etc/yunohost/apps/$app/settings.yml

    template="$(mktemp -d -p $VAR_WWW)/template.txt"
    cat << EOF > $template 
app={{ app }}
{% if foo == "bar" %}foo=true{% endif %}
EOF

    foo="bar"
    install_dir="$VAR_WWW"
    
    ynh_config_add --template="$template" --destination="$VAR_WWW/config.txt" --jinja

    test "$(cat $VAR_WWW/config.txt)" == "$(echo -ne 'app=ynhtest\nfoo=true')"
    test "$(ls -l $VAR_WWW/config.txt | cut -d' ' -f1-4)" == "-rw------- 1 ynhtest ynhtest"
}


