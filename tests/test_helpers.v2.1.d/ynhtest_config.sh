
#################
#  _ __  _   _  #
# | '_ \| | | | #
# | |_) | |_| | #
# | .__/ \__, | #
# | |     __/ | #
# |_|    |___/  #
#               #
#################

_read_py() {
    local file="$1"
    local key="$2"
    python3 -c "exec(open('$file').read()); print($key)"
}

ynhtest_config_read_py() {

    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.py"

    cat << EOF > $dummy_dir/dummy.py
# Some comment
FOO = None
ENABLED = False
# TITLE = "Old title"
TITLE = "Lorem Ipsum"
THEME = "colib'ris"
EMAIL = "root@example.com" # This is a comment without quotes
PORT   = 1234 # This is a comment without quotes
URL = 'https://yunohost.org'
DICT = {}
DICT['ldap_base'] = "ou=users,dc=yunohost,dc=org"
DICT['ldap_conf'] = {}
DICT['ldap_conf']['user'] = "camille"
# YNH_ICI
DICT['TITLE'] = "Hello world"
EOF

    test "$(_read_py                    "$file"       "FOO")" == "None"
    test "$(ynh_read_var_in_file --file="$file" --key="FOO")" == "None"

    test "$(_read_py                    "$file"       "ENABLED")" == "False"
    test "$(ynh_read_var_in_file --file="$file" --key="ENABLED")" == "False"

    test "$(_read_py                    "$file"       "TITLE")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file --file="$file" --key="TITLE")" == "Lorem Ipsum"

    test "$(_read_py                    "$file"       "THEME")" == "colib'ris"
    test "$(ynh_read_var_in_file --file="$file" --key="THEME")" == "colib'ris"

    test "$(_read_py                    "$file"       "EMAIL")" == "root@example.com"
    test "$(ynh_read_var_in_file --file="$file" --key="EMAIL")" == "root@example.com"

    test "$(_read_py                    "$file"       "PORT")" == "1234"
    test "$(ynh_read_var_in_file --file="$file" --key="PORT")" == "1234"

    test "$(_read_py                    "$file"       "URL")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file --file="$file" --key="URL")" == "https://yunohost.org"

    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=users,dc=yunohost,dc=org"
    
    test "$(ynh_read_var_in_file --file="$file" --key="user")" == "camille"
    
    test "$(ynh_read_var_in_file --file="$file" --key="TITLE" --after="YNH_ICI")" == "Hello world"

    ! _read_py                          "$file"       "NONEXISTENT"
    test "$(ynh_read_var_in_file --file="$file" --key="NONEXISTENT")" == "YNH_NULL"

    ! _read_py                          "$file"       "ENABLE"
    test "$(ynh_read_var_in_file --file="$file" --key="ENABLE")" == "YNH_NULL"
}

ynhtest_config_write_py() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.py"

    cat << EOF > $dummy_dir/dummy.py
# Some comment
FOO = None
ENABLED = False
# TITLE = "Old title"
TITLE = "Lorem Ipsum"
THEME = "colib'ris"
EMAIL = "root@example.com" # This is a comment without quotes
PORT   = 1234 # This is a comment without quotes
URL = 'https://yunohost.org'
DICT = {}
DICT['ldap_base'] = "ou=users,dc=yunohost,dc=org"
# YNH_ICI
DICT['TITLE'] = "Hello world"
EOF

    ynh_write_var_in_file        --file="$file" --key="FOO" --value="bar"
    test "$(_read_py                    "$file"       "FOO")"    == "bar"
    test "$(ynh_read_var_in_file --file="$file" --key="FOO")"    == "bar"

    ynh_write_var_in_file        --file="$file" --key="ENABLED" --value="True"
    test "$(_read_py                    "$file"       "ENABLED")"    == "True"
    test "$(ynh_read_var_in_file --file="$file" --key="ENABLED")"    == "True"

    ynh_write_var_in_file        --file="$file" --key="TITLE" --value="Foo Bar"
    test "$(_read_py                    "$file"       "TITLE")"    == "Foo Bar"
    test "$(ynh_read_var_in_file --file="$file" --key="TITLE")"    == "Foo Bar"

    ynh_write_var_in_file        --file="$file" --key="THEME" --value="super-awesome-theme"
    test "$(_read_py                    "$file"       "THEME")"    == "super-awesome-theme"
    test "$(ynh_read_var_in_file --file="$file" --key="THEME")"    == "super-awesome-theme"

    ynh_write_var_in_file        --file="$file" --key="EMAIL" --value="sam@domain.tld"
    test "$(_read_py                    "$file"       "EMAIL")"    == "sam@domain.tld"
    test "$(ynh_read_var_in_file --file="$file" --key="EMAIL")"    == "sam@domain.tld"

    ynh_write_var_in_file        --file="$file" --key="PORT" --value="5678"
    test "$(_read_py                    "$file"       "PORT")"    == "5678"
    test "$(ynh_read_var_in_file --file="$file" --key="PORT")"    == "5678"

    ynh_write_var_in_file        --file="$file" --key="URL" --value="https://domain.tld/foobar"
    test "$(_read_py                    "$file"       "URL")"    == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="URL")"    == "https://domain.tld/foobar"

    ynh_write_var_in_file        --file="$file" --key="ldap_base" --value="ou=users,dc=yunohost,dc=org"
    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")"    == "ou=users,dc=yunohost,dc=org"
    
    ynh_write_var_in_file        --file="$file" --key="TITLE" --value="YOLO" --after="YNH_ICI"
    test "$(ynh_read_var_in_file --file="$file" --key="TITLE" --after="YNH_ICI")" == "YOLO"

    ! ynh_write_var_in_file      --file="$file" --key="NONEXISTENT" --value="foobar"
    ! _read_py                          "$file"       "NONEXISTENT"
    test "$(ynh_read_var_in_file --file="$file" --key="NONEXISTENT")" == "YNH_NULL"

    ! ynh_write_var_in_file      --file="$file" --key="ENABLE" -value="foobar"
    ! _read_py                          "$file"       "ENABLE"
    test "$(ynh_read_var_in_file --file="$file" --key="ENABLE")" == "YNH_NULL"

}

###############
#  _       _  #
# (_)     (_) #
#  _ _ __  _  #
# | | '_ \| | #
# | | | | | | #
# |_|_| |_|_| #
#             #
###############

_read_ini() {
    local file="$1"
    local key="$2"
    python3 -c "import configparser; c = configparser.ConfigParser(); c.read('$file'); print(c['main']['$key'])"
}

ynhtest_config_read_ini() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.ini"

    cat << EOF > $file
# Some comment
; Another comment
[main]
foo = null
enabled =    False
# title = Old title
title =    Lorem Ipsum
theme = colib'ris
email = root@example.com ; This is a comment without quotes
port =     1234 ; This is a comment without quotes
url = https://yunohost.org
[dict]
    ldap_base = ou=users,dc=yunohost,dc=org
EOF

    test "$(_read_ini                   "$file"       "foo")" == "null"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")" == "null"

    test "$(_read_ini                   "$file"       "enabled")" == "False"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "False"

    test "$(_read_ini                   "$file"       "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file --file="$file" --key="title")" == "Lorem Ipsum"

    test "$(_read_ini                   "$file"       "theme")" == "colib'ris"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")" == "colib'ris"

    #test "$(_read_ini                   "$file"       "email")" == "root@example.com"
    test "$(ynh_read_var_in_file --file="$file" --key="email")" == "root@example.com"

    #test "$(_read_ini                   "$file"       "port")" == "1234"
    test "$(ynh_read_var_in_file --file="$file" --key="port")" == "1234"

    test "$(_read_ini                   "$file"       "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file --file="$file" --key="url")" == "https://yunohost.org"

    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=users,dc=yunohost,dc=org"

    ! _read_ini                         "$file"       "nonexistent"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! _read_ini                         "$file"       "enable"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")" == "YNH_NULL"

}

ynhtest_config_write_ini() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.ini"

    cat << EOF > $file
# Some comment
; Another comment
[main]
foo = null
enabled =    False
# title = Old title
title =    Lorem Ipsum
theme = colib'ris
email = root@example.com # This is a comment without quotes
port =     1234 # This is a comment without quotes
url = https://yunohost.org
[dict]
    ldap_base = ou=users,dc=yunohost,dc=org
EOF

    ynh_write_var_in_file        --file="$file" --key="foo" --value="bar"
    test "$(_read_ini                   "$file"       "foo")"    == "bar"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")"    == "bar"

    ynh_write_var_in_file        --file="$file" --key="enabled" --value="True"
    test "$(_read_ini                   "$file"       "enabled")"    == "True"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")"    == "True"

    ynh_write_var_in_file        --file="$file" --key="title" --value="Foo Bar"
    test "$(_read_ini                   "$file"       "title")"    == "Foo Bar"
    test "$(ynh_read_var_in_file --file="$file" --key="title")"    == "Foo Bar"

    ynh_write_var_in_file        --file="$file" --key="theme" --value="super-awesome-theme"
    test "$(_read_ini                   "$file"       "theme")"    == "super-awesome-theme"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")"    == "super-awesome-theme"

    ynh_write_var_in_file        --file="$file" --key="email" --value="sam@domain.tld"
    test "$(_read_ini                   "$file"       "email")"    == "sam@domain.tld # This is a comment without quotes"
    test "$(ynh_read_var_in_file --file="$file" --key="email")"    == "sam@domain.tld"

    ynh_write_var_in_file        --file="$file" --key="port" --value="5678"
    test "$(_read_ini                   "$file"       "port")"    == "5678 # This is a comment without quotes"
    test "$(ynh_read_var_in_file --file="$file" --key="port")"    == "5678"

    ynh_write_var_in_file        --file="$file" --key="url" --value="https://domain.tld/foobar"
    test "$(_read_ini                   "$file"       "url")"    == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="url")"    == "https://domain.tld/foobar"

    ynh_write_var_in_file        --file="$file" --key="ldap_base" --value="ou=users,dc=yunohost,dc=org"
    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")"    == "ou=users,dc=yunohost,dc=org"

    ! ynh_write_var_in_file      --file="$file" --key="nonexistent" "foobar"
    ! _read_ini                         "$file"       "nonexistent"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! ynh_write_var_in_file      --file="$file" --key="enable" "foobar"
    ! _read_ini                         "$file"       "enable"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")" == "YNH_NULL"

}

#############################
#                        _  #
#                       | | #
#  _   _  __ _ _ __ ___ | | #
# | | | |/ _` | '_ ` _ \| | #
# | |_| | (_| | | | | | | | #
#  \__, |\__,_|_| |_| |_|_| #
#   __/ |                   #
#  |___/                    #
#                           #
#############################

_read_yaml() {
    local file="$1"
    local key="$2"
    python3 -c "import yaml; print(yaml.safe_load(open('$file'))['$key'])"
}

ynhtest_config_read_yaml() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.yml"

    cat << EOF > $file
# Some comment
foo:
enabled: false
# title: old title
title: Lorem Ipsum
theme: colib'ris
email: root@example.com # This is a comment without quotes
port: 1234 # This is a comment without quotes
url: https://yunohost.org
dict:
   ldap_base: ou=users,dc=yunohost,dc=org
EOF

    test "$(_read_yaml                  "$file"       "foo")" == "None"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")" == ""

    test "$(_read_yaml                  "$file"       "enabled")" == "False"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "false"

    test "$(_read_yaml                  "$file"       "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file --file="$file" --key="title")" == "Lorem Ipsum"

    test "$(_read_yaml                  "$file"       "theme")" == "colib'ris"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")" == "colib'ris"

    test "$(_read_yaml                  "$file"       "email")" == "root@example.com"
    test "$(ynh_read_var_in_file --file="$file" --key="email")" == "root@example.com"

    test "$(_read_yaml                  "$file"       "port")" == "1234"
    test "$(ynh_read_var_in_file --file="$file" --key="port")" == "1234"

    test "$(_read_yaml                  "$file"       "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file --file="$file" --key="url")" == "https://yunohost.org"

    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=users,dc=yunohost,dc=org"

    ! _read_yaml                        "$file"       "nonexistent"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! _read_yaml                        "$file"       "enable"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")" == "YNH_NULL"
}


ynhtest_config_write_yaml() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.yml"

    cat << EOF > $file
# Some comment
foo:
enabled: false
# title: old title
title: Lorem Ipsum
theme: colib'ris
email: root@example.com # This is a comment without quotes
port: 1234 # This is a comment without quotes
url: https://yunohost.org
dict:
   ldap_base: ou=users,dc=yunohost,dc=org
EOF

    ynh_write_var_in_file         --file="$file" --key="foo" --value="bar"
    # cat $dummy_dir/dummy.yml   # to debug
    ! test "$(_read_yaml                "$file"       "foo")" == "bar" # writing broke the yaml syntax... "foo:bar" (no space aftr :)
    test "$(ynh_read_var_in_file --file="$file" --key="foo")" == "bar"

    ynh_write_var_in_file        --file="$file" --key="enabled" --value="true"
    test "$(_read_yaml                  "$file"       "enabled")"    == "True"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")"    == "true"

    ynh_write_var_in_file        --file="$file" --key="title" --value="Foo Bar"
    test "$(_read_yaml                  "$file"       "title")"    == "Foo Bar"
    test "$(ynh_read_var_in_file --file="$file" --key="title")"    == "Foo Bar"

    ynh_write_var_in_file        --file="$file" --key="theme" --value="super-awesome-theme"
    test "$(_read_yaml                  "$file"       "theme")"    == "super-awesome-theme"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")"    == "super-awesome-theme"

    ynh_write_var_in_file        --file="$file" --key="email" --value="sam@domain.tld"
    test "$(_read_yaml                  "$file"       "email")"    == "sam@domain.tld"
    test "$(ynh_read_var_in_file --file="$file" --key="email")"    == "sam@domain.tld"

    ynh_write_var_in_file        --file="$file" --key="port" --value="5678"
    test "$(_read_yaml                  "$file"       "port")"    == "5678"
    test "$(ynh_read_var_in_file --file="$file" --key="port")"    == "5678"

    ynh_write_var_in_file        --file="$file" --key="url" --value="https://domain.tld/foobar"
    test "$(_read_yaml                  "$file"       "url")"    == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="url")"    == "https://domain.tld/foobar"

    ynh_write_var_in_file        --file="$file" --key="ldap_base" --value="ou=foobar,dc=domain,dc=tld"
    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=foobar,dc=domain,dc=tld"

    ! ynh_write_var_in_file      --file="$file" --key="nonexistent" --value="foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! ynh_write_var_in_file      --file="$file" --key="enable" --value="foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")"  == "YNH_NULL"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "true"
}

#########################
#    _                  #
#   (_)                 #
#    _ ___  ___  _ __   #
#   | / __|/ _ \| '_ \  #
#   | \__ \ (_) | | | | #
#   | |___/\___/|_| |_| #
#  _/ |                 #
# |__/                  #
#                       #
#########################

_read_json() {
    local file="$1"
    local key="$2"
    python3 -c "import json; print(json.load(open('$file'))['$key'])"
}

ynhtest_config_read_json() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.json"

    cat << EOF > $file
{
     "foo": null,
     "enabled":     false,
     "title": "Lorem Ipsum",
     "theme": "colib'ris",
     "email": "root@example.com",
       "port": 1234,
     "url": "https://yunohost.org",
     "dict": {
         "ldap_base": "ou=users,dc=yunohost,dc=org"
     }
}
EOF


    test "$(_read_json                  "$file"       "foo")" == "None"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")" == "null"

    test "$(_read_json                  "$file"       "enabled")" == "False"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "false"

    test "$(_read_json                  "$file"       "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file --file="$file" --key="title")" == "Lorem Ipsum"

    test "$(_read_json                  "$file"       "theme")" == "colib'ris"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")" == "colib'ris"

    test "$(_read_json                  "$file"       "email")" == "root@example.com"
    test "$(ynh_read_var_in_file --file="$file" --key="email")" == "root@example.com"

    test "$(_read_json                  "$file"       "port")" == "1234"
    test "$(ynh_read_var_in_file --file="$file" --key="port")" == "1234"

    test "$(_read_json                  "$file"       "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file --file="$file" --key="url")" == "https://yunohost.org"

    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=users,dc=yunohost,dc=org"

    ! _read_json                        "$file"       "nonexistent"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! _read_json                        "$file"       "enable"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")" == "YNH_NULL"
}


ynhtest_config_write_json() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.json"

    cat << EOF > $file
{
     "foo": null,
     "enabled":     false,
     "title": "Lorem Ipsum",
     "theme": "colib'ris",
     "email": "root@example.com",
       "port": 1234,
     "url": "https://yunohost.org",
     "dict": {
         "ldap_base": "ou=users,dc=yunohost,dc=org"
     }
}
EOF

    ynh_write_var_in_file        --file="$file" --key="foo" --value="bar"
    cat $file
    test "$(_read_json                  "$file"       "foo")"    == "bar"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")"    == "bar"

    ynh_write_var_in_file        --file="$file" --key="enabled" --value="true"
    cat $file
    test "$(_read_json                  "$file"       "enabled")"    == "true"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")"    == "true"

    ynh_write_var_in_file        --file="$file" --key="title" --value="Foo Bar"
    cat $file
    test "$(_read_json                  "$file"       "title")"    == "Foo Bar"
    test "$(ynh_read_var_in_file --file="$file" --key="title")"    == "Foo Bar"

    ynh_write_var_in_file        --file="$file" --key="theme" --value="super-awesome-theme"
    cat $file
    test "$(_read_json                  "$file"       "theme")"    == "super-awesome-theme"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")"    == "super-awesome-theme"

    ynh_write_var_in_file        --file="$file" --key="email" --value="sam@domain.tld"
    cat $file
    test "$(_read_json                  "$file"       "email")"    == "sam@domain.tld"
    test "$(ynh_read_var_in_file --file="$file" --key="email")"    == "sam@domain.tld"

    ynh_write_var_in_file        --file="$file" --key="port" --value="5678"
    test "$(_read_json                  "$file"       "port")"    == "5678"
    test "$(ynh_read_var_in_file --file="$file" --key="port")"    == "5678"

    ynh_write_var_in_file        --file="$file" --key="url" --value="https://domain.tld/foobar"
    test "$(_read_json                  "$file"       "url")"    == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="url")"    == "https://domain.tld/foobar"

    ynh_write_var_in_file        --file="$file" --key="ldap_base" --value="ou=foobar,dc=domain,dc=tld"
    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=foobar,dc=domain,dc=tld"

    ! ynh_write_var_in_file      --file="$file" --key="nonexistent" --value="foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! ynh_write_var_in_file      --file="$file" --key="enable" --value="foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")"  == "YNH_NULL"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "true"
}

#######################
#        _            #
#       | |           #
#  _ __ | |__  _ __   #
# | '_ \| '_ \| '_ \  #
# | |_) | | | | |_) | #
# | .__/|_| |_| .__/  #
# | |         | |     #
# |_|         |_|     #
#                     #
#######################

_read_php() {
    local file="$1"
    local key="$2"
    php -r "include '$file'; echo var_export(\$$key);" | sed "s/^'//g" | sed "s/'$//g"
}

ynhtest_config_read_php() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.php"

    cat << EOF > $file
<?php
  // Some comment
  \$foo = NULL;
  \$enabled = false;
  // \$title = "old title";
  \$title = "Lorem Ipsum";
   \$theme = "colib'ris";
  \$email = "root@example.com"; // This is a comment without quotes
  \$port = 1234; // This is a second comment without quotes
  \$url = "https://yunohost.org";
  \$dict = [
     'ldap_base' => "ou=users,dc=yunohost,dc=org",
     'ldap_conf' => []
  ];
  \$dict['ldap_conf']['user'] = 'camille';
  const DB_HOST       = 'localhost';
?>
EOF

    test "$(_read_php                   "$file"       "foo")" == "NULL"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")" == "NULL" 

    test "$(_read_php                   "$file"       "enabled")" == "false"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "false" 

    test "$(_read_php                   "$file"       "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file --file="$file" --key="title")" == "Lorem Ipsum"

    test "$(_read_php                   "$file"       "theme")" == "colib\\'ris"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")" == "colib'ris"

    test "$(_read_php                   "$file"       "email")" == "root@example.com"
    test "$(ynh_read_var_in_file --file="$file" --key="email")" == "root@example.com"

    test "$(_read_php                   "$file"       "port")" == "1234"
    test "$(ynh_read_var_in_file --file="$file" --key="port")" == "1234"

    test "$(_read_php                   "$file"       "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file --file="$file" --key="url")" == "https://yunohost.org"

    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")" == "ou=users,dc=yunohost,dc=org"
    
    test "$(ynh_read_var_in_file --file="$file" --key="user")" == "camille"
    
    test "$(ynh_read_var_in_file --file="$file" --key="DB_HOST")" == "localhost"

    ! _read_php                         "$file"       "nonexistent"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! _read_php                         "$file"       "enable"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")" == "YNH_NULL"
}


ynhtest_config_write_php() {
    local dummy_dir="$(mktemp -d -p $VAR_WWW)"
    file="$dummy_dir/dummy.php"

    cat << EOF > $file
<?php
  // Some comment
  \$foo = NULL;
  \$enabled = false;
  // \$title = "old title";
  \$title = "Lorem Ipsum";
   \$theme = "colib'ris";
  \$email = "root@example.com"; // This is a comment without quotes
  \$port = 1234; // This is a comment without quotes
  \$url = "https://yunohost.org";
  \$dict = [
     'ldap_base' => "ou=users,dc=yunohost,dc=org",
  ];
?>
EOF

    ynh_write_var_in_file        --file="$file" --key="foo" --value="bar"
    test "$(_read_php                   "$file"       "foo")"    == "bar"
    test "$(ynh_read_var_in_file --file="$file" --key="foo")"    == "bar"

    ynh_write_var_in_file        --file="$file" --key="enabled" --value="true"
    test "$(_read_php                   "$file"       "enabled")"    == "true"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")"    == "true"

    ynh_write_var_in_file        --file="$file" --key="title" --value="Foo Bar"
    cat $file
    test "$(_read_php                   "$file"       "title")"    == "Foo Bar"
    test "$(ynh_read_var_in_file --file="$file" --key="title")"    == "Foo Bar"

    ynh_write_var_in_file        --file="$file" --key="theme" --value="super-awesome-theme"
    cat $file
    test "$(_read_php                   "$file"       "theme")"    == "super-awesome-theme"
    test "$(ynh_read_var_in_file --file="$file" --key="theme")"    == "super-awesome-theme"

    ynh_write_var_in_file        --file="$file" --key="email" --value="sam@domain.tld"
    cat $file
    test "$(_read_php                   "$file"       "email")"    == "sam@domain.tld"
    test "$(ynh_read_var_in_file --file="$file" --key="email")"    == "sam@domain.tld"

    ynh_write_var_in_file        --file="$file" --key="port" --value="5678"
    test "$(_read_php                   "$file"       "port")"    == "5678"
    test "$(ynh_read_var_in_file --file="$file" --key="port")"    == "5678"

    ynh_write_var_in_file        --file="$file" --key="url" --value="https://domain.tld/foobar"
    test "$(_read_php                   "$file"       "url")"    == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="url")"    == "https://domain.tld/foobar"

    ynh_write_var_in_file        --file="$file" --key="ldap_base" --value="ou=foobar,dc=domain,dc=tld"
    test "$(ynh_read_var_in_file --file="$file" --key="ldap_base")"    == "ou=foobar,dc=domain,dc=tld"

    ! ynh_write_var_in_file      --file="$file" --key="nonexistent" --value="foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="nonexistent")" == "YNH_NULL"

    ! ynh_write_var_in_file      --file="$file" --key="enable" --value="foobar"
    test "$(ynh_read_var_in_file --file="$file" --key="enable")"  == "YNH_NULL"
    test "$(ynh_read_var_in_file --file="$file" --key="enabled")" == "true"
}
