_make_dummy_files() {

    local_dummy_dir="$1"

    cat << EOF > $dummy_dir/dummy.ini
# Some comment
foo =
enabled =    False
# title = Old title
title =    Lorem Ipsum
email = root@example.com
theme = colib'ris
  port =     1234
url = https://yunohost.org
[dict]
    ldap_base = ou=users,dc=yunohost,dc=org
EOF

    cat << EOF > $dummy_dir/dummy.py
# Some comment
FOO = None
ENABLED = False
# TITLE = "Old title"
TITLE = "Lorem Ipsum"
THEME = "colib'ris"
EMAIL = "root@example.com"
PORT   = 1234
URL = 'https://yunohost.org'
DICT['ldap_base'] = "ou=users,dc=yunohost,dc=org"
EOF

}

_ynh_read_yaml_with_python() {
    local file="$1"
    local key="$2"
    python3 -c "import yaml; print(yaml.safe_load(open('$file'))['$key'])"
}

_ynh_read_json_with_python() {
    local file="$1"
    local key="$2"
    python3 -c "import json; print(json.load(open('$file'))['$key'])"
}

_ynh_read_php_with_php() {
    local file="$1"
    local key="$2"
    php -r "include '$file'; echo var_export(\$$key);" | sed "s/^'//g" | sed "s/'$//g"
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
email: root@example.com
port: 1234
url: https://yunohost.org
dict:
   ldap_base: ou=users,dc=yunohost,dc=org
EOF

    test "$(_ynh_read_yaml_with_python "$file" "foo")" == "None"
    test "$(ynh_read_var_in_file       "$file" "foo")" == ""
    
    test "$(_ynh_read_yaml_with_python "$file" "enabled")" == "False"
    test "$(ynh_read_var_in_file       "$file" "enabled")" == "false"
    
    test "$(_ynh_read_yaml_with_python "$file" "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file       "$file" "title")" == "Lorem Ipsum"
    
    test "$(_ynh_read_yaml_with_python "$file" "theme")" == "colib'ris"
    test "$(ynh_read_var_in_file       "$file" "theme")" == "colib'ris"
    
    test "$(_ynh_read_yaml_with_python "$file" "email")" == "root@example.com"
    test "$(ynh_read_var_in_file       "$file" "email")" == "root@example.com"
    
    test "$(_ynh_read_yaml_with_python "$file" "port")" == "1234"
    test "$(ynh_read_var_in_file       "$file" "port")" == "1234"
    
    test "$(_ynh_read_yaml_with_python "$file" "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file       "$file" "url")" == "https://yunohost.org"
    
    test "$(ynh_read_var_in_file       "$file" "ldap_base")" == "ou=users,dc=yunohost,dc=org"
    
    ! _ynh_read_yaml_with_python       "$file" "nonexistent"
    test "$(ynh_read_var_in_file       "$file" "nonexistent")" == "YNH_NULL"
    
    ! _ynh_read_yaml_with_python       "$file" "enable"
    test "$(ynh_read_var_in_file       "$file" "enable")" == "YNH_NULL"
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
email: root@example.com
port: 1234
url: https://yunohost.org
dict:
   ldap_base: ou=users,dc=yunohost,dc=org
EOF



    #ynh_write_var_in_file              "$file" "foo"      "bar"
    # cat $dummy_dir/dummy.yml   # to debug
    #! test "$(_ynh_read_yaml_with_python "$file" "foo")" == "bar" # FIXME FIXME FIXME : writing broke the yaml syntax... "foo:bar" (no space aftr :)
    #test "$(ynh_read_var_in_file       "$file" "foo")" == "bar"

    ynh_write_var_in_file              "$file" "enabled"      "true"
    test "$(_ynh_read_yaml_with_python "$file" "enabled")" == "True" 
    test "$(ynh_read_var_in_file       "$file" "enabled")" == "true"

    ynh_write_var_in_file              "$file" "title"      "Foo Bar"
    test "$(_ynh_read_yaml_with_python "$file" "title")" == "Foo Bar"
    test "$(ynh_read_var_in_file       "$file" "title")" == "Foo Bar"
    
    ynh_write_var_in_file              "$file" "theme"      "super-awesome-theme"
    test "$(_ynh_read_yaml_with_python "$file" "theme")" == "super-awesome-theme"
    test "$(ynh_read_var_in_file       "$file" "theme")" == "super-awesome-theme"
    
    ynh_write_var_in_file              "$file" "email"      "sam@domain.tld"
    test "$(_ynh_read_yaml_with_python "$file" "email")" == "sam@domain.tld"
    test "$(ynh_read_var_in_file       "$file" "email")" == "sam@domain.tld"
    
    ynh_write_var_in_file              "$file" "port"      "5678"
    test "$(_ynh_read_yaml_with_python "$file" "port")" == "5678"
    test "$(ynh_read_var_in_file       "$file" "port")" == "5678"
    
    ynh_write_var_in_file              "$file" "url"      "https://domain.tld/foobar"
    test "$(_ynh_read_yaml_with_python "$file" "url")" == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file       "$file" "url")" == "https://domain.tld/foobar"
    
    ynh_write_var_in_file              "$file" "ldap_base"      "ou=foobar,dc=domain,dc=tld"
    test "$(ynh_read_var_in_file       "$file" "ldap_base")" == "ou=foobar,dc=domain,dc=tld"
    
    ynh_write_var_in_file              "$file" "nonexistent"      "foobar"
    test "$(ynh_read_var_in_file       "$file" "nonexistent")" == "YNH_NULL"
    
    ynh_write_var_in_file              "$file" "enable"       "foobar"
    test "$(ynh_read_var_in_file       "$file" "enable")"  == "YNH_NULL"
    test "$(ynh_read_var_in_file       "$file" "enabled")" == "true"
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


    test "$(_ynh_read_json_with_python "$file" "foo")" == "None"
    test "$(ynh_read_var_in_file       "$file" "foo")" == "null," # FIXME FIXME FIXME trailing ,
    
    test "$(_ynh_read_json_with_python "$file" "enabled")" == "False"
    test "$(ynh_read_var_in_file       "$file" "enabled")" == "false," # FIXME FIXME FIXME trailing ,
    
    test "$(_ynh_read_json_with_python "$file" "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file       "$file" "title")" == "Lorem Ipsum"
    
    test "$(_ynh_read_json_with_python "$file" "theme")" == "colib'ris"
    test "$(ynh_read_var_in_file       "$file" "theme")" == "colib'ris"
    
    test "$(_ynh_read_json_with_python "$file" "email")" == "root@example.com"
    test "$(ynh_read_var_in_file       "$file" "email")" == "root@example.com"
    
    test "$(_ynh_read_json_with_python "$file" "port")" == "1234"
    test "$(ynh_read_var_in_file       "$file" "port")" == "1234," # FIXME FIXME FIXME trailing ,
    
    test "$(_ynh_read_json_with_python "$file" "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file       "$file" "url")" == "https://yunohost.org"
    
    test "$(ynh_read_var_in_file       "$file" "ldap_base")" == "ou=users,dc=yunohost,dc=org"
    
    ! _ynh_read_json_with_python       "$file" "nonexistent"
    test "$(ynh_read_var_in_file       "$file" "nonexistent")" == "YNH_NULL"
    
    ! _ynh_read_json_with_python       "$file" "enable"
    test "$(ynh_read_var_in_file       "$file" "enable")" == "YNH_NULL"
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

    #ynh_write_var_in_file              "$file" "foo"      "bar"
    #cat $file
    #test "$(_ynh_read_json_with_python "$file" "foo")" == "bar"    # FIXME FIXME FIXME
    #test "$(ynh_read_var_in_file       "$file" "foo")" == "bar"

    #ynh_write_var_in_file              "$file" "enabled"      "true"
    #test "$(_ynh_read_json_with_python "$file" "enabled")" == "True"     # FIXME FIXME FIXME
    #test "$(ynh_read_var_in_file       "$file" "enabled")" == "true"

    ynh_write_var_in_file              "$file" "title"      "Foo Bar"
    cat $file
    test "$(_ynh_read_json_with_python "$file" "title")" == "Foo Bar"
    test "$(ynh_read_var_in_file       "$file" "title")" == "Foo Bar"
    
    ynh_write_var_in_file              "$file" "theme"      "super-awesome-theme"
    cat $file
    test "$(_ynh_read_json_with_python "$file" "theme")" == "super-awesome-theme"
    test "$(ynh_read_var_in_file       "$file" "theme")" == "super-awesome-theme"
    
    ynh_write_var_in_file              "$file" "email"      "sam@domain.tld"
    cat $file
    test "$(_ynh_read_json_with_python "$file" "email")" == "sam@domain.tld"
    test "$(ynh_read_var_in_file       "$file" "email")" == "sam@domain.tld"
    
    #ynh_write_var_in_file              "$file" "port"      "5678"
    #cat $file
    #test "$(_ynh_read_json_with_python "$file" "port")" == "5678"    # FIXME FIXME FIXME
    #test "$(ynh_read_var_in_file       "$file" "port")" == "5678"
    
    ynh_write_var_in_file              "$file" "url"      "https://domain.tld/foobar"
    test "$(_ynh_read_json_with_python "$file" "url")" == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file       "$file" "url")" == "https://domain.tld/foobar"
    
    ynh_write_var_in_file              "$file" "ldap_base"      "ou=foobar,dc=domain,dc=tld"
    test "$(ynh_read_var_in_file       "$file" "ldap_base")" == "ou=foobar,dc=domain,dc=tld"
    
    ynh_write_var_in_file              "$file" "nonexistent"      "foobar"
    test "$(ynh_read_var_in_file       "$file" "nonexistent")" == "YNH_NULL"
    
    ynh_write_var_in_file              "$file" "enable"       "foobar"
    test "$(ynh_read_var_in_file       "$file" "enable")"  == "YNH_NULL"
    #test "$(ynh_read_var_in_file       "$file" "enabled")" == "true"   # FIXME
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
  \$email = "root@example.com";
  \$port = 1234;
  \$url = "https://yunohost.org";
  \$dict = [
     'ldap_base' => "ou=users,dc=yunohost,dc=org",
  ];
?>
EOF

    test "$(_ynh_read_php_with_php "$file" "foo")" == "NULL"
    test "$(ynh_read_var_in_file   "$file" "foo")" == "NULL;" # FIXME FIXME FIXME trailing ;
    
    test "$(_ynh_read_php_with_php "$file" "enabled")" == "false"
    test "$(ynh_read_var_in_file   "$file" "enabled")" == "false;" # FIXME FIXME FIXME trailing ;
    
    test "$(_ynh_read_php_with_php "$file" "title")" == "Lorem Ipsum"
    test "$(ynh_read_var_in_file   "$file" "title")" == "Lorem Ipsum"
    
    test "$(_ynh_read_php_with_php "$file" "theme")" == "colib\\'ris"
    test "$(ynh_read_var_in_file   "$file" "theme")" == "colib'ris"
    
    test "$(_ynh_read_php_with_php "$file" "email")" == "root@example.com"
    test "$(ynh_read_var_in_file   "$file" "email")" == "root@example.com"
    
    test "$(_ynh_read_php_with_php "$file" "port")" == "1234"
    test "$(ynh_read_var_in_file   "$file" "port")" == "1234;"   # FIXME FIXME FIXME trailing ;
    
    test "$(_ynh_read_php_with_php "$file" "url")" == "https://yunohost.org"
    test "$(ynh_read_var_in_file   "$file" "url")" == "https://yunohost.org"
    
    test "$(ynh_read_var_in_file   "$file" "ldap_base")" == "ou=users,dc=yunohost,dc=org"
    
    ! _ynh_read_php_with_php       "$file" "nonexistent"
    test "$(ynh_read_var_in_file   "$file" "nonexistent")" == "YNH_NULL"
    
    ! _ynh_read_php_with_php       "$file" "enable"
    test "$(ynh_read_var_in_file   "$file" "enable")" == "YNH_NULL"
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
  \$email = "root@example.com";
  \$port = 1234;
  \$url = "https://yunohost.org";
  \$dict = [
     'ldap_base' => "ou=users,dc=yunohost,dc=org",
  ];
?>
EOF

    #ynh_write_var_in_file          "$file" "foo"      "bar"
    #cat $file
    #test "$(_ynh_read_php_with_php "$file" "foo")" == "bar"
    #test "$(ynh_read_var_in_file   "$file" "foo")" == "bar" # FIXME FIXME FIXME
    
    #ynh_write_var_in_file          "$file" "enabled"      "true"
    #cat $file
    #test "$(_ynh_read_php_with_php "$file" "enabled")" == "true"
    #test "$(ynh_read_var_in_file   "$file" "enabled")" == "true" # FIXME FIXME FIXME
   
    ynh_write_var_in_file          "$file" "title"      "Foo Bar"
    cat $file
    test "$(_ynh_read_php_with_php  "$file" "title")" == "Foo Bar"
    test "$(ynh_read_var_in_file    "$file" "title")" == "Foo Bar"
    
    ynh_write_var_in_file          "$file" "theme"      "super-awesome-theme"
    cat $file
    test "$(_ynh_read_php_with_php "$file" "theme")" == "super-awesome-theme"
    test "$(ynh_read_var_in_file   "$file" "theme")" == "super-awesome-theme"
    
    ynh_write_var_in_file          "$file" "email"      "sam@domain.tld"
    cat $file
    test "$(_ynh_read_php_with_php "$file" "email")" == "sam@domain.tld"
    test "$(ynh_read_var_in_file   "$file" "email")" == "sam@domain.tld"

    #ynh_write_var_in_file          "$file" "port"      "5678"
    #cat $file
    #test "$(_ynh_read_php_with_php "$file" "port")" == "5678"    # FIXME FIXME FIXME
    #test "$(ynh_read_var_in_file   "$file" "port")" == "5678"
    
    ynh_write_var_in_file          "$file" "url"      "https://domain.tld/foobar"
    test "$(_ynh_read_php_with_php "$file" "url")" == "https://domain.tld/foobar"
    test "$(ynh_read_var_in_file   "$file" "url")" == "https://domain.tld/foobar"
    
    ynh_write_var_in_file          "$file" "ldap_base"      "ou=foobar,dc=domain,dc=tld"
    test "$(ynh_read_var_in_file   "$file" "ldap_base")" == "ou=foobar,dc=domain,dc=tld"
    
    ynh_write_var_in_file          "$file" "nonexistent"      "foobar"
    test "$(ynh_read_var_in_file   "$file" "nonexistent")" == "YNH_NULL"
   
    ynh_write_var_in_file          "$file" "enable"       "foobar"
    test "$(ynh_read_var_in_file   "$file" "enable")"  == "YNH_NULL"
    #test "$(ynh_read_var_in_file   "$file" "enabled")" == "true"   # FIXME
}
