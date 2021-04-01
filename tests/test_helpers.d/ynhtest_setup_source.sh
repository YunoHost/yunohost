EXAMPLE_SRC="
SOURCE_URL=https://github.com/Hextris/hextris/archive/8872ec47d694628e2fe668ebaa90b13d5626d95f.tar.gz
SOURCE_SUM=67f3fbd54c405717a25fb1e6f71d2b46e94c7ac6971861dd99ae5e58f6609892
"

ynhtest_setup_source_nominal() {
    mkdir -p /tmp/var/www/
    final_path="$(mktemp -d -p /tmp/var/www)"
    mkdir ../conf
    echo "$EXAMPLE_SRC" > ../conf/test.src 
    
    ynh_setup_source --dest_dir="$final_path" --source_id="test"

    test -e "$final_path"
    test -e "$final_path/index.html"
}


ynhtest_setup_source_nominal_upgrade() {
    mkdir -p /tmp/var/www/
    final_path="$(mktemp -d -p /tmp/var/www)"
    mkdir ../conf
    echo "$EXAMPLE_SRC" > ../conf/test.src 
    
    ynh_setup_source --dest_dir="$final_path" --source_id="test"

    test -e "$final_path"
    test -e "$final_path/index.html"
    
    # Except index.html to get overwritten during next ynh_setup_source
    echo "HELLOWORLD" > $final_path/index.html
    test "$(cat $final_path/index.html)" == "HELLOWORLD"

    ynh_setup_source --dest_dir="$final_path" --source_id="test"

    test "$(cat $final_path/index.html)" != "HELLOWORLD"
}


ynhtest_setup_source_with_keep() {
    mkdir -p /tmp/var/www/
    final_path="$(mktemp -d -p /tmp/var/www)"
    mkdir ../conf
    echo "$EXAMPLE_SRC" > ../conf/test.src 

    echo "HELLOWORLD" > $final_path/index.html
    echo "HELLOWORLD" > $final_path/test.conf.txt

    ynh_setup_source --dest_dir="$final_path" --source_id="test" --keep="index.html test.conf.txt"

    test -e "$final_path"
    test -e "$final_path/index.html"
    test -e "$final_path/test.conf.txt"
    test "$(cat $final_path/index.html)" == "HELLOWORLD"
    test "$(cat $final_path/test.conf.txt)" == "HELLOWORLD"
}

