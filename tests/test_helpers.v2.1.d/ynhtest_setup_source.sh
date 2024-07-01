_make_dummy_manifest() {
    if [ ! -e $HTTPSERVER_DIR/dummy.tar.gz ]
    then
        pushd "$HTTPSERVER_DIR"
            mkdir dummy
            pushd dummy
            echo "Lorem Ipsum" > index.html
            echo '{"foo": "bar"}' > conf.json
            mkdir assets
            echo '.some.css { }' > assets/main.css
            echo 'var some="js";' > assets/main.js
            popd
            tar -czf dummy.tar.gz dummy
        popd
    fi

    cat << EOF
packaging_format = 2
id = "$app"
version = "0.1~ynh2"

[resources]
    [resources.sources.dummy]
    url = "http://127.0.0.1:$HTTPSERVER_PORT/dummy.tar.gz"
    sha256 = "$(sha256sum $HTTPSERVER_DIR/dummy.tar.gz | awk '{print $1}')"

    [resources.install_dir]
    group = "www-data:r-x"
EOF

}

ynhtest_setup_source_nominal() {
    install_dir="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_manifest > ../manifest.toml
    
    ynh_setup_source --dest_dir="$install_dir" --source_id="dummy"

    test -e "$install_dir"
    test -e "$install_dir/index.html"

    ls -ld "$install_dir"            | grep -q "drwxr-x--- . $app www-data"
    ls -l  "$install_dir/index.html" | grep -q "\-rw-r----- . $app www-data"
}

ynhtest_setup_source_no_group_in_manifest() {
    install_dir="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_manifest > ../manifest.toml
    sed '/www-data/d' -i ../manifest.toml
    cat ../manifest.toml # debug
    
    ynh_setup_source --dest_dir="$install_dir" --source_id="dummy"

    test -e "$install_dir"
    test -e "$install_dir/index.html"

    ls -ld "$install_dir"            | grep -q "drwxr-x--- . $app $app"
    ls -l  "$install_dir/index.html" | grep -q "\-rw-r----- . $app $app"
}


ynhtest_setup_source_nominal_upgrade() {
    install_dir="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_manifest > ../manifest.toml

    ynh_setup_source --dest_dir="$install_dir" --source_id="dummy"

    test "$(cat $install_dir/index.html)" == "Lorem Ipsum"
    
    # Except index.html to get overwritten during next ynh_setup_source
    echo "IEditedYou!" > $install_dir/index.html
    test "$(cat $install_dir/index.html)" == "IEditedYou!"

    ynh_setup_source --dest_dir="$install_dir" --source_id="dummy"

    test "$(cat $install_dir/index.html)" == "Lorem Ipsum"
}


ynhtest_setup_source_with_keep() {
    install_dir="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_manifest > ../manifest.toml

    echo "IEditedYou!" > $install_dir/index.html
    echo "IEditedYou!" > $install_dir/test.txt

    ynh_setup_source --dest_dir="$install_dir" --source_id="dummy" --keep="index.html test.txt"

    test -e "$install_dir"
    test -e "$install_dir/index.html"
    test -e "$install_dir/test.txt"
    test "$(cat $install_dir/index.html)" == "IEditedYou!"
    test "$(cat $install_dir/test.txt)" == "IEditedYou!"
}

ynhtest_setup_source_with_patch() {
    install_dir="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_manifest > ../manifest.toml

    mkdir -p ../patches/dummy/
    cat > ../patches/dummy/index.html.patch << EOF
--- a/index.html
+++ b/index.html
@@ -1 +1,1 @@
-Lorem Ipsum
+Lorem Ipsum dolor sit amet
EOF

    ynh_setup_source --dest_dir="$install_dir" --source_id="dummy"

    test "$(cat $install_dir/index.html)" == "Lorem Ipsum dolor sit amet"
}
