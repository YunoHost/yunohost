_make_dummy_src() {
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
    echo "SOURCE_URL=http://127.0.0.1:$HTTPSERVER_PORT/dummy.tar.gz"
    echo "SOURCE_SUM=$(sha256sum $HTTPSERVER_DIR/dummy.tar.gz | awk '{print $1}')"
}

ynhtest_setup_source_nominal() {
    final_path="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_src > ../conf/dummy.src
    
    ynh_setup_source --dest_dir="$final_path" --source_id="dummy"

    test -e "$final_path"
    test -e "$final_path/index.html"
}

ynhtest_setup_source_nominal_upgrade() {
    final_path="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_src > ../conf/dummy.src

    ynh_setup_source --dest_dir="$final_path" --source_id="dummy"

    test "$(cat $final_path/index.html)" == "Lorem Ipsum"
    
    # Except index.html to get overwritten during next ynh_setup_source
    echo "IEditedYou!" > $final_path/index.html
    test "$(cat $final_path/index.html)" == "IEditedYou!"

    ynh_setup_source --dest_dir="$final_path" --source_id="dummy"

    test "$(cat $final_path/index.html)" == "Lorem Ipsum"
}


ynhtest_setup_source_with_keep() {
    final_path="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_src > ../conf/dummy.src

    echo "IEditedYou!" > $final_path/index.html
    echo "IEditedYou!" > $final_path/test.txt

    ynh_setup_source --dest_dir="$final_path" --source_id="dummy" --keep="index.html test.txt"

    test -e "$final_path"
    test -e "$final_path/index.html"
    test -e "$final_path/test.txt"
    test "$(cat $final_path/index.html)" == "IEditedYou!"
    test "$(cat $final_path/test.txt)" == "IEditedYou!"
}

ynhtest_setup_source_with_patch() {
    final_path="$(mktemp -d -p $VAR_WWW)"
    _make_dummy_src > ../conf/dummy.src

    mkdir -p ../sources/patches
    cat > ../sources/patches/dummy-index.html.patch << EOF
--- a/index.html
+++ b/index.html
@@ -1 +1,1 @@
-Lorem Ipsum
+Lorem Ipsum dolor sit amet
EOF

    ynh_setup_source --dest_dir="$final_path" --source_id="dummy"

    test "$(cat $final_path/index.html)" == "Lorem Ipsum dolor sit amet"
}
