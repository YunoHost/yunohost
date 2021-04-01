#!/bin/bash

readonly NORMAL=$(printf '\033[0m')
readonly BOLD=$(printf '\033[1m')
readonly RED=$(printf '\033[31m')
readonly GREEN=$(printf '\033[32m')
readonly ORANGE=$(printf '\033[33m')

function log_test()
{
    echo -n "${BOLD}$1${NORMAL} ... "
}

function log_passed()
{
    echo "${BOLD}${GREEN}✔ Passed${NORMAL}"
}

function log_failed()
{
    echo "${BOLD}${RED}✘ Failed${NORMAL}"
}

function cleanup()
{
    [ -n "$HTTPSERVER" ] && kill "$HTTPSERVER"
    [ -d "$HTTPSERVER_DIR" ] && rm -rf "$HTTPSERVER_DIR"
    [ -d "$VAR_WWW" ] && rm -rf "$VAR_WWW"
}
trap cleanup EXIT SIGINT

# =========================================================

# Dummy http server, to serve archives for ynh_setup_source
HTTPSERVER_DIR=$(mktemp -d)
HTTPSERVER_PORT=1312
pushd "$HTTPSERVER_DIR" >/dev/null
python -m SimpleHTTPServer $HTTPSERVER_PORT &>/dev/null &
HTTPSERVER="$!"
popd >/dev/null

VAR_WWW=$(mktemp -d)/var/www
mkdir -p $VAR_WWW
# =========================================================

source /usr/share/yunohost/helpers
for TEST_SUITE in $(ls test_helpers.d/*)
do
    source $TEST_SUITE
done

# Hack to list all known function, keep only those starting by ynhtest_
TESTS=$(declare -F | grep ' ynhtest_' | awk '{print $3}')

global_result=0

for TEST in $TESTS
do
    log_test $TEST
    cd $(mktemp -d)
    (app=ynhtest
     YNH_APP_ID=$app
     mkdir conf
     mkdir scripts
     cd scripts
     set -eux
     $TEST
    ) > ./test.log 2>&1

    if [[ $? == 0 ]]
    then
        set +x; log_passed;
    else
        set +x; echo -e "\n----------"; cat ./test.log; echo -e "----------"; log_failed; global_result=1;
    fi
done

exit $global_result
