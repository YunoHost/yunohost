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

source /usr/share/yunohost/helpers
for TEST_SUITE in $(ls helpers.tests/*)
do
    source $TEST_SUITE
done

TESTS=$(declare -F | grep ' ynhtest_' | awk '{print $3}')

for TEST in $TESTS
do
    log_test $TEST
    cd $(mktemp -d)
    (app=ynhtest
     YNH_APP_ID=$app
     mkdir scripts
     cd scripts
     set -eu
     $TEST
    ) > ./test.log 2>&1 \
    && log_passed \
    || { echo -e "\n----------"; cat ./test.log; echo -e "----------"; log_failed;  }
done
