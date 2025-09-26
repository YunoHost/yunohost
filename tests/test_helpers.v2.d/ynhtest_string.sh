#!/usr/bin/env bash

ynhtest_string_random() {
    declare -A results
    for _ in $(seq 1 1000); do
        local result="$(ynh_string_random --length=64 --filter='a-f0-9')"
        test -n "${result:-}"
        echo "result=$result"
        test -z "${results["$result"]:-}"
        results["$result"]="1"
    done
}
