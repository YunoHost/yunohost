#!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

# Import log module
import::import_module log

#>> ## NAME
#>>
#>>> `log_run` - various functions related to logging commands.

run::stderr_to_stdout() {
    "$@" 2>&1
}

run::debug() {
    "$@" | log::debug -
}

run::info() {
    "$@" | log::info -
}

run::warn() {
    "$@" | log::warn -
}

run::error() {
    "$@" | log::error -
}

run::fatal() {
    "$@" | log::fatal -
}

run::quiet() {
    local result returncode
    result=$(run::stderr_to_stdout "$@" || echo "__log_run__returncode=$?")
    returncode=$(echo "$result" | sed -n 's|^__log_run__returncode=\(.*\)$|\1|p')
    if [[ -n "$returncode" ]]; then
        log::error "$@"
        return "$returncode"
    fi
}
