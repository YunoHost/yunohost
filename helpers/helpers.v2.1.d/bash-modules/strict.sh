#!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

import::import_module array

#>> ## NAME
#>>
#>>> `strict` - unofficial strict mode for bash
#>>
#>> Just import this module, to enabe strict mode: `set -euEo pipefail`.
#>
#> ## NOTE
#>
#> * Option `-e` is not working when command is part of a compound command,
#> or in subshell. See bash manual for details. For example, `-e` may not working
#> in a `for` cycle.

set -euEo pipefail

declare -Ag __cleanup_CODES

cleanup::run() {
    for key in "${!__cleanup_CODES[@]}"; do
        echo "Cleaning up $key..."
        cleanup::pop "$key"
    done
}

cleanup::add() {
    key="$1" ; shift
    value="${1:-}"
    __cleanup_CODES+=([$key]="$value")
}

cleanup::remove() {
    local key="$1"
    unset "__cleanup_CODES[$key]"
}

cleanup::pop() {
    local key="$1"
    if array::contains "$key" __cleanup_CODES; then
        code="${__cleanup_CODES[$key]}"
        cleanup::remove "$key"
        eval "$code"
    fi
}

trap 'log::panic "Uncaught error."' ERR
trap 'cleanup::run' EXIT
