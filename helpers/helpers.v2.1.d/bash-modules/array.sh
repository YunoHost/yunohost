#!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> list - various functions to manipulate lists (passed as argument list).
#>>> array - various functions to manipulate arrays (passed as array names).

#>>
#>> ## FUNCTIONS

list::contain() {
    local searching="$1"; shift
    if [[ -z "$searching" ]] || [[ "$#" = 0 ]]; then
        return 1
    fi
    for element in "$@"; do
        if [[ "$searching" == "$element" ]]; then
            return 0
        fi
    done
    return 1
}

array::contains() {
    local searching="$1"; shift
    declare -n __array_name="$1" ; shift
    list::contain "$searching" "${__array_name[@]}"
}


list::join() {
    local sep="$1"; shift
    while (( "$#" > 1 )); do
        printf '%s%s' "$1" "$sep"
        shift
    done
    if [[ "$#" = 1 ]]; then
        printf '%s' "$1"
    fi
}

array::join() {
    local sep="$1"; shift
    declare -n __array_name="$1"; shift
    list::join "$sep" "${__array_name[@]}"
}


list::min() {
    local __min
    if [[ "$#" = 0 ]]; then
        return 1
    fi
    for value in "$@"; do
        __min=$(echo "if($value<$__min) $value else $__min" | bc)
    done
    echo "$__min"
}

array::min() {
    local sep="$1"; shift
    declare -n __array_name="$1"; shift
    list::min "$sep" "${__array_name[@]}"
}


list::max() {
    local __max
    if [[ "$#" = 0 ]]; then
        return 1
    fi
    for value in "$@"; do
        __max=$(echo "if($value<$__max) $value else $__max" | bc)
    done
    echo "$__max"
}

array::max() {
    local sep="$1"; shift
    declare -n __array_name="$1"; shift
    list::max "$sep" "${__array_name[@]}"
}


array::sort() {
    declare -n __array_name="$1" ; shift
    local __sort_args=("$@")

    printf '%s\n' "${__array_name[@]}" | sort "${__sort_args[@]}"
}

list::sort() {
    local __array=("$@")
    array::sort __array
}


list::uniq() {
    printf "%s\n" "$@" | sort -u
}

array::uniq() {
    local sep="$1"; shift
    declare -n __array_name="$1"; shift
    list::uniq "$sep" "${__array_name[@]}"
}

array::empty() {
    declare -n __array_name="$1"; shift
    (( ${#__array_name[@]} == 0 ))
}
