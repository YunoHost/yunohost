#! /usr/bin/env bash

set -Eeuo pipefail

YUNODIR="$(realpath "$(dirname "$0")"/..)"
SHFMT="$YUNODIR"/maintenance/shfmt.sh

help() {
    echo "pre-commit.sh ACTION [LANG]"
    echo "  Run common pre-commit checks to make CI happy"
    echo "  ACTIONS:"
    echo "    - check: provide recommendations"
    echo "    - fix: apply recommendations automatically"
    echo "  LANG: python|bash, by default applies to all languages"
}

check_deps() {
    for dep in "$@"; do
        if ! command -v "$dep" > /dev/null 2>&1; then
            echo "Missing dependency: $dep. Please install it first."
            exit 1
        fi
    done
}

check_bash() {
    check_deps shfmt
    "$SHFMT" -d "$YUNODIR"/helpers/helpers \
        "$YUNODIR"/helpers/helpers.v2.1.d/* \
        "$YUNODIR"/helpers/helpers.v2.d/* \
        "$YUNODIR"/hooks/*
}

check_python() {
    check_deps black
    black --quiet --check "$YUNODIR"/bin \
        "$YUNODIR"/src
}

check() {
    case "$1" in
        "python")
            check_python
            ;;
        "bash")
            check_bash
            ;;
        "all")
            check_bash
            check_python
            ;;
        *)
            echo "Unknown language: $1"
            exit 1
            ;;
    esac
}

fix_bash() {
    check_deps shfmt
    "$SHFMT" -w helpers/helpers
    "$SHFMT" -w helpers/helpers.v2.1.d/*
    "$SHFMT" -w helpers/helpers.v2.d/*
    "$SHFMT" -w hooks/*
}

fix_python() {
    check_deps black
    black --quiet bin
    black --quiet src
}

fix() {
    case "$1" in
        "python")
            fix_python
            ;;
        "bash")
            fix_bash
            ;;
        "all")
            fix_bash
            fix_python
            ;;
        *)
            echo "Unknown language: $1"
            exit 1
            ;;
    esac
}

run() {
    case "${1:-check}" in
        "check")
            check "${2:-all}"
            ;;
        "fix")
            fix "${2:-all}"
            ;;
        "help" | "--help" | "-h")
            help
            exit 0
            ;;
        "")
            check "all"
            ;;
        *)
            help
            echo "Unknown command: $1"
            exit 1
            ;;
    esac
}

run "$@"
echo "OK"
