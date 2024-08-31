#!/usr/bin/env bash
set -Eeuo pipefail

shfmt_args=(
    --indent 4
    --keep-padding      # keep column alignment paddings
    --space-redirects   # redirect operators will be followed by a space
    --binary-next-line  # binary ops like && and | may start a line
    --case-indent       # switch cases will be indented
)

shfmt "${shfmt_args[@]}" "$@" \
    helpers/helpers \
    helpers/helpers.v2.1.d/* \
    helpers/helpers.v2.d/* \
    hooks/*
