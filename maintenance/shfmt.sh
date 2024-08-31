#!/usr/bin/env bash

shfmt_args=(
    -i=4
    -kp      # keep column alignment paddings
    -sr   # redirect operators will be followed by a space
    -bn  # binary ops like && and | may start a line
    -ci       # switch cases will be indented
)

shfmt "${shfmt_args[@]}" "$@"
