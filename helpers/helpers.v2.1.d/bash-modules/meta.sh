##!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> `meta` - functions for working with bash functions.

#>>
#>> ## FUNCTIONS

#>>
#>> * `meta::copy_function FUNCTION_NAME NEW_FUNCTION_PREFIX` - copy function to new function with prefix in name.
#>    Create copy of function with new prefix.
#>    Old function can be redefined or `unset -f`.
meta::copy_function() {
  local FUNCTION_NAME="$1"
  local PREFIX="$2"

  eval "$PREFIX$(declare -fp $FUNCTION_NAME)"
}

#>>
#>> * `meta::wrap BEFORE AFTER FUNCTION_NAME[...]` - wrap function.
#>    Create wrapper for a function(s). Execute given commands before and after
#>    each function. Original function is available as meta::orig_FUNCTION_NAME.
meta::wrap() {
  local BEFORE="$1"
  local AFTER="$2"
  shift 2

  local FUNCTION_NAME
  for FUNCTION_NAME in "$@"
  do
    # Rename original function
    meta::copy_function "$FUNCTION_NAME" "meta::orig_" || return 1

    # Redefine function
    eval "
function $FUNCTION_NAME() {
  $BEFORE

  local __meta__EXIT_CODE=0
  meta::orig_$FUNCTION_NAME \"\$@\" || __meta__EXIT_CODE=\$?

  $AFTER

  return \$__meta__EXIT_CODE
}
"
  done
}


#>>
#>> * `meta::functions_with_prefix PREFIX` - print list of functions with given prefix.
meta::functions_with_prefix() {
  compgen -A function "$1"
}

#>>
#>> * `meta::is_function FUNC_NAME` Checks is given name corresponds to a function.
meta::is_function() {
  declare -F "$1" >/dev/null
}

#>>
#>> * `meta::dispatch PREFIX COMMAND [ARGUMENTS...]` - execute function `PREFIX__COMMAND [ARGUMENTS]`
#>
#>    For example, it can be used to execute functions (commands) by name, e.g.
#> `main() { meta::dispatch command__ "$@" ; }`, when called as `man hw world` will execute
#> `command_hw "$world"`. When command handler is not found, dispatcher will try
#> to call `PREFIX__DEFAULT` function instead, or return error code when defaulf handler is not found.
meta::dispatch() {
  local prefix="${1:?Prefix is required.}"
  local command="${2:?Command is required.}"
  shift 2

  local fn="${prefix}${command}"

  # Is handler function exists?
  meta::is_function "$fn" || {
    # Is default handler function exists?
    meta::is_function "${prefix}__DEFAULT" || { echo "ERROR: Function \"$fn\" is not found." >&2; return 1; }
    fn="${prefix}__DEFAULT"
  }

  "$fn" "${@:+$@}" || return $?
}
