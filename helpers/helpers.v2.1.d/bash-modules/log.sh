#!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> `log` - various functions related to logging.

#>
#> ## VARIABLES

#export PS4='+${BASH_SOURCE}:${LINENO}:${FUNCNAME[0]:+${FUNCNAME[0]}}: '.

#> * `__log__APP` - name of main file without path.
__log__APP="${IMPORT__BIN_FILE##*/}" # Strip everything before last "/"

#> * `__log__DEBUG` - set to yes to enable printing of debug messages and stacktraces.
#> * `__log__STACKTRACE` - set to yes to enable printing of stacktraces.

#> * `__log__TIMESTAMPED` - set to yes to enable timestamped logs
#> * `__log_timestamp_format` - format of timestamp. Default value: "%F %T" (full date and time).
__log_timestamp_format="%F %T"

#>>
#>> ## FUNCTIONS

#>>
#>> * `MESSAGE | log::prefix PREFIX` - display string with PREFIX prefixed to every line
#>>
log::prefix() {
  __log__PREFIX="$1"
  while read -r line; do
    # shellcheck disable=SC2001
    echo "$line" | sed 's|^|'"$__log__PREFIX"'|'
  done
}

#>>
#>> * `MESSAGE | log::_generic_log COLOR LEVEL -` - display message with color, date, app name
#>> * or log::_generic_log COLOR LEVEL MESSAGE`
#>>
log::_generic_log() {
  local color="$1" ; shift
  local level="$1" ; shift
  local log_prefix="" log_date="" color_stop=""
  if [[ -n "$color" ]]; then
    color_stop=$'\033[39m'
  fi
  if [[ "$#" == 1 ]] && [[ "$1" == "-" ]]; then
    while read -r line ; do
      if [ "${__log__TIMESTAMPED:-}" == "yes" ]; then
        # space at the end
        log_date="$(date::print_current_datetime "$__log_timestamp_format") "
      fi
      log_prefix="${log_date}[$__log__APP] ${color}$level${color_stop}: "
      echo "$line" | log::prefix "$log_prefix"
    done
  else
    if [ "${__log__TIMESTAMPED:-}" == "yes" ]; then
      # space at the end
      log_date="$(date::print_current_datetime "$__log_timestamp_format") "
    fi
    log_prefix="${log_date}[$__log__APP] ${color}$level${color_stop}: "
    echo "$@" | log::prefix "$log_prefix"
  fi
}

#>>
#>> * `stacktrace [INDEX]` - display functions and source line numbers starting
#>> from given index in stack trace, when debugging or back tracking is enabled.
log::stacktrace() {
  if [ "${__log__DEBUG:-}" != "yes" ] && [ "${__log__STACKTRACE:-}" != "yes" ]; then
    local BEGIN="${1:-1}" # Display line numbers starting from given index, e.g. to skip "log::stacktrace" and "error" functions.
    local I
    for(( I=BEGIN; I<${#FUNCNAME[@]}; I++ ))
    do
      echo $'\t\t'"at ${FUNCNAME[$I]}(${BASH_SOURCE[$I]}:${BASH_LINENO[$I-1]})" >&2
    done
    echo
  fi
}

#>>
#>> * `log::debug LEVEL MESSAGE...` - print debug-like LEVEL: MESSAGE to STDOUT.
log::debug::custom() {
  local LEVEL="${1:-DEBUG}" ; shift
  if [ -t 1 ]; then
    # STDOUT is tty
    local __log_DEBUG_BEGIN=$'\033[96m'
  fi
  log::_generic_log "${__log_DEBUG_BEGIN:-}" "$LEVEL" "$@"
}

#>>
#>> * `debug MESAGE...` - print debug message.
log::debug() {
  if [ "${__log__DEBUG:-}" == "yes" ]; then
    log::debug::custom DEBUG "$@"
  fi
}

#>>
#>> * `log::info LEVEL MESSAGE...` - print info-like LEVEL: MESSAGE to STDOUT.
log::info::custom() {
  local LEVEL="${1:-INFO}" ; shift
  if [ -t 1 ]; then
    # STDOUT is tty
    local __log_INFO_BEGIN=$'\033[92m'
  fi
  log::_generic_log "${__log_INFO_BEGIN:-}" "$LEVEL" "$@"
}

#>>
#>> * `info MESAGE...` - print info message.
log::info() {
  log::info::custom INFO "$@"
}

#>>
#>> * `log::warn LEVEL MESSAGE...` - print warning-like LEVEL: MESSAGE to STDERR.
log::warn::custom() {
  local LEVEL="${1:-WARN}" ; shift
  if [ -t 2 ]; then
  # STDERR is tty
    local __log_WARN_BEGIN=$'\033[93m'
  fi
  log::_generic_log "${__log_WARN_BEGIN:-}" "$LEVEL" >&2 "$@"
}

#>>
#>> * `warn MESAGE...` - print warning message and stacktrace (if enabled).
log::warn() {
  log::warn::custom WARN "$@"
  log::stacktrace 2
}

#>>
#>> * `log::error LEVEL MESSAGE...` - print error-like LEVEL: MESSAGE to STDERR.
log::error::custom() {
  local LEVEL="$1" ; shift
  if [ -t 2 ]; then
    # STDERR is tty
    local __log_ERROR_BEGIN=$'\033[91m'
  fi
  log::_generic_log "${__log_ERROR_BEGIN:-}" "$LEVEL" >&2 "$@"
}

#>>
#>> * `error MESAGE...` - print error message and stacktrace (if enabled).
log::error() {
  log::error::custom ERROR "$@"
  log::stacktrace 2
}

#>>
#>> * `log::fatal LEVEL MESSAGE...` - print a fatal-like LEVEL: MESSAGE to STDERR.
log::fatal::custom() {
  local LEVEL="$1" ; shift
  if [ -t 2 ]; then
    # STDERR is tty
    local __log_FATAL_BEGIN=$'\033[95m'
  fi
  log::_generic_log "${__log_FATAL_BEGIN:-}" "$LEVEL" >&2 "$@"
}

#>>
#>> * `log::fatal LEVEL MESSAGE...` - print a fatal-like LEVEL: MESSAGE to STDERR.
log::fatal() {
  log::fatal::custom FATAL "$@"
  log::stacktrace 2
}

#>>
#>> * `panic MESAGE...` - print error message and stacktrace, then exit with error code 1.
log::panic() {
  log::fatal::custom "PANIC" "$@"
  log::enable_stacktrace
  log::stacktrace 2
  exit 1
}

#>>
#>> * `unimplemented MESSAGE...` - print error message and stacktrace, then exit with error code 42.
log::unimplemented() {
  log::fatal::custom "UNIMPLEMENTED" "$@"
  log::enable_stacktrace
  log::stacktrace 2
  exit 42
}

#>>
#>> * `todo MESAGE...` - print todo message and stacktrace.
log::todo() {
  log::warn::custom "TODO" "$@"
  local __log__STACKTRACE="yes"
  log::stacktrace 2
}

#>>
#>> * `dbg VARIABLE...` - print name of variable and it content to stderr
log::dbg() {
  log::debug "$(declare -p "$@" | sed 's|declare -. ||')"
}

#>>
#>> * `log::enable_debug_mode` - enable debug messages and stack traces.
log::enable_debug_mode() {
  __log__DEBUG="yes"
}

#>>
#>> * `log::disable_debug_mode` - disable debug messages and stack traces.
log::disable_debug_mode() {
  __log__DEBUG="no"
}

#>>
#>> * `log::enable_stacktrace` - enable stack traces.
log::enable_stacktrace() {
  __log__STACKTRACE="yes"
}

#>>
#>> * `log::disable_stacktrace` - disable stack traces.
log::disable_stacktrace() {
  __log__STACKTRACE="no"
}

#>>
#>> * `log::enable_timestamps` - enable timestamps.
log::enable_timestamps() {
  __log__TIMESTAMPED="yes"
}

#>>
#>> * `log::disable_timestamps` - disable timestamps.
log::disable_timestamps() {
  __log__TIMESTAMPED="no"
}

#>>
#>> * `log::set_timestamp_format FORMAT` - Set format for date. Default value is "%F %T".
log::set_timestamp_format() {
  __log_timestamp_format="$1"
}

#>>
#>> ## NOTES
#>>
#>> - If STDOUT is connected to tty, then
#>>   * info and info-like messages will be printed with message level higlighted in green,
#>>   * warn and warn-like messages will be printed with message level higlighted in yellow,
#>>   * error and error-like messages will be printed with message level higlighted in red.
