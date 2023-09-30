##!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> `unit` - functions for unit testing.

import::import_module log arguments

#>>
#>> ## FUNCTIONS

#>>
#>> * `unit::assert_yes VALUE [MESSAGE]`            - Show error message, when `VALUE` is not equal to `"yes"`.
unit::assert_yes() {
  local VALUE="${1:-}"
  local MESSAGE="${2:-Value is not \"yes\".}"

  [ "${VALUE:-}" == "yes" ] || {
    log::error::custom "ASSERT FAILED" "$MESSAGE"
    exit 1
  }
}

#>>
#>> * `unit::assert_no VALUE [MESSAGE]`             - Show error message, when `VALUE` is not equal to `"no"`.
unit::assert_no() {
  local VALUE="$1"
  local MESSAGE="${2:-Value is not \"no\".}"

  [ "$VALUE" == "no" ] || {
    log::error::custom "ASSERT FAILED" "$MESSAGE"
    exit 1
  }
}

#>>
#>> * `unit::assert_not_empty VALUE [MESSAGE]`       - Show error message, when `VALUE` is empty.
unit::assert_not_empty() {
  local VALUE="${1:-}"
  local MESSAGE="${2:-Value is empty.}"

  [ -n "${VALUE:-}" ] || {
    log::error::custom "ASSERT FAILED" "$MESSAGE"
    exit 1
  }
}

#>>
#>> * `unit::assert_equal ACTUAL EXPECTED [MESSAGE]`  - Show error message, when values are not equal.
unit::assert_equal() {
  local ACTUAL="${1:-}"
  local EXPECTED="${2:-}"
  local MESSAGE="${3:-Values are not equal.}"

  [ "${ACTUAL:-}" == "${EXPECTED:-}" ] || {
    log::error::custom "ASSERT FAILED" "$MESSAGE Actual value: \"${ACTUAL:-}\", expected value: \"${EXPECTED:-}\"."
    exit 1
  }
}

#>>
#>> * `unit::assert_arrays_are_equal MESSAGE VALUE1... -- VALUE2...` - Show error message when arrays are not equal in size or content.
unit::assert_arrays_are_equal() {
  local MESSAGE="${1:-Arrays are not equal.}" ; shift
  local ARGS=( $@ )

  local I LEN1=''
  for((I=0;I<${#ARGS[@]};I++))
  do
    [ "${ARGS[I]}" != "--" ] || {
      LEN1="$I"
      break
    }
  done

  [ -n "${LEN1:-}" ] || {
    error "Array separator is not found. Put \"--\" between two arrays."
    exit 1
  }

  local LEN2=$(($# - LEN1 - 1))
  local MIN=$(( (LEN1<LEN2) ? LEN1 : LEN2 ))

  for((I=0; I < MIN; I++)) {
    local ACTUAL="${ARGS[I]:-}"
    local EXPECTED="${ARGS[I + LEN1 + 1]:-}"

    [ "${ACTUAL:-}" == "${EXPECTED:-}" ] || {
      log::error::custom "ASSERT FAILED" "$MESSAGE Actual size of array: $LEN1, expected size of array: $LEN2, position in array: $I, actual value: \"${ACTUAL:-}\", expected value: \"${EXPECTED:-}\"."$'\n'"$@"
      exit 1
    }
  }

  [ "$LEN1" -eq "$LEN2" ] || {
    log::error::custom "ASSERT FAILED" "$MESSAGE Arrays are not equal in size. Actual size: $LEN1, expected size: $LEN2."$'\n'"$@"
    exit 1
  }
}

#>>
#>> * `unit::assert_not_equal ACTUAL_VALUE UNEXPECTED_VALUE [MESSAGE]` - Show error message, when values ARE equal.
unit::assert_not_equal() {
  local ACTUAL_VALUE="${1:-}"
  local UNEXPECTED_VALUE="${2:-}"
  local MESSAGE="${3:-values are equal but must not.}"

  [ "${ACTUAL_VALUE:-}" != "${UNEXPECTED_VALUE:-}" ] || {
    log::error::custom "ASSERT FAILED" "$MESSAGE Actual value: \"${ACTUAL_VALUE:-}\", unexpected value: \"$UNEXPECTED_VALUE\"."
    exit 1
  }
}

#>>
#>> * `unit::assert MESSAGE TEST[...]`             - Evaluate test and show error message when it returns non-zero exit code.
unit::assert() {
  local MESSAGE="${1:-}"; shift

  eval "$@" || {
    log::error::custom "ASSERT FAILED" "${MESSAGE:-}: $@"
    exit 1
  }
}

#>>
#>> * `unit::fail [MESSAGE]`                       - Show error message.
unit::fail() {
  local MESSAGE="${1:-This point in test case must not be reached.}"; shift
  log::error::custom "FAIL" "$MESSAGE $@"
  exit 1
}

#>>
#>> * `unit::run_test_cases [OPTIONS] [--] [ARGUMENTS]` - Execute all functions with
#>>    test* prefix in name in alphabetic order
#>
#>    * OPTIONS:
#>      * `-t | --test TEST_CASE` - execute single test case,
#>      * `-q | --quiet`          - do not print informational messages and dots,
#>      * `--debug`               - enable stack traces.
#>   * ARGUMENTS - All arguments, which are passed to run_test_cases, are passed then
#>  to `unit::set_up`, `unit::tear_down` and test cases using `ARGUMENTS` array, so you
#>  can parametrize your test cases. You can call `run_test_cases` more than
#>  once with different arguments. Use `"--"` to strictly separate arguments
#>  from options.
#>
#>  After execution of `run_test_cases`, following variables will have value:
#>
#>    * `NUMBER_OF_TEST_CASES` - total number of test cases executed,
#>    * `NUMBER_OF_FAILED_TEST_CASES` - number of failed test cases,
#>    * `FAILED_TEST_CASES` - names of functions of failed tests cases.
#>
#>
#>  If you want to ignore some test case, just prefix them with
#>  underscore, so `unit::run_test_cases` will not see them.
#>
#>  If you want to run few subsets of test cases in one file, define each
#>  subset in it own subshell and execute `unit::run_test_cases` in each subshell.
#>
#>  Each test case is executed in it own subshell, so you can call `exit`
#>  in the test case or assign variables without any effect on subsequent test
#>  cases.
unit::run_test_cases() {

  NUMBER_OF_TEST_CASES=0
  NUMBER_OF_FAILED_TEST_CASES=0
  FAILED_TEST_CASES=( )

  local __QUIET=no __TEST_CASES=(  )

  arguments::parse \
    "-t|test)__TEST_CASES;Array" \
    "-q|--quiet)__QUIET;Yes" \
    -- "$@" || panic "Cannot parse arguments. Arguments: $*"

  # If no test cases are given via options
  [ "${#__TEST_CASES[@]}" -gt 0 ] || {
    # Then generate list of test cases using compgen
    # As alternative, declare -F | cut -d ' ' -f 3 | grep '^test' can be used
    __TEST_CASES=( $(compgen -A function test) ) || panic "No test cases are found. Create a function with test_ prefix in the name."
  }

  local __TEST __EXIT_CODE=0

  ( set -ueEo pipefail ; FIRST_TEAR_DOWN=yes ; unit::tear_down "${ARGUMENTS[@]:+${ARGUMENTS[@]}}" ) || {
      __EXIT_CODE=$?
      log::error::custom "FAIL" "tear_down before first test case is failed."
    }

  for __TEST in "${__TEST_CASES[@]:+${__TEST_CASES[@]}}"
  do
    let NUMBER_OF_TEST_CASES++ || :
    [ "$__QUIET" == "yes" ] || echo -n "."

    (
      __EXIT_CODE=0

      unit::set_up "${ARGUMENTS[@]:+${ARGUMENTS[@]}}" || {
        __EXIT_CODE=$?
        unit::fail "unit::set_up failed before test case #$NUMBER_OF_TEST_CASES ($__TEST)."
      }

      ( "$__TEST" "${ARGUMENTS[@]:+${ARGUMENTS[@]}}" ) || {
        __EXIT_CODE=$?
        unit::fail "Test case #$NUMBER_OF_TEST_CASES ($__TEST) failed."
      }

      unit::tear_down "${ARGUMENTS[@]:+${ARGUMENTS[@]}}" || {
        __EXIT_CODE=$?
        unit::fail "unit::tear_down failed after test case #$NUMBER_OF_TEST_CASES ($__TEST)."
      }
      exit $__EXIT_CODE # Exit from subshell
    ) || {
      __EXIT_CODE=$?
      let NUMBER_OF_FAILED_TEST_CASES++ || :
      FAILED_TEST_CASES[${#FAILED_TEST_CASES[@]}]="$__TEST"
    }
  done

  [ "$__QUIET" == "yes" ] || echo
  if [ "$__EXIT_CODE" -eq 0 ]
  then
    [ "$__QUIET" == "yes" ] || log::info "OK" "Test cases total: $NUMBER_OF_TEST_CASES, failed: $NUMBER_OF_FAILED_TEST_CASES${FAILED_TEST_CASES[@]:+, failed methods: ${FAILED_TEST_CASES[@]}}."
  else
    log::error::custom "FAIL" "Test cases total: $NUMBER_OF_TEST_CASES, failed: $NUMBER_OF_FAILED_TEST_CASES${FAILED_TEST_CASES[@]:+, failed methods: ${FAILED_TEST_CASES[@]}}."
  fi

  return $__EXIT_CODE
}

#>
#> `unit::run_test_cases` will also call `unit::set_up` and `unit::tear_down`
#> functions before and after each test case. By default, they do nothing.
#> Override them to do something useful.

#>>
#>> * `unit::set_up` - can set variables which are available for following
#>>  test case and `tear_down`. It also can alter `ARGUMENTS` array. Test case
#>>  and tear_down are executed in their own subshell, so they cannot change
#>>  outer variables.
unit::set_up() {
  return 0
}

#>>
#>> * `unit::tear_down` is called first, before first set_up of first test case, to
#>>  cleanup after possible failed run of previous test case. When it
#>>  called for first time, `FIRST_TEAR_DOWN` variable with value `"yes"` is
#>>  available.
unit::tear_down() {
  return 0
}


#>
#> ## NOTES
#>
#> All assert functions are executing `exit` instead of returning error code.
