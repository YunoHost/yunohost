##!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> string - various functions to manipulate strings.

#>>
#>> ## FUNCTIONS

#>>
#>> * `string::trim_spaces VARIABLE VALUE`
#>    Trim white space characters around value and assign result to variable.
string::trim() {
  local -n __string__VAR="$1"
  local __string__VALUE="${2:-}"

  # remove leading whitespace characters
  __string__VALUE="${__string__VALUE#"${__string__VALUE%%[![:space:]]*}"}"
  # remove trailing whitespace characters
  __string__VALUE="${__string__VALUE%"${__string__VALUE##*[![:space:]]}"}"

  __string__VAR="$__string__VALUE"
}

#>>
#>> * `string::trim_start VARIABLE VALUE`
#>    Trim white space characters at begining of the value and assign result to the variable.
string::trim_start() {
  local -n __string__VAR="$1"
  local __string__VALUE="${2:-}"

  # remove leading whitespace characters
  __string__VALUE="${__string__VALUE#"${__string__VALUE%%[![:space:]]*}"}" #"

  __string__VAR="$__string__VALUE"
}

#>>
#>> * `string::trim_end VARIABLE VALUE`
#>    Trim white space characters at the end of the value and assign result to the variable.
string::trim_end() {
  local -n __string__VAR="$1"
  local __string__VALUE="${2:-}"

  # remove trailing whitespace characters
  __string__VALUE="${__string__VALUE%"${__string__VALUE##*[![:space:]]}"}" #"

  __string__VAR="$__string__VALUE"
}

#>>
#>> * `string::insert VARIABLE POSITION VALUE`
#>    Insert `VALUE` into `VARIABLE` at given `POSITION`.
#>    Example:
#>
#>    ```bash
#>    v="abba"
#>    string::insert v 2 "cc"
#>    # now v=="abccba"
#>   ```
string::insert() {
  local -n __string__VAR="$1"
  local __string__POSITION="$2"
  local __string__VALUE="${3:-}"

  __string__VALUE="${__string__VAR::$__string__POSITION}${__string__VALUE}${__string__VAR:$__string__POSITION}"

  __string__VAR="$__string__VALUE"
}

#>>
#>> * `string::split ARRAY DELIMITERS VALUE`
#>    Split value by delimiter(s) and assign result to array. Use
#>    backslash to escape delimiter in string.
string::split_to() {
  local __string__VAR="$1"
  local IFS="$2"
  local __string__VALUE="${3:-}"

  # We can use "for" loop and strip elements item by item, but we are
  # unable to assign result to named array, so we must use "read -a" and "<<<" here.

  # TODO: use regexp and loop instead.
  read -a "$__string__VAR" <<<"${__string__VALUE:-}"
}

#>>
#>> * `string::split DELIMITERS VALUE`
#>    Split value by delimiter(s) and echo the result. Use
#>    backslash to escape delimiter in string.
string::split() {
  local -a __string__ECHO
  string::split_to "__string__ECHO" "$@"
  echo "${__string__ECHO[@]}"
}

#>>
#>> * `string::basename VARIABLE FILE [EXT]`
#>    Strip path and optional extension from  full file name and store
#>    file name in variable.
string::basename() {
  local -n __string__VAR="$1"
  local __string__FILE="${2:-}"
  local __string__EXT="${3:-}"

  __string__FILE="${__string__FILE##*/}" # Strip everything before last "/"
  __string__FILE="${__string__FILE%$__string__EXT}" # Strip .sh extension

  __string__VAR="$__string__FILE"
}

#>>
#>> * `string::dirname VARIABLE FILE`
#>    Strip file name from path and store directory name in variable.
string::dirname() {
  local -n __string__VAR="$1"
  local __string__FILE="${2:-}"

  local __string__DIR=""
  case "$__string__FILE" in
    */*)
      __string__DIR="${__string__FILE%/*}" # Strip everything after last "/'
    ;;
    *)
      __string__DIR="."
    ;;
  esac

  __string__VAR="$__string__DIR"
}

#>>
#>> * `string::random_string VARIABLE LENGTH`
#>    Generate random string of given length using [a-zA-Z0-9]
#>    characters and store it into variable.
string::random_string() {
  local -n __string__VAR="$1"
  local __string__LENGTH="${2:-8}"

  local __string__ALPHABET="0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
  local __string__ALPHABET_LENGTH=${#__string__ALPHABET}

  local __string__I __string__RESULT=""
  for((__string__I=0; __string__I<__string__LENGTH; __string__I++))
  do
    __string__RESULT="$__string__RESULT${__string__ALPHABET:RANDOM%__string__ALPHABET_LENGTH:1}"
  done

  __string__VAR="$__string__RESULT"
}

#>>
#>> * `string::chr VARIABLE CHAR_CODE`
#>    Convert decimal character code to its ASCII representation.
string::chr() {
  local __string__VAR="$1"
  local __string__CODE="$2"

  local __string__OCTAL_CODE
  printf -v __string__OCTAL_CODE '%03o' "$__string__CODE"
  printf -v "$__string__VAR" "\\$__string__OCTAL_CODE"
}

#>>
#>> * `string::ord VARIABLE CHAR`
#>    Converts ASCII character to its decimal value.
string::ord() {
  local __string__VAR="$1"
  local __string__CHAR="$2"

  printf -v "$__string__VAR" '%d' "'$__string__CHAR"
}

# Alternative version of function:
#  string::quote_to_bash_format() {
#    local -n __string__VAR="$1"
#    local __string__STRING="$2"
#
#    local __string__QUOTE="'\\''"
#    local __string__QUOTE="'\"'\"'"
#    __string__VAR="'${__string__STRING//\'/$__string__QUOTE}'"
#  }

#>>
#>> * `string::quote_to_bash_format VARIABLE STRING`
#>    Quote the argument in a way that can be reused as shell input.
string::quote_to_bash_format() {
  local __string__VAR="$1"
  local __string__STRING="$2"

  printf -v "$__string__VAR" "%q" "$__string__STRING"
}

#>>
#>> * `string::unescape_backslash_sequences VARIABLE STRING`
#>    Expand backslash escape sequences.
string::unescape_backslash_sequences() {
  local __string__VAR="$1"
  local __string__STRING="$2"

  printf -v "$__string__VAR" "%b" "$__string__STRING"
}

#>>
#>> * `string::to_identifier VARIABLE STRING`
#>    Replace all non-alphanumeric characters in string by underscore character.
string::to_identifier() {
  local -n __string__VAR="$1"
  local __string__STRING="$2"

  # We need a-zA-Z letters only.
  # 'z' can be in middle of alphabet on some locales.
  __string__VAR="${__string__STRING//[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]/_}"
}

#>>
#>> * `string::find_string_with_prefix VAR PREFIX [STRINGS...]`
#>    Find first string with given prefix and assign it to VAR.
string::find_string_with_prefix() {
  local -n __string__VAR="$1"
  local __string__PREFIX="$2"
  shift 2

  local __string__I
  for __string__I in "$@"
  do
    [[ "${__string__I}" != "${__string__PREFIX}"* ]] || {
      __string__VAR="${__string__I}"
      return 0
    }
  done
  return 1
}

#>>
#>> * `string::empty STRING`
#>    Returns zero exit code (true), when string is empty
string::empty() {
  [[ -z "${1:-}" ]]
}



#>>
#>> * `string::contains STRING SUBSTRING`
#>    Returns zero exit code (true), when string contains substring
string::contains() {
  case "$1" in
    *"$2"*) return 0 ;;
    *) return 1 ;;
  esac
}

#>>
#>> * `string::starts_with STRING SUBSTRING`
#>    Returns zero exit code (true), when string starts with substring
string::starts_with() {
  case "$1" in
    "$2"*) return 0 ;;
    *) return 1 ;;
  esac
}

#>>
#>> * `string::ends_with STRING SUBSTRING`
#>    Returns zero exit code (true), when string ends with substring
string::ends_with() {
  case "$1" in
    *"$2") return 0 ;;
    *) return 1 ;;
  esac
}
