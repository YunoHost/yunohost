#!/usr/bin/env bash
#
# Copyright (c) 2009-2013 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
#
# This file is part of bash-modules (http://trac.assembla.com/bash-modules/).
#
# bash-modules is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 2.1 of the License, or
# (at your option) any later version.
#
# bash-modules is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with bash-modules  If not, see <http://www.gnu.org/licenses/>.

#> ## NAME
#>>
#>>> `import.sh` - import bash modules into scripts or into interactive shell
#>
#> ## SYNOPSIS
#>>
#>> ### In a scipt:
#>>
#>> * `. import.sh MODULE[...]`      - import module(s) into script or shell
#>> * `source import.sh MODULE[...]` - same as above, but with `source` instead of `.`
#>>
#>>
#>> ### At command line:
#>>
#>> * `import.sh --help|-h`                - print this help text
#>> * `import.sh --man`                    - show manual
#>> * `import.sh --list`                   - list modules with their path
#>> * `import.sh --summary|-s [MODULE...]` - list module(s) with summary
#>> * `import.sh --usage|-u MODULE[...]`   - print module help text
#>> * `import.sh --doc|-d MODULE[...]`     - print module documentation
#>>
#> ## DESCRIPTION
#>
#> Imports given module(s) into current shell.
#>
#> Use:
#>
#> * `import.sh --list` - to print list of available modules.
#> * `import.sh --summary` - to print list of available modules with short description.
#> * `import.sh --usage MODULE[...]` - to print longer description of given module(s).

[ "${__IMPORT__DEFINED:-}" == "yes" ] || {
  __IMPORT__DEFINED="yes"

  [ "$BASH_VERSINFO" -ge 4 ] || {
    echo "[import.sh] ERROR: This script works only with Bash, version 4 or greater. Upgrade is necessary." >&2
    exit 80
  }

  # If BASH_MODULES_PATH variable contains a ':' separator, then split it into array
  if [[ "${BASH_MODULES_PATH:-}" == *':'* ]]; then
    __split_by_delimiter() {
      local __string__VAR="$1"
      local IFS="$2"
      local __string__VALUE="${3:-}"
      read -a "$__string__VAR" <<<"${__string__VALUE:-}"
    }
    __split_by_delimiter __BASH_MODULES_PATH_ARRAY ':' "${BASH_MODULES_PATH:+$BASH_MODULES_PATH}"
    unset -f __split_by_delimiter
  else
    __BASH_MODULES_PATH_ARRAY=( "${BASH_MODULES_PATH:+$BASH_MODULES_PATH}" )
  fi

  #>
  #> ## CONFIGURATION

  #>
  #> * `BASH_MODULES_PATH` - (variable with single path entry, at present time).
  #> `BASH_MODULES_PATH` can contain multiple directories separated by ":".
  #>
  #> * `__IMPORT__BASE_PATH` - array with list of your own directories with modules,
  #> which will be prepended to module search path. You can set `__IMPORT__BASE_PATH` array in
  #> script at begining, in `/etc/bash-modules/config.sh`, or in `~/.config/bash-modules/config.sh` file.
  __IMPORT__BASE_PATH=( "${__BASH_MODULES_PATH_ARRAY[@]:+${__BASH_MODULES_PATH_ARRAY[@]}}" "${__IMPORT__BASE_PATH[@]:+${__IMPORT__BASE_PATH[@]}}" "/usr/share/bash-modules" )
  unset __BASH_MODULES_PATH_ARRAY

  #>
  #> * `/etc/bash-modules/config.sh` - system wide configuration file.
  #> WARNING: Code in this script will affect all scripts.
  #>
  #> ### Example configration file
  #>
  #> Put following snippet into `~/.config/bash-modules/config.sh` file:
  #>
  #>```bash
  #>
  #>     # Enable stack trace printing for warnings and errors,
  #>     # like with --debug option:
  #>     __log__STACKTRACE=="yes"
  #>
  #>     # Add additional directory to module search path:
  #>     BASH_MODULES_PATH="/home/user/my-bash-modules"
  #>
  #>```
  [ ! -s /etc/bash-modules/config.sh ] || source /etc/bash-modules/config.sh || {
    echo "[import.sh] WARN: Cannot import \"/etc/bash-modules/config.sh\" or an error in this file." >&2
  }

  #>
  #> * `~/.config/bash-modules/config.sh` - user configuration file.
  #> **WARNING:** Code in this script will affect all user scripts.
  [ ! -s "$HOME/.config/bash-modules/config.sh" ] || source "$HOME/.config/bash-modules/config.sh" || {
    echo "[import.sh] WARN: Cannot import \"$HOME/.config/bash-modules/config.sh\" or an error in this file." >&2
  }

  #>
  #> ## VARIABLES

  #>
  #> * `IMPORT__BIN_FILE` -  script main file name, e.g. `/usr/bin/my-script`, as in `$0` variable in main file.
  __IMPORT_INDEX="${#BASH_SOURCE[*]}"
  IMPORT__BIN_FILE="${BASH_SOURCE[__IMPORT_INDEX-1]}"
  unset __IMPORT_INDEX

  #>
  #> ## FUNCTIONS

  #>
  #> * `import::import_module MODULE` - import single module only.
  import::import_module() {
    local __MODULE="${1:?Argument is required: module name, without path and without .sh extension, e.g. "log".}"

    local __PATH
    for __PATH in "${__IMPORT__BASE_PATH[@]}"
    do
      [ -f "$__PATH/$__MODULE.sh" ] || continue

      # Don't import module twice, to avoid loops.
      # Replace some special symbols in the module name by "_".
      local -n __IMPORT_MODULE_DEFINED="__${__MODULE//[\[\]\{\}\/!@#$%^&*()=+~\`\\,?|\'\"-]/_}__DEFINED" # Variable reference
      [ "${__IMPORT_MODULE_DEFINED:-}" != "yes" ] || return 0 # Already imported
      __IMPORT_MODULE_DEFINED="yes"
      unset -n __IMPORT_MODULE_DEFINED # Unset reference

      # Import module
      source "$__PATH/$__MODULE.sh" || return 1
      return 0
    done

    echo "[import.sh:import_module] ERROR: Cannot locate module: \"$__MODULE\". Search path: ${__IMPORT__BASE_PATH[*]}" >&2
    return 2
  }

  #>
  #> * `import::import_modules MODULE[...]` - import module(s).
  import::import_modules() {
    local __MODULE __ERROR_CODE=0
    for __MODULE in "$@"
    do
      import::import_module "$__MODULE" || __ERROR_CODE=$?
    done
    return $__ERROR_CODE
  }

  #>
  #> * `import::list_modules FUNC [MODULE]...` - print various information about module(s).
  #> `FUNC` is a function to call on each module. Function will be called with two arguments:
  #> path to module and module name.
  #> Rest of arguments are module names. No arguments means all modules.
  import::list_modules() {
    local __FUNC="${1:?ERROR: Argument is required: function to call with module name.}"
    shift

    declare -a __MODULES
    local __PATH __MODULE __MODULES

    # Collect modules
    if [ $# -eq 0 ]
    then
      # If no arguments are given,
      # then add all modules in all directories
      for __PATH in "${__IMPORT__BASE_PATH[@]}"
      do
        for __MODULE in "$__PATH"/*.sh
        do
          [ -f "$__MODULE" ] || continue
          __MODULES[${#__MODULES[@]}]="$__MODULE"
        done
      done
    else
      # Argument can be directory or module path or module name.
      local __ARG
      for __ARG in "$@"
      do
        if [ -d "$__ARG" ]
        then
          # Directory. Add all modules in directory
          for __MODULE in "$__ARG"/*.sh
          do
            [ -f "$__MODULE" ] || continue
            __MODULES[${#__MODULES[@]}]="$__MODULE"
          done
        elif [ -f "$__ARG" ]
        then
          # Direct path. Add single module.
          __MODULES[${#__MODULES[@]}]="$__ARG"
        else
          # Module name. Find single module in path.
          for __PATH in "${__IMPORT__BASE_PATH[@]}"
          do
            [ -f "$__PATH/$__ARG.sh" ] || continue
            __MODULES[${#__MODULES[@]}]="$__PATH/$__ARG.sh"
          done
        fi
      done
    fi

    # Call function on each module
    local __MODULE_PATH
    for __MODULE_PATH in "${__MODULES[@]}"
    do
      [ -f "$__MODULE_PATH" ] || continue
      __MODULE="${__MODULE_PATH##*/}" # Strip directory
      __MODULE="${__MODULE%.sh}" # Strip extension

      # Call requested function on each module
      $__FUNC "$__MODULE_PATH" "$__MODULE" || { echo "WARN: Error in function \"$__FUNC '$__MODULE_PATH'\"." >&2 ; }
    done
  }

  #>
  #> * `import::show_documentation LEVEL PARSER FILE` - print module built-in documentation.
  #> This function scans given file for lines with "#>" prefix (or given prefix) and prints them to stdout with prefix stripped.
  #>   * `LEVEL` - documentation level (one line summary, usage, full manual):
  #>      - 1 - for manual (`#>` and `#>>` and `#>>>`),
  #>      - 2 - for usage (`#>>` and `#>>>`),
  #>      - 3 - for one line summary (`#>>>`),
  #>      - or arbitrary prefix, e.g. `##`.
  #>   * `FILE` - path to file with built-in documentation.
  import::show_documentation() {
    local LEVEL="${1:?ERROR: Argument is required: level of documentation: 1 for all documentation, 2 for usage, 3 for one line summary.}"
    local FILE="${2:?ERRROR: Argument is required: file to parse documentation from.}"

    [ -e "$FILE" ] || {
      echo "ERROR: File \"$FILE\" is not exits." >&2
    }
    [ -f "$FILE" ] || {
      echo "ERROR: Path \"$FILE\" is not a file." >&2
    }
    [ -r "$FILE" ] || {
      echo "ERROR: Cannot read file \"$FILE\"." >&2
    }
    [ -s "$FILE" ] || {
      echo "ERROR: File \"$FILE\" is empty." >&2
    }

    local PREFIX=""
    case "$LEVEL" in
      1)  PREFIX="#>" ;;
      2)  PREFIX="#>>" ;;
      3)  PREFIX="#>>>" ;;
      *)
        PREFIX="$LEVEL"
      ;;
    esac

    local line
    while read line
    do
      if [[ "$line" =~ ^\s*"$PREFIX"\>*\ ?(.*)$ ]]
      then
        echo "${BASH_REMATCH[1]}"
      fi
    done < "$FILE"
  }


}

# If this is top level code and program name is .../import.sh
if [ "${FUNCNAME:+x}" == "" -a "${0##*/}" == "import.sh" ]
then
  show_module_info() {
    local module_path="$1"
    local module_name="$2"

    printf "%-24s\t%s\n" "$module_name" "$module_path"
  }

  # import.sh called as standalone program
  if  [ "$#" -eq 0 ]
  then
    import::show_documentation 2 "$IMPORT__BIN_FILE"
  else
    case "$1" in
      --list|-l)
        shift 1
        import::list_modules "show_module_info" "${@:+$@}"
      ;;
      --summary|-s)
        shift 1
        import::list_modules "import::show_documentation 3" "${@:+$@}"
      ;;
      --usage|-u)
        shift 1
        import::list_modules "import::show_documentation 2" "${@:+$@}"
      ;;
      --documentation|--doc|-d)
        shift 1
        import::list_modules "import::show_documentation 1" "${@:+$@}" | less
      ;;
      --man)
        shift 1
        import::show_documentation 1 "$IMPORT__BIN_FILE" | less
      ;;
      --help|-h|*)
        shift 1
        import::show_documentation 2 "$IMPORT__BIN_FILE"
      ;;
    esac
  fi

else
  # Import given modules when parameters are supplied.
  [ "$#" -eq 0 ] || import::import_modules "$@"
fi
