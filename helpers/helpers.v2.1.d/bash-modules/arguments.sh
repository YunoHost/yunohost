#!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> `arguments`  - contains function to parse arguments and assign option values to variables.

#>>
#>> ## FUNCTIONS

#>>
#>> * `arguments::parse [-S|--FULL)VARIABLE;FLAGS[,COND]...]... -- [ARGUMENTS]...`
#>
#> Where:
#>
#> * `-S`       - short option name.
#>
#> * `--FULL`   - long option name.
#>
#> * `VARIABLE` - name of shell variable to assign value to.
#>
#> * `FLAGS`    - one of (case sensitive):
#>   * `Y | Yes`               - set variable value to "yes";
#>   * `No`                    - set variable value to "no";
#>   * `I | Inc | Incremental` - incremental (no value) - increment variable value by one;
#>   * `S | Str | String`      - string value;
#>   * `N | Num | Number`      - numeric value;
#>   * `A | Arr | Array`       - array of string values (multiple options);
#>   * `C | Com | Command`     - option name will be assigned to the variable.
#>
#> * `COND` -  post conditions:
#>   * `R | Req | Required` - option value must be not empty after end of parsing.
#>                          Set initial value to empty value to require this option;
#>   * any code           - executed after option parsing to check post conditions, e.g. "(( FOO > 3 )), (( FOO > BAR ))".
#>
#> * --       - the separator between option descriptions and script commandline arguments.
#>
#> * `ARGUMENTS` - command line arguments to parse.
#>
#> **LIMITATION:** grouping of one-letter options is NOT supported. Argument `-abc` will be parsed as
#> option `-abc`, not as `-a -b -c`.
#>
#> **NOTE:** bash4 requires to use `"${@:+$@}"` to expand empty list of arguments in strict mode (`-u`).
#>
#> By default, function supports `-h|--help`, `--man` and `--debug` options.
#> Options `--help` and `--man` are calling `arguments::help()` function with `2` or `1` as
#> argument. Override that function if you want to provide your own help.
#>
#> Unlike many other parsers, this function stops option parsing at first
#> non-option argument.
#>
#> Use `--` in commandline arguments to strictly separate options and arguments.
#>
#> After option parsing, unparsed command line arguments are stored in
#> `ARGUMENTS` array.
#>
#> **Example:**
#>
#> ```bash
#> # Boolean variable ("yes" or "no")
#> FOO="no"
#> # String variable
#> BAR=""
#> # Indexed array
#> declare -a BAZ=( )
#> # Integer variable
#> declare -i TIMES=0
#>
#> arguments::parse \\
#>    "-f|--foo)FOO;Yes" \\
#>    "-b|--bar)BAR;String,Required" \\
#>    "-B|--baz)BAZ;Array" \\
#>    "-i|--inc)TIMES;Incremental,((TIMES<3))" \\
#>    -- \\
#>    "${@:+$@}"
#>
#> # Print name and value of variables
#> dbg FOO BAR BAZ TIMES ARGUMENTS
#> ```
arguments::parse() {

  # Global array to hold command line arguments
  ARGUMENTS=( )

  # Local variables
  local OPTION_DESCRIPTIONS PARSER
  declare -a OPTION_DESCRIPTIONS
  # Initialize array, because declare -a is not enough anymore for -u opt
  OPTION_DESCRIPTIONS=( )

  # Split arguments list at "--"
  while [ $# -gt 0 ]
  do
    [ "$1" != "--" ] || {
      shift
      break
    }

    OPTION_DESCRIPTIONS[${#OPTION_DESCRIPTIONS[@]}]="$1" # Append argument to end of array
    shift
  done

  # Generate option parser and execute it
  PARSER="$(arguments::generate_parser "${OPTION_DESCRIPTIONS[@]:+${OPTION_DESCRIPTIONS[@]}}")" || return 1
  eval "$PARSER" || return 1
  arguments::parse_options "${@:+$@}" || return $?
}

#>>
#>> * `arguments::generate_parser OPTIONS_DESCRIPTIONS` - generate parser for options.
#> Will create function `arguments::parse_options()`, which can be used to parse arguments.
#> Use `declare -fp arguments::parse_options` to show generated source.
arguments::generate_parser() {

  local OPTION_DESCRIPTION OPTION_CASE OPTION_FLAGS OPTION_TYPE OPTION_OPTIONS OPTIONS_PARSER="" OPTION_POSTCONDITIONS=""

  # Parse option description and generate code to parse that option from script arguments
  while [ $# -gt 0 ]
  do
    # Parse option description
    OPTION_DESCRIPTION="$1" ; shift

    # Check option syntax
    case "$OPTION_DESCRIPTION" in
      *')'*';'*) ;; # OK
      *)
        log::error "Incorrect syntax of option: \"$OPTION_DESCRIPTION\". Option syntax: -S|--FULL)VARIABLE;TYPE[,CHECK]... . Example: '-f|--foo)FOO;String,Required'."
        __log__DEBUG=yes; log::stacktrace
        return 1
      ;;
    esac

    OPTION_CASE="${OPTION_DESCRIPTION%%)*}" # Strip everything after first ')': --foo)BAR -> --foo
    OPTION_VARIABLE="${OPTION_DESCRIPTION#*)}" # Strip everything before first ')': --foo)BAR -> BAR
    OPTION_FLAGS="${OPTION_VARIABLE#*;}" # Strip everything before first ';': BAR;Baz -> Baz
    OPTION_VARIABLE="${OPTION_VARIABLE%%;*}" # String everything after first ';': BAR;Baz -> BAR

    IFS=',' read -a OPTION_OPTIONS <<<"$OPTION_FLAGS" # Convert string into array: 'a,b,c' -> [ a b c ]
    OPTION_TYPE="${OPTION_OPTIONS[0]:-}" ; unset OPTION_OPTIONS[0] ; # First element of array is option type

    # Generate the parser for option
    case "$OPTION_TYPE" in

     Y|Yes) # Set variable to "yes", no arguments
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          $OPTION_VARIABLE=\"yes\"
          shift 1
        ;;
        "
      ;;

     No) # Set variable to "no", no arguments
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          $OPTION_VARIABLE=\"no\"
          shift 1
        ;;
        "
      ;;

     C|Com|Command) # Set variable to name of the option, no arguments
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          $OPTION_VARIABLE=\"\$1\"
          shift 1
        ;;
        "
      ;;


     I|Incr|Incremental) # Incremental - any use of this option will increment variable by 1
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          let $OPTION_VARIABLE++ || :
          shift 1
        ;;
        "
      ;;

      S|Str|String) # Regular option with string value
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          $OPTION_VARIABLE=\"\${2:?ERROR: String value is required for \\\"$OPTION_CASE\\\" option. See --help for details.}\"
          shift 2
        ;;
        ${OPTION_CASE//|/=*|}=*)
          $OPTION_VARIABLE=\"\${1#*=}\"
          shift 1
        ;;
        "
      ;;

      N|Num|Number) # Same as string
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          $OPTION_VARIABLE=\"\${2:?ERROR: Numeric value is required for \\\"$OPTION_CASE\\\" option. See --help for details.}\"
          shift 2
        ;;
        ${OPTION_CASE//|/=*|}=*)
          $OPTION_VARIABLE=\"\${1#*=}\"
          shift 1
        ;;
        "
      ;;

      A|Arr|Array) # Array of strings
        OPTIONS_PARSER="$OPTIONS_PARSER
        $OPTION_CASE)
          ${OPTION_VARIABLE}[\${#${OPTION_VARIABLE}[@]}]=\"\${2:?Value is required for \\\"$OPTION_CASE\\\". See --help for details.}\"
          shift 2
        ;;
        ${OPTION_CASE//|/=*|}=*)
          ${OPTION_VARIABLE}[\${#${OPTION_VARIABLE}[@]}]=\"\${1#*=}\"
          shift 1
        ;;
        "
      ;;

      *)
        echo "ERROR: Unknown option type: \"$OPTION_TYPE\"." >&2
        return 1
      ;;
    esac

    # Parse option options, e.g "Required". Any other text is treated as condition, e.g. (( VAR > 10 && VAR < 20 ))
    local OPTION_OPTION
    for OPTION_OPTION in "${OPTION_OPTIONS[@]:+${OPTION_OPTIONS[@]}}"
    do
      case "$OPTION_OPTION" in
        R|Req|Required)
          OPTION_POSTCONDITIONS="$OPTION_POSTCONDITIONS
            [ -n \"\$${OPTION_VARIABLE}\" ] || { echo \"ERROR: Option \\\"$OPTION_CASE\\\" is required. See --help for details.\" >&2; return 1; }
          "
        ;;
        *) # Any other code after option type i
          OPTION_POSTCONDITIONS="$OPTION_POSTCONDITIONS
            $OPTION_OPTION || { echo \"ERROR: Condition for \\\"$OPTION_CASE\\\" option is failed. See --help for details.\" >&2; return 1; }
          "
        ;;
      esac
    done

  done
  echo "
    arguments::parse_options() {
    # Global array to hold command line arguments
    ARGUMENTS=( )

    while [ \$# -gt 0 ]
    do
      case \"\$1\" in
      # User options.
      $OPTIONS_PARSER

      # Built-in options.
      -h|--help)
        arguments::help 2
        exit 0
      ;;
      --man)
        arguments::help 1
        exit 0
      ;;
      --debug)
        log::enable_debug_mode
        shift
      ;;
      --)
        shift; break; # Do not parse rest of the command line arguments
      ;;
      -*)
        echo \"ERROR: Unknown option: \\\"\$1\\\".\" >&2
        arguments::help 3
        return 1
      ;;
      *)
        break; # Do not parse rest of the command line
      ;;
      esac
    done
    [ \$# -eq 0 ] || ARGUMENTS=( \"\$@\" ) # Store rest of the command line arguments into the ARGUMENTS array
    $OPTION_POSTCONDITIONS
    }
  "
}

#>>
#>> * `arguments::help LEVEL` - display embeded documentation.
#>> LEVEL - level of documentation:
#>>   * 3 - summary (`#>>>` comments),
#>>   * 2 - summary and usage ( + `#>>` comments),
#>>   * 1 - full documentation (+ `#>` comments).
arguments::help() {
  local LEVEL="${1:-3}"
  case "$LEVEL" in
   2|3)  import::show_documentation "$LEVEL" "$IMPORT__BIN_FILE" ;;
   1)  import::show_documentation "$LEVEL" "$IMPORT__BIN_FILE" | less ;;
  esac
}
