##!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+
import::import_modules log arguments

#>> ## NAME
#>>
#>>> `settings` - import settings from configuration files and configuration directories.
#>> Also known as "configuration directory" pattern.

#>>
#>> ## FUNCTIONS

#>> * `settings::import [-e|--ext EXTENSION] FILE|DIRECTORY...` -  Import settings
#> (source them into current program as shell script) when
#> file or directory exists. For directories, all files with given extension
#> (`".sh"` by default) are imported, without recursion.
#>
#> **WARNING:** this method is powerful, but unsafe, because user can put any shell
#> command into the configuration file, which will be executed by script.
#>
#> **TODO:** implement file parsing instead of sourcing.
settings::import() {
  local __settings_EXTENSION="sh"
  arguments::parse '-e|--ext)__settings_EXTENSION;String,Required' -- "$@" || panic "Cannot parse arguments."

  local __settings_ENTRY
  for __settings_ENTRY in "${@:+$@}"
  do
    if [ -f "$__settings_ENTRY" -a -r "$__settings_ENTRY" -a -s "$__settings_ENTRY" ]
    then
      # Just source configuration file into this script.
      source "$__settings_ENTRY" || {
        error "Cannot import settings from \"$__settings_ENTRY\" file: non-zero exit code returned: $?." >&2
        return 1
      }
    elif [ -d "$__settings_ENTRY" -a -x "$__settings_ENTRY" ]
    then
      # Just source each configuration file in the directory into this script.
      local __settings_FILE
      for __settings_FILE in "$__settings_ENTRY"/*."$__settings_EXTENSION"
      do
        if [ -f "$__settings_FILE" -a -r "$__settings_FILE" -a -s "$__settings_FILE" ]
        then
          source "$__settings_FILE" || {
            error "Cannot import settings from \"$__settings_FILE\" file: non-zero exit code returned: $?." >&2
            return 1
          }
        fi
      done
    fi
  done
  return 0
}
