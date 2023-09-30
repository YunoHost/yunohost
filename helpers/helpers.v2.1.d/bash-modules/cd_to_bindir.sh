##!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+
#>> # NAME
#>>> `cd_to_bindir` - change working directory to the directory where main script file is located.
#>>
#>> # DESCRIPTION
#>>
#>> Just import this cwdir module to change current working directory to a directory,
#>> where main script file is located.

# Get file name of the main source file
__CD_TO_BINDIR__BIN_FILE="${BASH_SOURCE[${#BASH_SOURCE[@]}-1]}"

# If file name doesn't contains "/", then use `which` to find path to file name.
[[ "$__CD_TO_BINDIR__BIN_FILE" == */* ]] || __CD_TO_BINDIR__BIN_FILE=$( which "$__CD_TO_BINDIR__BIN_FILE" )

# Strip everything after last "/" to get directoru: "/foo/bar/baz" -> "/foo/bar", "./foo" -> "./".
# Then cd to the directory and get it path.
__CD_TO_BINDIR_DIRECTORY=$( cd "${__CD_TO_BINDIR__BIN_FILE%/*}/" ; pwd )

unset __CD_TO_BINDIR__BIN_FILE

#>>
#>> # FUNCTIONS
#>>
#>> * `ch_bin_dir` - Change working directory to directory where script is located, which is usually called "bin dir".
cd_to_bindir() {
  cd "$__CD_TO_BINDIR_DIRECTORY"
}

# Call this function at import.
cd_to_bindir
