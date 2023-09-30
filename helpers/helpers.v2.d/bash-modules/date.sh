#!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> `date` - date-time functions.

#>
#> ## FUNCTIONS

#>>
#>> * `date::timestamp VARIABLE` - return current time in seconds since UNIX epoch
date::timestamp() {
  printf -v "$1" "%(%s)T" "-1"
}

#>>
#>> * `date::current_datetime VARIABLE FORMAT` - return current date time in given format.
#> See `man 3 strftime` for details.
date::current_datetime() {
  printf -v "$1" "%($2)T" "-1"
}

#>>
#>> * `date::print_current_datetime FORMAT` - print current date time in given format.
#> See `man 3 strftime` for details.
date::print_current_datetime() {
  printf "%($1)T" "-1"
}

#>>
#>> * `date::datetime VARIABLE FORMAT TIMESTAMP` - return current date time in given format.
#> See `man 3 strftime` for details.
date::datetime() {
  printf -v "$1" "%($2)T" "$3"
}

#>>
#>> * `date::print_elapsed_time` - print value of SECONDS variable in human readable form: "Elapsed time: 0 days 00:00:00."
#> It's useful to know time of execution of a long script, so here is function for that.
#> Assign 0 to SECONDS variable to reset counter.
date::print_elapsed_time() {
  printf "Elapsed time: %d days %02d:%02d:%02d.\n" $((SECONDS/(24*60*60))) $(((SECONDS/(60*60))%24)) $(((SECONDS/60)%60)) $((SECONDS%60))
}
