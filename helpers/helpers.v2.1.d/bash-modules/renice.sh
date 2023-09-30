##!/bin/bash
# Copyright (c) 2009-2021 Volodymyr M. Lisivka <vlisivka@gmail.com>, All Rights Reserved
# License: LGPL2+

#>> ## NAME
#>>
#>>> `renice` - reduce priority of current shell to make it low priority task (`renice 19` to self).
#>>
#>> ## USAGE
#>>
#>> `. import.sh renice`

# Run this script as low priority task
renice 19 -p $$ >/dev/null
