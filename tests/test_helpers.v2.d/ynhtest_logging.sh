ynhtest_exec_warn_less() {

    FOO='foo'
    bar=""
    BAR='$bar'
    FOOBAR="foo bar"

    # These looks like stupid edge case
    # but in fact happens when dealing with passwords
    # (which could also contain bash chars like [], {}, ...)
    # or urls containing &, ...
    FOOANDBAR="foo&bar"
    FOO1QUOTEBAR="foo'bar"
    FOO2QUOTEBAR="foo\"bar"
    
    ynh_exec_warn_less uptime
   
    test ! -e $FOO
    ynh_exec_warn_less touch $FOO
    test -e $FOO
    rm $FOO

    test ! -e $FOO1QUOTEBAR
    ynh_exec_warn_less touch $FOO1QUOTEBAR
    test -e $FOO1QUOTEBAR
    rm $FOO1QUOTEBAR

    test ! -e $FOO2QUOTEBAR
    ynh_exec_warn_less touch $FOO2QUOTEBAR
    test -e $FOO2QUOTEBAR
    rm $FOO2QUOTEBAR

    test ! -e $BAR
    ynh_exec_warn_less touch $BAR
    test -e $BAR
    rm $BAR

    test ! -e "$FOOBAR"
    ynh_exec_warn_less touch "$FOOBAR"
    test -e "$FOOBAR"
    rm "$FOOBAR"

    test ! -e "$FOOANDBAR"
    ynh_exec_warn_less touch $FOOANDBAR
    test -e "$FOOANDBAR"
    rm "$FOOANDBAR"

    ###########################
    # Legacy stuff using eval #
    ###########################
    
    test ! -e $FOO
    ynh_exec_warn_less "touch $FOO"
    test -e $FOO
    rm $FOO

    test ! -e $FOO1QUOTEBAR
    ynh_exec_warn_less "touch \"$FOO1QUOTEBAR\""
    # (this works but expliciy *double* quotes have to be provided)
    test -e $FOO1QUOTEBAR
    rm $FOO1QUOTEBAR

    #test ! -e $FOO2QUOTEBAR
    #ynh_exec_warn_less "touch \'$FOO2QUOTEBAR\'"
    ## (this doesn't work with simple or double quotes)
    #test -e $FOO2QUOTEBAR
    #rm $FOO2QUOTEBAR

    test ! -e $BAR
    ynh_exec_warn_less 'touch $BAR'
    # That one works because $BAR is only interpreted during eval
    test -e $BAR
    rm $BAR

    #test ! -e $BAR
    #ynh_exec_warn_less "touch $BAR"
    # That one doesn't work because $bar gets interpreted as empty var by eval...
    #test -e $BAR
    #rm $BAR

    test ! -e "$FOOBAR"
    ynh_exec_warn_less "touch \"$FOOBAR\""
    # (works but requires explicit double quotes otherwise eval would interpret 'foo bar' as two separate args..)
    test -e "$FOOBAR"
    rm "$FOOBAR"

    test ! -e "$FOOANDBAR"
    ynh_exec_warn_less "touch \"$FOOANDBAR\""
    # (works but requires explicit double quotes otherwise eval would interpret '&' as a "run command in background" and also bar is not a valid command)
    test -e "$FOOANDBAR"
    rm "$FOOANDBAR"
}
