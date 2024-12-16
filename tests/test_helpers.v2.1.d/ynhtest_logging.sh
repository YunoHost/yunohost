#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034,SC2089,SC2090

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

    ynh_hide_warnings uptime

    test ! -e $FOO
    ynh_hide_warnings touch $FOO
    test -e $FOO
    rm $FOO

    test ! -e $FOO1QUOTEBAR
    ynh_hide_warnings touch $FOO1QUOTEBAR
    test -e $FOO1QUOTEBAR
    rm $FOO1QUOTEBAR

    test ! -e $FOO2QUOTEBAR
    ynh_hide_warnings touch $FOO2QUOTEBAR
    test -e $FOO2QUOTEBAR
    rm $FOO2QUOTEBAR

    test ! -e $BAR
    ynh_hide_warnings touch $BAR
    test -e $BAR
    rm $BAR

    test ! -e "$FOOBAR"
    ynh_hide_warnings touch "$FOOBAR"
    test -e "$FOOBAR"
    rm "$FOOBAR"

    test ! -e "$FOOANDBAR"
    ynh_hide_warnings touch $FOOANDBAR
    test -e "$FOOANDBAR"
    rm "$FOOANDBAR"

    test ! -e $FOO
    ! ynh_hide_warnings "touch $FOO"
    ! test -e $FOO
}
