#!/usr/bin/env bash

VERSION=$1
TESTFILE=$2
TESTFUNC=$3

export YNH_STDINFO=1
export YNH_ARCH=$(dpkg --print-architecture)
export YNH_J2_FILTERS_FILE_PATH="$(python3 <<< 'from yunohost.utils import jinja_filters; print(jinja_filters.__file__)')"
export YNH_HELPERS_VERSION="$VERSION"

pushd "$(mktemp -d)" >/dev/null
mkdir conf
mkdir scripts
cd scripts
# shellcheck disable=SC1091
source /usr/share/yunohost/helpers
app=ynhtest
# shellcheck disable=SC2034
YNH_APP_ID=$app

set -eux

# shellcheck disable=SC1090
source "$TESTFILE"
"$TESTFUNC"
