#!/bin/bash

#=================================================
# N UPDATING HELPER
#=================================================

# This script is meant to be run by GitHub Actions.
# It is derived from the Updater script from the YunoHost-Apps organization.
# It aims to automate the update of `n`, the Node version management system.

#=================================================
# FETCHING LATEST RELEASE AND ITS ASSETS
#=================================================

# Fetching information
source helpers/nodejs
current_version="$n_version"
repo="tj/n"
# Some jq magic is needed, because the latest upstream release is not always the latest version (e.g. security patches for older versions)
version=$(curl --silent "https://api.github.com/repos/$repo/releases" | jq -r '.[] | select( .prerelease != true ) | .tag_name' | sort -V | tail -1)

# Later down the script, we assume the version has only digits and dots
# Sometimes the release name starts with a "v", so let's filter it out.
if [[ ${version:0:1} == "v" || ${version:0:1} == "V" ]]; then
    version=${version:1}
fi

# Setting up the environment variables
echo "Current version: $current_version"
echo "Latest release from upstream: $version"
echo "VERSION=$version" >> $GITHUB_ENV
# For the time being, let's assume the script will fail
echo "PROCEED=false" >> $GITHUB_ENV

# Proceed only if the retrieved version is greater than the current one
if ! dpkg --compare-versions "$current_version" "lt" "$version" ; then
    echo "::warning ::No new version available"
    exit 0
# Proceed only if a PR for this new version does not already exist
elif git ls-remote -q --exit-code --heads https://github.com/${GITHUB_REPOSITORY:-YunoHost/yunohost}.git ci-auto-update-n-v$version ; then
    echo "::warning ::A branch already exists for this update"
    exit 0
fi

#=================================================
# UPDATE SOURCE FILES
#=================================================

asset_url="https://github.com/tj/n/archive/v${version}.tar.gz"

echo "Handling asset at $asset_url"

# Create the temporary directory
tempdir="$(mktemp -d)"

# Download sources and calculate checksum
filename=${asset_url##*/}
curl --silent -4 -L $asset_url -o "$tempdir/$filename"
checksum=$(sha256sum "$tempdir/$filename" | head -c 64)

# Delete temporary directory
rm -rf $tempdir

echo "Calculated checksum for n v${version} is $checksum"

#=================================================
# GENERIC FINALIZATION
#=================================================

# Replace new version in helper
sed -i -E "s/^n_version=.*$/n_version=$version/" helpers/nodejs

# Replace checksum in helper
sed -i -E "s/^n_checksum=.*$/n_checksum=$checksum/" helpers/nodejs

# The Action will proceed only if the PROCEED environment variable is set to true
echo "PROCEED=true" >> $GITHUB_ENV
exit 0
