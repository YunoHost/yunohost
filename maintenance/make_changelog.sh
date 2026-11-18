#!/usr/bin/env bash
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

set -eu

function increment_version() {
    local version=$1
    local incr_type=$2

    local major=$(awk -F. '{print $1}' <<< "$version")
    local medium=$(awk -F. '{print $2}' <<< "$version")
    local minor=$(awk -F. '{print $3}' <<< "$version")
    local patch=$(awk -F. '{print $4}' <<< "$version")
    patch=${patch:-0}

    if [[ "$incr_type" == "patch" ]]
    then
        echo "$major.$medium.$minor.$((patch+1))"
    elif [[ "$incr_type" == "minor" ]]
    then
        echo "$major.$medium.$((minor+1))"
    elif [[ "$incr_type" == "medium" ]]
    then
        echo "$major.$((medium+1)).0"
    else
        echo "Unhandled version increment type '$incr_type', should be either 'patch', 'minor' or 'medium'" >&2
        exit 1
    fi
}


RELEASE="stable"
ME=$(git config --get user.name)
EMAIL=$(git config --get user.email)

REPO=$(head -n1 debian/changelog | awk '{print $1}')
CURRENT_VERSION=$(head -n1 debian/changelog | awk '{print $2}' | tr -d '()')
CURRENT_RELEASE_TYPE=$(head -n1 debian/changelog | awk '{print $3}' | tr -d ';')

INCR_VERSION_TYPE="${1:-}"
if [[ -n "$INCR_VERSION_TYPE" ]]
then
    NEW_VERSION="$(increment_version "$CURRENT_VERSION" "$INCR_VERSION_TYPE")"
else
    NEW_VERSION="x.y.z"
fi

RELEASE_TYPE="${2:-}"
if [[ -n "$RELEASE_TYPE" ]]
then
    [[ $RELEASE_TYPE == "stable" ]] || [[ $RELEASE_TYPE == "testing" ]] || ( echo "Release type should be either 'stable' or 'testing'" >&2; exit 1; )
    NEW_RELEASE_TYPE=$RELEASE_TYPE
else
    NEW_VERSION_TYPE=$CURRENT_RELEASE_TYPE
fi



echo "$REPO ($NEW_VERSION) $CURRENT_RELEASE_TYPE; urgency=low"
echo ""

PREVIOUS_TAG="debian/$CURRENT_VERSION"
COMMITS=$(git log "$PREVIOUS_TAG".. -n 10000 --first-parent --pretty=tformat:'%h')
for COMMIT in $COMMITS
do
    SUBJECT="$(git show -s "$COMMIT" --pretty="%s")"
    # "Regular" PRs merge commit
    if grep -q "^Merge pull request #" <<< "$SUBJECT"
    then
        PR_LINK=$(sed -E "s@Merge .*#([0-9]+).*\$@[#\1]\(http://github.com/YunoHost/$REPO/pull/\1\)@g" <<< "$SUBJECT")
        BODY="$(git show -s "$COMMIT" --pretty="%b")"
        echo "  - $BODY ($PR_LINK)"
    # PRs merged via stash
    elif grep -q " (#[0-9]*)$" <<< "$SUBJECT"
    then
        SUBJECT=$(sed -E "s@(.*) \(#([0-9]*)\)\$@\1 ([#\2]\(http://github.com/YunoHost/$REPO/pull/\2\))@g" <<< "$SUBJECT")
        echo "  - $SUBJECT"
    # Other "direct" commits
    else
        echo "  - $SUBJECT ($COMMIT)"
    fi
done \
| sed -E "/Co-authored-by: .* <.*>/d" \
| grep -v "Translations update from Weblate" \
| grep -v "Translated using Weblate" \
| grep -v ":art: Format Python code" \
| tac

TRANSLATIONS=$(git log "$PREVIOUS_TAG"... -n 10000 --pretty=format:"%s"  \
               | grep "Translated using Weblate" \
               | sed -E "s/Translated using Weblate \((.*)\)/\1/g"  \
               | sort | uniq | tr '\n' ', ' | sed -e 's/,$//g' -e 's/,/, /g')
[[ -z "$TRANSLATIONS" ]] || echo "  - i18n: Translations updated for $TRANSLATIONS"

echo ""
CONTRIBUTORS=$(git log -n10 --pretty=format:'%Cred%h%Creset %C(bold blue)(%an) %Creset%Cgreen(%cr)%Creset - %s %C(yellow)%d%Creset' --abbrev-commit "$PREVIOUS_TAG"... -n 10000 --pretty=format:"%an" \
               | sort | uniq  | grep -v "$ME" | grep -vi 'yunohost-bot\|YunoHost bot\|weblate' \
               | tr '\n' ', ' | sed -e 's/,$//g' -e 's/,/, /g')
[[ -z "$CONTRIBUTORS" ]] || echo "  Thanks to all contributors <3 ! ($CONTRIBUTORS)"
echo ""
echo " -- $ME <$EMAIL>  $(date -R)"
echo ""

echo "===================================="
echo "To complete the release"
echo "===================================="
[[ -n "$INCR_VERSION_TYPE" ]] || \
    cat << EOF
- Fix the version number (or call this script with 'patch', 'minor' or 'medium' as first argument)
     - 'patch' is meant for shameful bugfixes like typo breaking everything, need fix ASAP
     - 'minor' for regular iterations on YunoHost with small features, minor fixes/improvements
     - 'medium' typically when releasing a bunch of important, major-ish changes (not counting Debian versions which is the first number)
EOF
[[ -n "$RELEASE_TYPE" ]] || \
    echo "- Confirm that this is still a '$NEW_VERSION_TYPE' release (you can also specify 'stable' or 'testing' as second arg to this command)"

cat << EOF
- Copypasta this new changelog to the top of debian/changelog, beware of formatting, empty line, leading/trailing spaces...
- Re-read carefully the changelog and smooth the messages to:
    - cleanup bumpy syntax/formatting
    - each line give a pretty good idea of what this is about without opening the commit/PR... Ideally at least prefix them with the general topic (eg 'apps:', 'dns:', 'nginx:', ...)
    - possibly trim stuff that are way too technical or irrelevant (typo fixes, syntax updates from bot, purely test/quality fixes, ...)
- Conclude with:
     NEW_VERSION="$NEW_VERSION"
     git commit debian/changelog -m "Update changelog for \$NEW_VERSION"
     git tag debian/\$NEW_VERSION
     git push origin $(git branch --show-current) --tags
- Connect to the infra' 'repo' machine, in vinaigrette directory
- Edit and run the 'release' script
EOF

# PR links can be converted to regular texts using : sed -E 's@\[(#[0-9]*)\]\([^ )]*\)@\1@g'
# Or readded with sed -E 's@#([0-9]*)@[YunoHost#\1](https://github.com/yunohost/yunohost/pull/\1)@g' | sed -E 's@\((\w+)\)@([YunoHost/\1](https://github.com/yunohost/yunohost/commit/\1))@g'
