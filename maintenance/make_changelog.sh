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

VERSION="?"
RELEASE="stable"
REPO=$(basename $(git rev-parse --show-toplevel))
REPO_URL=$(git remote get-url origin)
ME=$(git config --get user.name)
EMAIL=$(git config --get user.email)

LAST_RELEASE=$(git tag --list 'debian/12.*'  --sort="v:refname" | tail -n 1)

echo "$REPO ($VERSION) $RELEASE; urgency=low"
echo ""

git log $LAST_RELEASE.. -n 10000 --first-parent --pretty=tformat:'  - %b%s (%h)' \
| sed -E "s&Merge .*#([0-9]+).*\$& \([#\1]\(http://github.com/YunoHost/$REPO/pull/\1\)\)&g" \
| sed -E "/Co-authored-by: .* <.*>/d" \
| grep -v "Translations update from Weblate" \
| tac

TRANSLATIONS=$(git log $LAST_RELEASE... -n 10000 --pretty=format:"%s"  \
               | grep "Translated using Weblate" \
               | sed -E "s/Translated using Weblate \((.*)\)/\1/g"  \
               | sort | uniq | tr '\n' ', ' | sed -e 's/,$//g' -e 's/,/, /g')
[[ -z "$TRANSLATIONS" ]] || echo "  - [i18n] Translations updated for $TRANSLATIONS"

echo ""
CONTRIBUTORS=$(git log -n10 --pretty=format:'%Cred%h%Creset %C(bold blue)(%an) %Creset%Cgreen(%cr)%Creset - %s %C(yellow)%d%Creset' --abbrev-commit $LAST_RELEASE... -n 10000 --pretty=format:"%an" \
               | sort | uniq  | grep -v "$ME" | grep -v 'yunohost-bot' | grep -vi 'weblate' \
               | tr '\n' ', ' | sed -e 's/,$//g' -e 's/,/, /g')
[[ -z "$CONTRIBUTORS" ]] || echo "  Thanks to all contributors <3 ! ($CONTRIBUTORS)"
echo ""
echo " -- $ME <$EMAIL>  $(date -R)"
echo ""



# PR links can be converted to regular texts using : sed -E 's@\[(#[0-9]*)\]\([^ )]*\)@\1@g'
# Or readded with sed -E 's@#([0-9]*)@[YunoHost#\1](https://github.com/yunohost/yunohost/pull/\1)@g' | sed -E 's@\((\w+)\)@([YunoHost/\1](https://github.com/yunohost/yunohost/commit/\1))@g'
