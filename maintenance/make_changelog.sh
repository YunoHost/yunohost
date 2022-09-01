VERSION="?"
RELEASE="testing"
REPO=$(basename $(git rev-parse --show-toplevel))
REPO_URL=$(git remote get-url origin)
ME=$(git config --global --get user.name)
EMAIL=$(git config --global --get user.email)

LAST_RELEASE=$(git tag --list 'debian/11.*' | tail -n 1)

echo "$REPO ($VERSION) $RELEASE; urgency=low"
echo ""

git log $LAST_RELEASE.. -n 10000 --first-parent --pretty=tformat:'  - %b%s (%h)' \
| sed -E "s&Merge .*#([0-9]+).*\$& \([#\1]\($REPO_URL/pull/\1\)\)&g" \
| grep -v "Translations update from Weblate" \
| tac

TRANSLATIONS=$(git log $LAST_RELEASE... -n 10000 --pretty=format:"%s"  \
               | grep "Translated using Weblate" \
               | sed -E "s/Translated using Weblate \((.*)\)/\1/g"  \
               | sort | uniq | tr '\n' ', ' | sed -e 's/,$//g' -e 's/,/, /g')
[[ -z "$TRANSLATIONS" ]] || echo "  - [i18n] Translations updated for $TRANSLATIONS"

echo ""
CONTRIBUTORS=$(git logc $LAST_RELEASE... -n 10000 --pretty=format:"%an" \
               | sort | uniq  | grep -v "$ME" \
               | tr '\n' ', ' | sed -e 's/,$//g' -e 's/,/, /g')
[[ -z "$CONTRIBUTORS" ]] || echo "  Thanks to all contributors <3 ! ($CONTRIBUTORS)"
echo ""
echo " -- $ME <$EMAIL>  $(date -R)"
echo ""



# PR links can be converted to regular texts using : sed -E 's@\[(#[0-9]*)\]\([^ )]*\)@\1@g'
# Or readded with sed -E 's@#([0-9]*)@[YunoHost#\1](https://github.com/yunohost/yunohost/pull/\1)@g' | sed -E 's@\((\w+)\)@([YunoHost/\1](https://github.com/yunohost/yunohost/commit/\1))@g'
