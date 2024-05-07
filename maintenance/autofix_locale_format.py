import os
import re
import json
import glob
from collections import OrderedDict

ROOT = os.path.dirname(__file__) + "/../"
LOCALE_FOLDER = ROOT + "/locales/"

# List all locale files (except en.json being the ref)
TRANSLATION_FILES = glob.glob(LOCALE_FOLDER + "*.json")
TRANSLATION_FILES = [filename.split("/")[-1] for filename in TRANSLATION_FILES]
print(LOCALE_FOLDER)
TRANSLATION_FILES.remove("en.json")

REFERENCE_FILE = LOCALE_FOLDER + "en.json"


def autofix_i18n_placeholders():
    def _autofix_i18n_placeholders(locale_file):
        """
        This tries for magically fix mismatch between en.json format and other.json format
        e.g. an i18n string with:
            source:   "Lorem ipsum {some_var}"
            fr:       "Lorem ipsum {une_variable}"
        (ie the keyword in {} was translated but shouldnt have been)
        """

        this_locale = json.loads(open(LOCALE_FOLDER + locale_file).read())
        fixed_stuff = False
        reference = json.loads(open(REFERENCE_FILE).read())

        # We iterate over all keys/string in en.json
        for key, string in reference.items():
            # Ignore check if there's no translation yet for this key
            if key not in this_locale:
                continue

            # Then we check that every "{stuff}" (for python's .format())
            # should also be in the translated string, otherwise the .format
            # will trigger an exception!
            subkeys_in_ref = [k[0] for k in re.findall(r"{(\w+)(:\w)?}", string)]
            subkeys_in_this_locale = [
                k[0] for k in re.findall(r"{(\w+)(:\w)?}", this_locale[key])
            ]

            if set(subkeys_in_ref) != set(subkeys_in_this_locale) and (
                len(subkeys_in_ref) == len(subkeys_in_this_locale)
            ):
                for i, subkey in enumerate(subkeys_in_ref):
                    this_locale[key] = this_locale[key].replace(
                        "{%s}" % subkeys_in_this_locale[i], "{%s}" % subkey
                    )
                    fixed_stuff = True

            # Validate that now it's okay ?
            subkeys_in_ref = [k[0] for k in re.findall(r"{(\w+)(:\w)?}", string)]
            subkeys_in_this_locale = [
                k[0] for k in re.findall(r"{(\w+)(:\w)?}", this_locale[key])
            ]
            if any(k not in subkeys_in_ref for k in subkeys_in_this_locale):
                raise Exception(
                    """\n
==========================
Format inconsistency for string {key} in {locale_file}:"
en.json   -> {string}
{locale_file}   -> {translated_string}
Please fix it manually !
    """.format(
                        key=key,
                        string=string.encode("utf-8"),
                        locale_file=locale_file,
                        translated_string=this_locale[key].encode("utf-8"),
                    )
                )

        if fixed_stuff:
            json.dump(
                this_locale,
                open(LOCALE_FOLDER + locale_file, "w"),
                indent=4,
                ensure_ascii=False,
            )

    for locale_file in TRANSLATION_FILES:
        _autofix_i18n_placeholders(locale_file)


def autofix_orthotypography_and_standardized_words():
    def reformat(lang, transformations):
        locale = open(f"{LOCALE_FOLDER}{lang}.json").read()
        for pattern, replace in transformations.items():
            locale = re.compile(pattern).sub(replace, locale)

        open(f"{LOCALE_FOLDER}{lang}.json", "w").write(locale)

    ######################################################

    godamn_spaces_of_hell = [
        "\u00a0",
        "\u2000",
        "\u2001",
        "\u2002",
        "\u2003",
        "\u2004",
        "\u2005",
        "\u2006",
        "\u2007",
        "\u2008",
        "\u2009",
        "\u200A",
        "\u202f",
        "\u202F",
        "\u3000",
    ]

    transformations = {s: " " for s in godamn_spaces_of_hell}
    transformations.update(
        {
            "\.\.\.": "…",
            "https ://": "https://",
        }
    )

    reformat("en", transformations)

    ######################################################

    transformations.update(
        {
            "courriel": "email",
            "e-mail": "email",
            "Courriel": "Email",
            "E-mail": "Email",
            "« ": "'",
            "«": "'",
            " »": "'",
            "»": "'",
            "’": "'",
            # r"$(\w{1,2})'|( \w{1,2})'": r"\1\2’",
        }
    )

    reformat("fr", transformations)


def remove_stale_translated_strings():
    reference = json.loads(open(LOCALE_FOLDER + "en.json").read())

    for locale_file in TRANSLATION_FILES:
        print(locale_file)
        this_locale = json.loads(
            open(LOCALE_FOLDER + locale_file).read(), object_pairs_hook=OrderedDict
        )
        this_locale_fixed = {k: v for k, v in this_locale.items() if k in reference}

        json.dump(
            this_locale_fixed,
            open(LOCALE_FOLDER + locale_file, "w"),
            indent=4,
            ensure_ascii=False,
        )


autofix_orthotypography_and_standardized_words()
remove_stale_translated_strings()
autofix_i18n_placeholders()
