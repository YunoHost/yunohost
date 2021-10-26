import re
import json
import glob
import pytest

# List all locale files (except en.json being the ref)
locale_folder = "locales/"
locale_files = glob.glob(locale_folder + "*.json")
locale_files = [filename.split("/")[-1] for filename in locale_files]
locale_files.remove("en.json")

reference = json.loads(open(locale_folder + "en.json").read())


def find_inconsistencies(locale_file):

    this_locale = json.loads(open(locale_folder + locale_file).read())

    # We iterate over all keys/string in en.json
    for key, string in reference.items():

        # Ignore check if there's no translation yet for this key
        if key not in this_locale:
            continue

        # Then we check that every "{stuff}" (for python's .format())
        # should also be in the translated string, otherwise the .format
        # will trigger an exception!
        subkeys_in_ref = set(k[0] for k in re.findall(r"{(\w+)(:\w)?}", string))
        subkeys_in_this_locale = set(
            k[0] for k in re.findall(r"{(\w+)(:\w)?}", this_locale[key])
        )

        if any(k not in subkeys_in_ref for k in subkeys_in_this_locale):
            yield """\n
==========================
Format inconsistency for string {key} in {locale_file}:"
en.json   -> {string}
{locale_file}   -> {translated_string}
""".format(
                key=key,
                string=string.encode("utf-8"),
                locale_file=locale_file,
                translated_string=this_locale[key].encode("utf-8"),
            )


@pytest.mark.parametrize("locale_file", locale_files)
def test_translation_format_consistency(locale_file):
    inconsistencies = list(find_inconsistencies(locale_file))
    if inconsistencies:
        raise Exception("".join(inconsistencies))
