import re
import json
import glob

# List all locale files (except en.json being the ref)
locale_folder = "../locales/"
locale_files = glob.glob(locale_folder + "*.json")
locale_files = [filename.split("/")[-1] for filename in locale_files]
locale_files.remove("en.json")

reference = json.loads(open(locale_folder + "en.json").read())


def fix_locale(locale_file):

    this_locale = json.loads(open(locale_folder + locale_file).read())
    fixed_stuff = False

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

    if fixed_stuff:
        json.dump(
            this_locale,
            open(locale_folder + locale_file, "w"),
            indent=4,
            ensure_ascii=False,
        )


for locale_file in locale_files:
    fix_locale(locale_file)
