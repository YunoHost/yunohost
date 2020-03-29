import re
import json
import glob

# List all locale files (except en.json being the ref)
locale_folder = "../locales/"
locale_files = glob.glob(locale_folder + "*.json")
locale_files = [filename.split("/")[-1] for filename in locale_files]
locale_files.remove("en.json")

reference = json.loads(open(locale_folder + "en.json").read())

found_inconsistencies = False

# Let's iterate over each locale file
for locale_file in locale_files:

    this_locale = json.loads(open(locale_folder + locale_file).read())

    # We iterate over all keys/string in en.json
    for key, string in reference.items():
        # If there is a translation available for this key/string
        if key in this_locale:

            # Then we check that every "{stuff}" (for python's .format())
            # should also be in the translated string, otherwise the .format
            # will trigger an exception!
            subkeys_in_ref = set(k[0] for k in re.findall(r"{(\w+)(:\w)?}", string))
            subkeys_in_this_locale = set(k[0] for k in re.findall(r"{(\w+)(:\w)?}", this_locale[key]))

            if any(key not in subkeys_in_ref for key in subkeys_in_this_locale):
                found_inconsistencies = True
                print("\n")
                print("==========================")
                print("Format inconsistency for string %s in %s:" % (key, locale_file))
                print("%s   -> %s " % ("en.json", string))
                print("%s   -> %s " % (locale_file, this_locale[key]))

if found_inconsistencies:
    sys.exit(1)
