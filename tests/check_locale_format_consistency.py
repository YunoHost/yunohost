import re
import json
import glob

locale_folder = "../locales/"
locale_files = glob.glob(locale_folder + "*.json")
locale_files = [filename.split("/")[-1] for filename in locale_files]
locale_files.remove("en.json")

reference = json.loads(open(locale_folder + "en.json").read())

for locale_file in locale_files:

    this_locale = json.loads(open(locale_folder + locale_file).read())

    for key, string in reference.items():
        if key in this_locale:

            subkeys_in_ref = set(k[0] for k in re.findall(r"{(\w+)(:\w)?}", string))
            subkeys_in_this_locale = set(k[0] for k in re.findall(r"{(\w+)(:\w)?}", this_locale[key]))

            if any(key not in subkeys_in_ref for key in subkeys_in_this_locale):
                print("\n")
                print("==========================")
                print("Format inconsistency for string %s in %s:" % (key, locale_file))
                print("%s   -> %s " % ("en.json", string))
                print("%s   -> %s " % (locale_file, this_locale[key]))

