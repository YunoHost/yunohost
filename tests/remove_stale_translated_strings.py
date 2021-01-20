import json
import glob
from collections import OrderedDict

locale_folder = "../locales/"
locale_files = glob.glob(locale_folder + "*.json")
locale_files = [filename.split("/")[-1] for filename in locale_files]
locale_files.remove("en.json")

reference = json.loads(open(locale_folder + "en.json").read())

for locale_file in locale_files:

    print(locale_file)
    this_locale = json.loads(
        open(locale_folder + locale_file).read(), object_pairs_hook=OrderedDict
    )
    this_locale_fixed = {k: v for k, v in this_locale.items() if k in reference}

    json.dump(
        this_locale_fixed,
        open(locale_folder + locale_file, "w"),
        indent=4,
        ensure_ascii=False,
    )
