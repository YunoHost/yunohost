import re

locale_folder = "locales/"
locale = open(locale_folder + "fr.json").read()

godamn_spaces_of_hell = ["\u00a0", "\u2000", "\u2001", "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009", "\u200A", "\u202f", "\u202F", "\u3000"]

transformations = {s: " " for s in godamn_spaces_of_hell}

transformations.update({
    "courriel": "email",
    "e-mail": "email",
    "Courriel": "Email",
    "E-mail": "Email",
    "« ": "'",
    "«": "'",
    " »": "'",
    "»": "'",
    "…": "...",
    "’": "'",
    #r"$(\w{1,2})'|( \w{1,2})'": r"\1\2’",
})

for pattern, replace in transformations.items():
    locale = re.compile(pattern).sub(replace, locale)

open(locale_folder + "fr.json", "w").write(locale)
