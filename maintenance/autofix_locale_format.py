#!/usr/bin/env python3
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

import json
import re
import sys
import textwrap
from collections import OrderedDict
from pathlib import Path

Locale = dict[str, str]


def autofix_i18n_placeholders(
    reference: Locale, locale: Locale, reference_filename: str, filename: str
) -> tuple[bool, Locale]:
    """
    This tries for magically fix mismatch between en.json format and other.json format
    e.g. an i18n string with:
        source:   "Lorem ipsum {some_var}"
        fr:       "Lorem ipsum {une_variable}"
    (ie the keyword in {} was translated but shouldnt have been)
    """
    fatal_errors = False

    # We iterate over all keys/string in en.json
    for key, string in reference.items():
        # Ignore check if there's no translation yet for this key
        if key not in locale:
            continue

        # Then we check that every "{stuff}" (for python's .format())
        # should also be in the translated string, otherwise the .format
        # will trigger an exception!
        subkeys_in_ref = [k[0] for k in re.findall(r"{(\w+)(:\w)?}", string)]
        subkeys_in_this_locale = [
            k[0] for k in re.findall(r"{(\w+)(:\w)?}", locale[key])
        ]

        if set(subkeys_in_ref) != set(subkeys_in_this_locale) and (
            len(subkeys_in_ref) == len(subkeys_in_this_locale)
        ):
            for i, subkey in enumerate(subkeys_in_ref):
                locale[key] = locale[key].replace(
                    "{%s}" % subkeys_in_this_locale[i], "{%s}" % subkey
                )

        # Validate that now it's okay ?
        subkeys_in_ref = [k[0] for k in re.findall(r"{(\w+)(:\w)?}", string)]
        subkeys_in_this_locale = [
            k[0] for k in re.findall(r"{(\w+)(:\w)?}", locale[key])
        ]
        if any(k not in subkeys_in_ref for k in subkeys_in_this_locale):
            errmsg = textwrap.dedent(f"""\
                ==========================
                Format inconsistency for string {key} in {filename}:
                {reference_filename} -> {string.encode("utf-8")}
                {filename} -> {locale[key].encode("utf-8")}
                Please fix it manually !
                """)
            print(errmsg)
            fatal_errors = True

    return fatal_errors, locale


def autofix_orthotypography_and_standardized_words(
    locale: Locale, filename: str
) -> Locale:
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
        "\u200a",
        # "\u202f",
        # "\u202F",
        "\u3000",
    ]
    transformations_space = {s: " " for s in godamn_spaces_of_hell}

    transformations_misc = {
        r"\.\.\.": "…",
        "https ://": "https://",
    }

    transformations_fr = {
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

    match filename:
        case "en.json":
            transformations = transformations_space | transformations_misc
        case "fr.json":
            transformations = (
                transformations_space | transformations_misc | transformations_fr
            )
        case _:
            transformations = {}

    for pattern, replace in transformations.items():
        for key, value in locale.items():
            locale[key] = re.sub(pattern, replace, value)
    return locale


def remove_stale_translated_strings(reference: Locale, locale: Locale) -> Locale:
    return {k: v for k, v in locale.items() if k in reference}


def sort_locale(locale: Locale) -> Locale:
    return dict(sorted(locale.items()))


def main() -> None:
    project_dir: Path = Path(__file__).resolve().parent.parent
    locale_dir = project_dir / "locales"

    reference_file = locale_dir / "en.json"
    locale_files = list(locale_dir.glob("*.json"))
    locale_files.remove(reference_file)

    reference = json.load(reference_file.open())
    fatal_errors = []

    for file in locale_files:
        locale = json.load(file.open(), object_pairs_hook=OrderedDict)

        locale = autofix_orthotypography_and_standardized_words(locale, file.name)
        locale = remove_stale_translated_strings(reference, locale)
        errors, locale = autofix_i18n_placeholders(
            reference, locale, reference_file.name, file.name
        )
        if errors:
            fatal_errors.append(file.name)

        # locale = sort_locale(locale)

        with file.open("w") as locale_io:
            json.dump(
                locale,
                locale_io,
                indent=4,
                ensure_ascii=False,
            )
            locale_io.write("\n")

    if fatal_errors:
        print(f"Errors found in files: {', '.join(fatal_errors)}.")
        sys.exit(1)


if __name__ == "__main__":
    main()
