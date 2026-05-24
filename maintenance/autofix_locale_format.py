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

import re
import sys
import textwrap
from pathlib import Path

from babel.messages.catalog import Catalog
from babel.messages.pofile import read_po, write_po


def autofix_i18n_placeholders(
    reference: Catalog,
    catalog: Catalog,
) -> tuple[bool, Catalog]:
    """
    This tries for magically fix mismatch between en.po format and language.po format
    e.g. an i18n string with:
        source:   "Lorem ipsum {some_var}"
        fr:       "Lorem ipsum {une_variable}"
    (ie the keyword in {} was translated but shouldnt have been)
    """
    fatal_errors = False

    # We iterate over all keys/string in en.po
    for message in reference:
        # Ignore check if there's no translation yet for this key
        if (localemsg := catalog.get(message.id)) is None:
            continue
        localestring = localemsg.string
        assert isinstance(localestring, str)

        refstring = message.string
        assert isinstance(refstring, str)

        # Then we check that every "{stuff}" (for python's .format())
        # should also be in the translated string, otherwise the .format
        # will trigger an exception!
        subkeys_in_ref = [k[0] for k in re.findall(r"{(\w+)(:\w)?}", refstring)]
        subkeys_in_this_locale = [
            k[0] for k in re.findall(r"{(\w+)(:\w)?}", localestring)
        ]

        if set(subkeys_in_ref) != set(subkeys_in_this_locale) and (
            len(subkeys_in_ref) == len(subkeys_in_this_locale)
        ):
            for i, subkey in enumerate(subkeys_in_ref):
                localestring = localestring.replace(
                    f"{{{subkeys_in_this_locale[i]}}}",
                    f"{{{subkey}}}",
                )
            catalog.add(message.id, localestring)

        # Validate that now it's okay ?
        subkeys_in_ref = [k[0] for k in re.findall(r"{(\w+)(:\w)?}", refstring)]
        subkeys_in_this_locale = [
            k[0] for k in re.findall(r"{(\w+)(:\w)?}", localestring)
        ]
        if any(k not in subkeys_in_ref for k in subkeys_in_this_locale):
            errmsg = textwrap.dedent(f"""\
                ==========================
                Format inconsistency for string {message.id} in {catalog.locale}:
                {reference.locale} -> {refstring.encode("utf-8")}
                {catalog.locale} -> {localestring.encode("utf-8")}
                Please fix it manually !
                """)
            print(errmsg)
            fatal_errors = True

    return fatal_errors, catalog


def autofix_orthotypography_and_standardized_words(catalog: Catalog) -> Catalog:
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
    transformations_space = dict.fromkeys(godamn_spaces_of_hell, " ")

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
        "’": "'",  # noqa: RUF001
        # r"$(\w{1,2})'|( \w{1,2})'": r"\1\2’",  # noqa: RUF003
    }
    assert catalog.locale is not None
    match catalog.locale.language:
        case "en":
            transformations = transformations_space | transformations_misc
        case "fr":
            transformations = (
                transformations_space | transformations_misc | transformations_fr
            )
        case _:
            transformations = {}

    for message in catalog:
        newstring = message.string
        assert isinstance(newstring, str)
        for pattern, replace in transformations.items():
            newstring = re.sub(pattern, replace, newstring)
        if newstring != message.string:
            message.string = newstring
            catalog[message.id] = message
    return catalog


def main() -> None:
    project_dir: Path = Path(__file__).resolve().parent.parent
    locale_dir = project_dir / "po"

    reference_file = locale_dir / "en.po"
    locale_files = list(locale_dir.glob("*.po"))
    locale_files.remove(reference_file)

    reference = read_po(reference_file.open(), locale="en")
    fatal_errors = []

    for file in locale_files:
        catalog = read_po(file.open())

        catalog = autofix_orthotypography_and_standardized_words(catalog)
        errors, catalog = autofix_i18n_placeholders(reference, catalog)
        if errors:
            fatal_errors.append(file.name)

        write_po(file.open("wb"), catalog)

    if fatal_errors:
        print(f"Errors found in files: {', '.join(fatal_errors)}.")
        sys.exit(1)


if __name__ == "__main__":
    main()
