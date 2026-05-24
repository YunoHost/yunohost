#!/usr/bin/env python3

import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
LOCALES_DIR = PROJECT_ROOT / "locales"
GETTEXT_DIR = PROJECT_ROOT / "po"


def main() -> None:
    GETTEXT_DIR.mkdir(exist_ok=True)

    pot = GETTEXT_DIR / "yunohost.pot"
    subprocess.check_call([str(GETTEXT_DIR / "update_pot"), "-o", pot])

    locales = []

    for jsonfile in LOCALES_DIR.glob("*.json"):
        locale = jsonfile.name.removesuffix(".json")
        locales.append(locale)
        data = json.load(jsonfile.open())
        po = GETTEXT_DIR / f"{locale}.po"
        po.unlink(missing_ok=True)
        subprocess.check_call(
            [
                "msginit",
                "--input",
                str(pot),
                "--output",
                str(po),
                "--locale",
                locale,
                "--no-translator",
            ]
        )
        polines = po.read_text().splitlines()

        for msgid, translation in data.items():
            if msgid == "admin_password":
                continue
            try:
                msgid_line = next(
                    number
                    for number, line in enumerate(polines)
                    if line == f'msgid "{msgid}"'
                )
            except StopIteration:
                raise RuntimeError(f"Could not find msgid {msgid}")
            translation = (
                translation.replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace('"', '\\"')
            )
            polines[msgid_line + 1] = f'msgstr "{translation}"'

        po.write_text("\n".join(polines))

    subprocess.check_call(["po/update_po"])

    linguas = GETTEXT_DIR / "LINGUAS"
    linguas.write_text("\n".join(locales) + "\n")


if __name__ == "__main__":
    main()
