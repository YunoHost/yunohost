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

"""
Simple automated generation of a bash_completion file
for yunohost command from the actionsmap.

Generates a bash completion file assuming the structure
`yunohost category action`
adds `--help` at the end if one presses [tab] again.

author: Christophe Vuillot
"""

import argparse
import datetime
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Template

YUNOHOST_SRCDIR = Path(__file__).resolve().parent.parent


def render(actions: dict[str, Any]) -> str:
    template_file = YUNOHOST_SRCDIR / "doc" / "bash_completion.sh.j2"
    template = Template(template_file.read_text(), comment_start_string="auieauieauie")

    result = template.render(
        categories=actions,
    )
    return result


def get_actions() -> dict[str, Any]:
    actionsmap = YUNOHOST_SRCDIR / "share" / "actionsmap.yml"
    categories = yaml.safe_load(actionsmap.open())

    fullmap: dict[str, Any] = {}

    for category, cat_info in categories.items():
        if category.startswith("_"):
            continue
        fullmap[category] = {}
        fullmap[category]["actions"] = []
        fullmap[category]["subs"] = {}

        for action, _ in cat_info.get("actions", {}).items():
            fullmap[category]["actions"].append(action)

        for subcat, sub_info in cat_info.get("subcategories", {}).items():
            fullmap[category]["subs"][subcat] = list(sub_info["actions"].keys())

    return fullmap


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args()

    actions = get_actions()
    result = render(actions)

    args.output.write_text(result)


if __name__ == "__main__":
    main()
