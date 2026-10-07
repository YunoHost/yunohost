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
Inspired by yunohost_completion.py (author: Christophe Vuillot)
=======

This script generates man pages for yunohost.
Pages are stored in OUTPUT_DIR
"""

import argparse
import datetime
import gzip
from collections import OrderedDict
from pathlib import Path
from typing import Any, TextIO

import yaml
from jinja2 import Template

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_FILE = PROJECT_ROOT / "doc" / "manpage.template"
ACTIONSMAP_FILE = PROJECT_ROOT / "share" / "actionsmap.yml"


def ordered_yaml_load(stream: TextIO) -> dict[str, Any]:
    class OrderedLoader(yaml.SafeLoader):
        pass

    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        lambda loader, node: OrderedDict(loader.construct_pairs(node)),
    )
    return yaml.load(stream, OrderedLoader)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="generate yunohost manpage based on actionsmap.yml"
    )
    parser.add_argument("-o", "--output", type=Path, default="output/yunohost")
    parser.add_argument("-z", "--gzip", action="store_true", default=False)
    args = parser.parse_args()

    if args.output.is_dir():
        output_path: Path = args.output / "yunohost"
    else:
        output_path = args.output
    args.output.parent.mkdir(exist_ok=True)

    # Getting the dictionary containning what actions are possible per domain
    actionsmap = ordered_yaml_load(ACTIONSMAP_FILE.open())

    for i in list(actionsmap.keys()):
        if i.startswith("_"):
            del actionsmap[i]

    today = datetime.datetime.now(tz=datetime.UTC).date()

    template = Template(TEMPLATE_FILE.read_text())
    result = template.render(
        month=today.strftime("%B"),
        year=today.year,
        categories=actionsmap,
        str=str,
    )

    if not args.gzip:
        output_path.write_text(result)
    else:
        with gzip.open(output_path, mode="w", compresslevel=9) as output:
            output.write(result.encode())


if __name__ == "__main__":
    main()
