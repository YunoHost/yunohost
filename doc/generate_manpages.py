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

import os
import yaml
import gzip
import argparse

from datetime import date
from collections import OrderedDict

from jinja2 import Template

base_path = os.path.split(os.path.realpath(__file__))[0]

template = Template(open(os.path.join(base_path, "manpage.template")).read())


THIS_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACTIONSMAP_FILE = os.path.join(THIS_SCRIPT_DIR, "../share/actionsmap.yml")


def ordered_yaml_load(stream):
    class OrderedLoader(yaml.SafeLoader):
        pass

    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        lambda loader, node: OrderedDict(loader.construct_pairs(node)),
    )
    return yaml.load(stream, OrderedLoader)


def main():
    parser = argparse.ArgumentParser(
        description="generate yunohost manpage based on actionsmap.yml"
    )
    parser.add_argument("-o", "--output", default="output/yunohost")
    parser.add_argument("-z", "--gzip", action="store_true", default=False)

    args = parser.parse_args()

    if os.path.isdir(args.output):
        if not os.path.exists(args.output):
            os.makedirs(args.output)

        output_path = os.path.join(args.output, "yunohost")
    else:
        output_dir = os.path.split(args.output)[0]

        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        output_path = args.output

    # man pages of "yunohost *"
    with open(ACTIONSMAP_FILE, "r") as actionsmap:
        # Getting the dictionary containning what actions are possible per domain
        actionsmap = ordered_yaml_load(actionsmap)

        for i in list(actionsmap.keys()):
            if i.startswith("_"):
                del actionsmap[i]

        today = date.today()

        result = template.render(
            month=today.strftime("%B"),
            year=today.year,
            categories=actionsmap,
            str=str,
        )

        if not args.gzip:
            with open(output_path, "w") as output:
                output.write(result)
        else:
            with gzip.open(output_path, mode="w", compresslevel=9) as output:
                output.write(result.encode())


if __name__ == "__main__":
    main()
