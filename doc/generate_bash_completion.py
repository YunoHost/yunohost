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

import os

import yaml

THIS_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACTIONSMAP_FILE = THIS_SCRIPT_DIR + "/../share/actionsmap.yml"
BASH_COMPLETION_FOLDER = THIS_SCRIPT_DIR + "/bash_completion.d"
BASH_COMPLETION_FILE = BASH_COMPLETION_FOLDER + "/yunohost"


def get_dict_actions(OPTION_SUBTREE, category):
    ACTIONS = [
        action
        for action in OPTION_SUBTREE[category]["actions"].keys()
        if not action.startswith("_")
    ]
    ACTIONS_STR = "{}".format(" ".join(ACTIONS))

    DICT = {"actions_str": ACTIONS_STR}

    return DICT


with open(ACTIONSMAP_FILE, "r") as stream:
    # Getting the dictionary containning what actions are possible per category
    OPTION_TREE = yaml.safe_load(stream)

    CATEGORY = [
        category for category in OPTION_TREE.keys() if not category.startswith("_")
    ]

    CATEGORY_STR = "{}".format(" ".join(CATEGORY))
    ACTIONS_DICT = {}
    for category in CATEGORY:
        ACTIONS_DICT[category] = get_dict_actions(OPTION_TREE, category)

        ACTIONS_DICT[category]["subcategories"] = {}
        ACTIONS_DICT[category]["subcategories_str"] = ""

        if "subcategories" in OPTION_TREE[category].keys():
            SUBCATEGORIES = [
                subcategory
                for subcategory in OPTION_TREE[category]["subcategories"].keys()
            ]

            SUBCATEGORIES_STR = "{}".format(" ".join(SUBCATEGORIES))

            ACTIONS_DICT[category]["subcategories_str"] = SUBCATEGORIES_STR

            for subcategory in SUBCATEGORIES:
                ACTIONS_DICT[category]["subcategories"][subcategory] = get_dict_actions(
                    OPTION_TREE[category]["subcategories"], subcategory
                )

    os.makedirs(BASH_COMPLETION_FOLDER, exist_ok=True)

    with open(BASH_COMPLETION_FILE, "w") as generated_file:
        # header of the file
        generated_file.write("#\n")
        generated_file.write("# completion for yunohost\n")
        generated_file.write("# automatically generated from the actionsmap\n")
        generated_file.write("#\n\n")

        # Start of the completion function
        generated_file.write("_yunohost()\n")
        generated_file.write("{\n")

        # Defining local variable for previously and currently typed words
        generated_file.write("\tlocal cur prev opts narg\n")
        generated_file.write("\tCOMPREPLY=()\n\n")
        generated_file.write("\t# the number of words already typed\n")
        generated_file.write("\tnarg=${#COMP_WORDS[@]}\n\n")
        generated_file.write("\t# the current word being typed\n")
        generated_file.write('\tcur="${COMP_WORDS[COMP_CWORD]}"\n\n')

        # If one is currently typing a category then match with the category list
        generated_file.write("\t# If one is currently typing a category,\n")
        generated_file.write("\t# match with categorys\n")
        generated_file.write("\tif [[ $narg == 2 ]]; then\n")
        generated_file.write('\t\topts="{}"\n'.format(CATEGORY_STR))
        generated_file.write("\tfi\n\n")

        # If one is currently typing an action then match with the action list
        # of the previously typed category
        generated_file.write("\t# If one already typed a category,\n")
        generated_file.write(
            "\t# match the actions or the subcategories of that category\n"
        )
        generated_file.write("\tif [[ $narg == 3 ]]; then\n")
        generated_file.write("\t\t# the category typed\n")
        generated_file.write('\t\tcategory="${COMP_WORDS[1]}"\n\n')
        for category in CATEGORY:
            generated_file.write(
                '\t\tif [[ $category == "{}" ]]; then\n'.format(category)
            )
            generated_file.write(
                '\t\t\topts="{} {}"\n'.format(
                    ACTIONS_DICT[category]["actions_str"],
                    ACTIONS_DICT[category]["subcategories_str"],
                )
            )
            generated_file.write("\t\tfi\n")
        generated_file.write("\tfi\n\n")

        generated_file.write("\t# If one already typed an action or a subcategory,\n")
        generated_file.write("\t# match the actions of that subcategory\n")
        generated_file.write("\tif [[ $narg == 4 ]]; then\n")
        generated_file.write("\t\t# the category typed\n")
        generated_file.write('\t\tcategory="${COMP_WORDS[1]}"\n\n')
        generated_file.write("\t\t# the action or the subcategory typed\n")
        generated_file.write('\t\taction_or_subcategory="${COMP_WORDS[2]}"\n\n')
        for category in CATEGORY:
            if len(ACTIONS_DICT[category]["subcategories"]):
                generated_file.write(
                    '\t\tif [[ $category == "{}" ]]; then\n'.format(category)
                )
                for subcategory in ACTIONS_DICT[category]["subcategories"]:
                    generated_file.write(
                        '\t\t\tif [[ $action_or_subcategory == "{}" ]]; then\n'.format(
                            subcategory
                        )
                    )
                    generated_file.write(
                        '\t\t\t\topts="{}"\n'.format(
                            ACTIONS_DICT[category]["subcategories"][subcategory][
                                "actions_str"
                            ]
                        )
                    )
                    generated_file.write("\t\t\tfi\n")
                generated_file.write("\t\tfi\n")
        generated_file.write("\tfi\n\n")

        # If both category and action have been typed or the category
        # was not recognized propose --help (only once)
        generated_file.write("\t# If no options were found propose --help\n")
        generated_file.write('\tif [ -z "$opts" ]; then\n')
        generated_file.write('\t\tprev="${COMP_WORDS[COMP_CWORD-1]}"\n\n')
        generated_file.write('\t\tif [[ $prev != "--help" ]]; then\n')
        generated_file.write("\t\t\topts=( --help )\n")
        generated_file.write("\t\tfi\n")
        generated_file.write("\tfi\n")

        # generate the completion list from the possible options
        generated_file.write('\tCOMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )\n')
        generated_file.write("\treturn 0\n")
        generated_file.write("}\n\n")

        # Add the function to bash completion
        generated_file.write("complete -F _yunohost yunohost")
