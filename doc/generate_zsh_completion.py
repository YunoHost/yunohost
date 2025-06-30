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

"""Automated generation of a zsh_completion file for yunohost.

Using the actionsmap yaml file and a jinja template.

INSTALL:
  This script creates a zsh completion file for yunohost.
  To install, copy (and rename) the created file to:
    - (Debian) `/usr/share/zsh/vendor-completions/_yunohost`
    - (Fedora) `/usr/share/zsh/site-functions/_yunohost`
    - (other distribution) `/usr/local/share/zsh/site-functions/_yunohost`

DOCS:
- https://github.com/zsh-users/zsh/blob/master/Etc/completion-style-guide
- http://zsh.sourceforge.net/Doc/Release/Completion-System.html#Completion-System
  or `man zshcompsys`
- http://zsh.sourceforge.net/Guide/zshguide06.html

MISC:
- http://zsh.sourceforge.net/Doc/Release/Parameters.html#Array-Parameters

MISSING:
- use the extra:required:True pattern (similar to `nargs`?)
- In `yunohost.yml`, consider merging:
  - metavar
  - pattern
  - autocomplete
- Make use of `type`, maybe using `_guard`
- Use `pattern`, maybe with `_guard`. This seems hard though, as ZSH has
its own globbing language...
Link about this globbing system:
http://zsh.sourceforge.net/Doc/Release/Expansion.html#Filename-Generation

Notes:
- Command for debugging zsh: `unfunction _yunohost; autoload -U _yunohost`

- Optimization:
  - caching mecanism: invalidate the cache afer some commands? Hard, the
  cache is local to user
  - implement a zstyle switch, to change the cache validity period?

AUTHORS:
 - buzuck (Fol)
 - kayou
 - getzze

"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml
from jinja2 import Template

if TYPE_CHECKING:
    from typing import NotRequired, TypedDict

    class Function(TypedDict):
        """Details of a helper function."""

        name: str
        shell_call: NotRequired[str]
        aggregated: NotRequired[str]

    class Case(TypedDict):
        """Details of dynamic argument completion function."""

        name: str
        shell_call: str

    class Action(TypedDict):
        """Command line action."""

        name: str
        help: str
        arguments: list[str]
        cases: list[Case]

    class Category(TypedDict):
        """Command line category.

        Categories have different level:
         - level 1: main category, e.g. `yunohost user`
         - level 2: sub-category, e.g. `yunohost user group`

        Only categories of level 1 have a `subs` key.

        Reminder:
            yunohost     user        group       list    --full --short
               ^          ^            ^          ^
            (script) | category | subcategory | action | parameters

        """

        name: str
        help: str
        level: int
        actions: list[Action]
        subs: NotRequired[dict[str, str]]


YUNOHOST_SRCDIR = Path(__file__).resolve().parent.parent


def get_actions_zsh(
    ynh_map: dict[str, dict[str, Any]],
) -> tuple[list[Category], list[Function]]:
    """Parse categories, subcategories and actions from an actionsmap yml file.

    Parameters
    ----------
    ynh_map: dict[str, dict[str, Any]]
        A dict loaded from an actionsmap yml file.

    Returns
    -------
    tuple[list[Category], list[Function]]
        A tuple of categories dict and helper functions dict.

    """
    categories: list[Category] = []
    functions: list[Function] = []

    for category, cat_info in ynh_map.items():
        if category.startswith("_") or cat_info.get("hide_in_help", False):
            continue

        cats, funcs = parse_category(category, cat_info)

        categories.extend(cats)
        functions.extend(funcs)

    # Remove duplicates in functions
    functions = [
        cast("Function", dict(t)) for t in {tuple(d.items()) for d in functions}
    ]

    return categories, functions


def parse_category(
    name: str,
    info: dict[str, Any],
) -> tuple[list[Category], list[Function]]:
    """Parse a Category  (level 1) for its actions and subcategories.

    Reminder:
        yunohost   monitor    info    --cpu --ram
           ^          ^         ^          ^
        (script) | category | action | parameters

    A Category may contain subcategories (of level 2), so a list of categories
    (of level 1 and 2) is returned.
    A category may need to define help functions that are needed to build
    the list of options. The list of help functions is returned.

    Parameters
    ----------
    name: str
        the category name
    info: dict[str, Any]
        the information dict about the category

    Returns
    -------
    tuple[list[Category], list[Function]]
        A tuple of the list of category and subcategories dicts
        and the list of category and subcategories helper functions.

    """
    cat: Category = {
        "name": name,
        "level": 1,
        "help": _escape(info.get("category_help", "")),
        "actions": [],
        "subs": {},
    }
    # Add the category first, the subcategories will be appended later
    categories: list[Category] = [cat]
    functions: list[Function] = []

    # Parse actions (before subcategories)
    actions = []
    for action, action_info in info.get("actions", {}).items():
        if action_info.get("hide_in_help", False):
            continue

        act, funcs = parse_actions(action, action_info)
        actions.append(act)
        functions.extend(funcs)
    cat["actions"] = actions

    # Parse subcategories
    subs = {}
    for subcategory, subcategory_info in info.get("subcategories", {}).items():
        if subcategory.startswith("_") or subcategory_info.get("hide_in_help", False):
            continue

        help, subcategory_dict, funcs = parse_subcategory(  # noqa: A001
            name,
            subcategory,
            subcategory_info,
        )
        subs[subcategory] = help
        functions.extend(funcs)
        # Append subcategory below the category
        categories.append(subcategory_dict)
    # Add the list of subcategories to the category
    cat["subs"] = subs

    return categories, functions


def parse_subcategory(
    category: str,
    name: str,
    info: dict[str, Any],
) -> tuple[str, Category, list[Function]]:
    """Parse a sub-category (level 2) for its actions.

    Reminder:
        yunohost     user        group       list    --full --short
           ^          ^            ^          ^
        (script) | category | subcategory | action | parameters

    A subcategory is treated as a Category (of level 2), with an 'actions' key,
    but no 'subs' key.
    The help text of the subcategory is needed to construct the 'subs' dict
    of the parent category.
    Like a level-1 category, subcategories may need to define help functions.
    The list of help functions is returned.

    Parameters
    ----------
    category: str
        the name of the parent category
    name: str
        the subcategory name
    info: dict[str, Any]
        the information dict about the subcategory

    Returns
    -------
    tuple[str, Category, list[Function]]
        A tuple of the subcategory help text, the subcategory dict
        and the list of subcategory helper functions.

    """
    full_name = f"{category}_{name}"
    help = _escape(info.get("subcategory_help", ""))  # noqa: A001

    subcat: Category = {"name": full_name, "level": 2, "help": help, "actions": []}
    functions: list[Function] = []

    # Parse actions (before subcategories)
    actions = []
    for action, action_info in info.get("actions", {}).items():
        if action_info.get("hide_in_help", False):
            continue

        act, funcs = parse_actions(action, action_info)
        actions.append(act)
        functions.extend(funcs)
    subcat["actions"] = actions

    return help, subcat, functions


def parse_actions(
    name: str,
    info: dict[str, Any],
) -> tuple[Action, list[Function]]:
    """Parse an Action for it's help text and arguments.

    Returns
    -------
    tuple[Action, list[Function]]
        A tuple of the action dict and the list of action helper functions.

    """
    functions: list[Function] = []

    # This is a counter, in case of position dependent paremeters (the ones not
    # beginning with a `-`)
    position = 0

    arguments: list[str] = []
    cases: list[Case] = []

    for _argument_name, argument_info in info.get("arguments", {}).items():
        #
        # Forcing to str, as the yaml parser inteprets numbers as integers
        # (eg.: `firewall allow... -4`)
        argument_name = str(_argument_name)
        case: Case | None = None
        funcs: list[Function] = []

        #
        # This is an optional parameter, beginning with a `-`
        if argument_name.startswith("-"):
            full_argument, case, funcs = parse_argument_optional(
                argument_name,
                argument_info,
            )
        #
        # A parameter not beginning with `-` is considered mandatory.
        else:
            position += 1
            full_argument, case, funcs = parse_argument_mandatory(
                argument_name,
                argument_info,
                position,
            )

        # If action is None, do not display the parameter
        if not full_argument:
            continue

        # If case is not None, add a case below the arguments list
        if case:
            cases.append(case)

        # Add helper functions
        functions.extend(funcs)

        # Append argument
        arguments.append(full_argument)

    help = _escape(info.get("action_help", ""))  # noqa: A001
    action_dict: Action = {
        "name": name,
        "help": help,
        "arguments": arguments,
        "cases": cases,
    }
    return action_dict, functions


def parse_argument_mandatory(
    name: str,
    info: dict[str, Any],
    position: int = 0,
) -> tuple[str, Case | None, list[Function]]:
    """Parse a mandatory argument."""
    #
    # Initializing the argument dict to make sure all fields are defined
    # - id: identifier (`-n` or `--name`). If none (e.g. `ynh app install
    # APP_NAME`), this field is the arguments position or cardinality (from
    # `nargs`)
    # - excludes: usually the argument itself. Only used for optional args
    # - desc: the argument description
    # - completion: the completion function name
    #
    arg = {"excludes": "", "spec": "", "desc": "", "mess": "", "action": "", "func": ""}

    #
    # Generation of the completion hints
    #
    arg["action"], case, functions = parse_argument_action(name, info)

    # Hidden argument
    if arg["action"] is None:
        return ("", None, [])

    # This parameter may be used more than once, else we use the position counter
    if info.get("nargs", "") in ["+", "*"]:
        if info["nargs"] == "+":
            arg["spec"] = f"'{{{position!s},*}}'"
        else:  # argument_details["nargs"] == "*":
            arg["spec"] = "*"
    else:
        arg["spec"] = str(position)
    arg["mess"] = info.get("help", name)

    #
    # If defined, add the default value as a hint
    if "default" in info:
        arg["mess"] += f" (default: {info['default']})"
    # Escape special character in the description
    arg["mess"] = _escape(arg["mess"])

    # ----
    # NOTE: a double colon marks for an optional argument:
    #     ::Username to update:__ynh_user_list
    # ----
    placeholder = "'{}{}{}:{}:{}'"

    # Escape special character in the description
    arg["desc"] = _escape(arg["desc"])
    argument = placeholder.format(
        arg["excludes"],
        arg["spec"],
        arg["desc"],
        arg["mess"],
        arg["action"],
    )
    return (argument, case, functions)


def parse_argument_optional(
    name: str,
    info: dict[str, Any],
) -> tuple[str, Case | None, list[Function]]:
    """Parse an optional argument."""
    #
    # Initializing the argument dict to make sure all fields are defined
    # - id: identifier (`-n` or `--name`). If none (e.g. `ynh app install
    # APP_NAME`), this field is the arguments position or cardinality (from
    # `nargs`)
    # - excludes: usually the argument itself. Only used for optional args
    # - desc: the argument description
    # - completion: the completion function name
    #
    arg = {"excludes": "", "spec": "", "desc": "", "mess": "", "action": "", "func": ""}

    #
    # Generation of the completion hints
    #
    arg["action"], case, functions = parse_argument_action(name, info)

    # Hidden argument
    if arg["action"] is None:
        return ("", None, [])

    # `full` is the extended form of the argument (e.g.: -n is short for --number)
    if "full" in info:
        full_name = info["full"]
        arg["mess"] = str(full_name).lstrip("-")
        arg["spec"] = f"'{{{name},{full_name}}}'"
        arg["excludes"] = f"({name} {full_name})"
    else:
        arg["mess"] = str(name).lstrip("-")
        arg["spec"] = name
    # Escape special character in the description
    arg["mess"] = _escape(arg["mess"])

    # The description of the parameter
    # Getting the `help` field if any, else simply by using it's name
    help = info.get("help", arg["mess"])  # noqa: A001
    arg["desc"] = f"[{help}]"

    has_action = True
    # Add a pattern field to match multiple arguments
    if info.get("nargs", "") in ["+", "*"]:
        if arg["excludes"]:
            # suppose that `arg["excludes"] = (-f --foo)`
            arg["excludes"] = "(* " + arg["excludes"][1:]
        else:
            arg["excludes"] = "(*)"
        arg["mess"] = "*:" + arg["mess"]
        has_action = True

    # Options without arguments should skip the message and action fields
    elif info.get("action", "").startswith("store_"):
        has_action = False

    # Place holder for the parameters
    placeholder = "'{}{}{}:{}:{}'" if has_action else "'{}{}{}'"
    # Escape special character in the description
    arg["desc"] = _escape(arg["desc"])
    argument = placeholder.format(
        arg["excludes"],
        arg["spec"],
        arg["desc"],
        arg["mess"],
        arg["action"],
    )
    return (argument, case, functions)


def parse_argument_action(  # noqa: C901, PLR0911, PLR0912
    name: str,
    info: dict[str, Any],
) -> tuple[str, Case | None, list[Function]]:
    """Parse an argument action."""
    functions: list[Function] = []
    #
    # Finds the completion function for the given argument, if defined.
    #
    # `functions` hold the elements needed to generate it.  The
    # actual creation of this function will be done by build_completion_functions(),
    # called near the end of this script.
    # `choices` and `autocomplete` should not be present at the same time
    # (`choices` takes precedence)

    #
    # A list of choices is defined
    if "choices" in info:
        all_choices = " ".join(info["choices"])
        action = f"({all_choices})"
        return (action, None, functions)

    #
    # Look for an autocompletion function, but it is not defined
    if "extra" not in info or "autocomplete" not in info["extra"]:
        return ("", None, functions)

    #
    # An autocompletion function is defined
    autocomplete = info["extra"]["autocomplete"]

    #
    # Check if the argument should be hidden (API only)
    if autocomplete.get("hide_in_help", False):
        return ("", None, functions)

    #
    # This is a combinaision of YunoHost and jq commands
    #
    if "ynh_selector" in autocomplete and "jq_selector" in autocomplete:
        #
        # Function dependent on previous arguments
        #
        if "depends" in autocomplete and autocomplete["depends"] == "previous":
            # Create cases that depend on the previous argument.
            #
            # First, build the shell command that returns the completions
            call = (
                f"sudo yunohost {autocomplete['ynh_selector']} "
                f'"${{previous}}" --output-as json '
                f"| jq -cr '{autocomplete['jq_selector']}' | xargs"
            )
            # If a cache is needed, wrap the call in the caching function
            if autocomplete.get("use_cache", False):
                call = '__get_ynh_cache YNH_{}_"${{previous}}" "{}"'.format(
                    _norm_name(autocomplete["ynh_selector"]),
                    # Remove the double-quote in "{previous}"
                    # because the whole cmd will be encased in quotes.
                    call.replace('"', ""),
                )

            function_name = f"->{name}"
            case: Case = {"name": name, "shell_call": call}
            return (function_name, case, functions)

        # Create this function's name
        function_name = _remove_special_chars(
            "__ynh_" + _norm_name(autocomplete["ynh_selector"]),
        )
        #
        # Add a helper function
        #
        # First, build the shell command that returns the completions
        call = "sudo yunohost {} --output-as json | jq -cr '{}'".format(
            autocomplete["ynh_selector"],
            autocomplete["jq_selector"],
        )
        # If a cache is needed, wrap the call in the caching function
        if autocomplete.get("use_cache", False):
            call = "__get_ynh_cache 'YNH_{}' \"{}\"".format(
                _norm_name(autocomplete["ynh_selector"]),
                call,
            )
        # Lastly, save the content
        func: Function = {"name": function_name, "shell_call": call}
        functions.append(func)
        return (function_name, None, functions)

    #
    # The autocompletion is done by a grep
    #
    if "shell_call" in autocomplete:
        # Create this function's name
        function_name = _remove_special_chars(
            "__ynh_" + _norm_name(autocomplete["shell_call"]),
        )
        #
        # Add a helper function
        #
        # First, build the shell command that returns the completions
        call = autocomplete["shell_call"]

        # If a cache is needed, wrap the call in the caching function
        # Note: not tested with grep, only with YunoHost's commands
        if autocomplete.get("use_cache", False):
            call = "__get_ynh_cache 'YNH_{}' \"{}\"".format(
                _remove_special_chars(autocomplete["shell_call"]),
                call,
            )
        # Lastly, save the content
        func = {"name": function_name, "shell_call": call}
        functions.append(func)
        return (function_name, None, functions)

    #
    # This is a combinaision of two other completion functions
    #
    if "aggregate" in autocomplete:
        # Create this function's name
        function_name = "__ynh"
        for subcall in autocomplete["aggregate"]:
            if "ynh_selector" in subcall:
                function_name += "_" + _norm_name(subcall["ynh_selector"])

        #
        # Add a helper function
        aggregation = ""
        for subcall in autocomplete["aggregate"]:
            if "name" in subcall and "ynh_selector" in subcall:
                aggregation += "\n'{}:{}:{}' \\".format(
                    subcall["name"],
                    subcall["name"],
                    _norm_name("__ynh_" + subcall["ynh_selector"]),
                )
        # Lastly, save the content
        func = {"name": function_name, "aggregated": aggregation}
        functions.append(func)
        return (function_name, None, functions)

    #
    # The autocompletion is done by a ZSH function
    #
    if "zsh_completion" in autocomplete:
        return (autocomplete["zsh_completion"], None, functions)

    #
    # No autocompletion schema was defined
    #
    return ("", None, functions)


def render_zsh(categories: list[Category], functions: list[Function]) -> str:
    """Render the jinja template with the parsed categories and helper functions."""
    template_file = YUNOHOST_SRCDIR / "doc" / "_zsh_completion.j2"
    template = Template(
        template_file.read_text(),
        keep_trailing_newline=True,
        comment_start_string="auieauieauie",
    )

    return template.render(
        categories=categories,
        functions=functions,
    )


#
# Utility functions, mainly string manipulation
#


def _norm_name(string: str) -> str:
    """Normalize a string to make it look like a function name.

    Apply the transformations:
      - lowercase
      - spaces replaced by underscores
      - no dashs

    :param str string: the string to norm.
    :return str: The normed string
    """
    return (
        string.lower()
        .replace(" ", "_")
        .replace("-", "")
        .replace("/", "_")
        .replace(".", "_")
    )


def _escape(string: str) -> str:
    r"""Escape any special character.

    Escape the characters:
      - single quotes (') are put in a separate double quoted string ('"'"')
      - colons (:) and other characters are preceded by a backslash (\:)

    :param str string: The string to escape
    :return str: The escaped string
    """
    return string.replace("'", "'\"'\"'").replace(":", r"\:")


def _remove_special_chars(string: str) -> str:
    """Remove any character with a special meaning in ZSH.

    Example of characters to remove:
        `$`, `{`, `(`, `[`, ...

    :param str string: The string to clean
    :return str: The cleaned string
    """
    # NOTE: this list may not be comprehensive and should be extended if needed
    return re.sub(r'[- =\^+:\?\'"$(){}\[\]/\\\\]', "", string).replace(".", "")


#
# Get action map
#


def get_action_map() -> dict[str, Any]:
    """Load the actionmap from a YAML file."""
    actionsmap = YUNOHOST_SRCDIR / "share" / "actionsmap.yml"
    return cast("dict[str, Any]", yaml.safe_load(actionsmap.open()))


def main() -> None:
    """Generate the completion file for Zsh."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", "-o", type=Path, required=True)

    args = parser.parse_args()

    yunohost_map = get_action_map()

    categories, functions = get_actions_zsh(yunohost_map)
    result = render_zsh(categories, functions)

    args.output.write_text(result)


if __name__ == "__main__":
    main()
