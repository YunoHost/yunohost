#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
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

import toml
import yaml

"""
Set of jinja filter to improve the usage of Jinja when called from bash script with simple variable with string.
The main issue is that when called from bash we can't pass complex data structure and sometime we to iterate over
complexe data structure. Theses set of filters was made mainly to fix this issue and make it more natural the usage
of the variable in the templates.
"""


def from_json(value: str):
    """
    Load a string as Json and return an object
    """
    return json.loads(value)


def from_yaml(value: str):
    """
    Load a string as Yaml and return an object
    """
    return yaml.safe_load(value)


def from_toml(value: str):
    """
    Load a string as Toml and return an object
    """
    return toml.loads(value)


def to_json(value: object) -> str:
    """
    Serialize to string an object to Json
    """
    return json.dumps(value)


def to_yaml(value: object) -> str:
    """
    Serialize to string an object to Yaml
    """
    return yaml.safe_dump(value)


def to_toml(value) -> str:
    """
    Serialize to string an object to Toml
    """
    return toml.dumps(value)
