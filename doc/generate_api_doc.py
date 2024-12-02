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
    Generate JSON specification files API
"""
import os
import sys
import yaml
import json


def main():
    with open("../share/actionsmap.yml") as f:
        action_map = yaml.safe_load(f)

    # try:
    #    with open("/etc/yunohost/current_host", "r") as f:
    #        domain = f.readline().rstrip()
    # except IOError:
    #    domain = requests.get("http://ip.yunohost.org").text

    with open("../debian/changelog") as f:
        top_changelog = f.readline()
    api_version = top_changelog[top_changelog.find("(") + 1 : top_changelog.find(")")]

    csrf = {
        "name": "X-Requested-With",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "default": "Swagger API"},
    }

    resource_list = {
        "openapi": "3.0.3",
        "info": {
            "title": "YunoHost API",
            "description": "This is the YunoHost API used on all YunoHost instances. This API is essentially used by YunoHost Webadmin.",
            "version": api_version,
        },
        "servers": [
            {
                "url": "https://{domain}/yunohost/api",
                "variables": {
                    "domain": {
                        "default": "demo.yunohost.org",
                        "description": "Your yunohost domain",
                    }
                },
            }
        ],
        "tags": [{"name": "public", "description": "Public route"}],
        "paths": {
            "/login": {
                "post": {
                    "tags": ["public"],
                    "summary": "Logs in and returns the authentication cookie",
                    "parameters": [csrf],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "credentials": {
                                            "type": "string",
                                            "format": "password",
                                        }
                                    },
                                    "required": ["credentials"],
                                }
                            }
                        },
                    },
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Successfully login",
                            "headers": {"Set-Cookie": {"schema": {"type": "string"}}},
                        }
                    },
                }
            },
            "/installed": {
                "get": {
                    "tags": ["public"],
                    "summary": "Test if the API is working",
                    "parameters": [],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Successfully working",
                        }
                    },
                }
            },
        },
    }

    def convert_categories(categories, parent_category=""):
        for category, category_params in categories.items():
            if parent_category:
                category = f"{parent_category} {category}"
            if "subcategory_help" in category_params:
                category_params["category_help"] = category_params["subcategory_help"]

            if "category_help" not in category_params:
                category_params["category_help"] = ""
            resource_list["tags"].append(
                {"name": category, "description": category_params["category_help"]}
            )

            for action, action_params in category_params["actions"].items():
                if "action_help" not in action_params:
                    action_params["action_help"] = ""
                if "api" not in action_params:
                    continue
                if not isinstance(action_params["api"], list):
                    action_params["api"] = [action_params["api"]]

                for i, api in enumerate(action_params["api"]):
                    print(api)
                    method, path = api.split(" ")
                    method = method.lower()
                    key_param = ""
                    if "{" in path:
                        key_param = path[path.find("{") + 1 : path.find("}")]
                    resource_list["paths"].setdefault(path, {})

                    notes = ""

                    operationId = f"{category}_{action}"
                    if i > 0:
                        operationId += f"_{i}"
                    operation = {
                        "tags": [category],
                        "operationId": operationId,
                        "summary": action_params["action_help"],
                        "description": notes,
                        "responses": {"200": {"description": "successful operation"}},
                    }
                    if action_params.get("deprecated"):
                        operation["deprecated"] = True

                    operation["parameters"] = []
                    if method == "post":
                        operation["parameters"] = [csrf]

                    if "arguments" in action_params:
                        if method in ["put", "post", "patch"]:
                            operation["requestBody"] = {
                                "required": True,
                                "content": {
                                    "multipart/form-data": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {},
                                            "required": [],
                                        }
                                    }
                                },
                            }
                        for arg_name, arg_params in action_params["arguments"].items():
                            if "help" not in arg_params:
                                arg_params["help"] = ""
                            param_type = "query"
                            allow_multiple = False
                            required = True
                            allowable_values = None
                            name = str(arg_name).replace("-", "_")
                            if name[0] == "_":
                                required = False
                                if "full" in arg_params:
                                    name = arg_params["full"][2:]
                                else:
                                    name = name[2:]
                                name = name.replace("-", "_")

                            if "choices" in arg_params:
                                allowable_values = arg_params["choices"]
                            _type = "string"
                            if "type" in arg_params:
                                types = {"open": "file", "int": "int"}
                                _type = types[arg_params["type"]]
                            if (
                                "action" in arg_params
                                and arg_params["action"] == "store_true"
                            ):
                                _type = "boolean"

                            if "nargs" in arg_params:
                                if arg_params["nargs"] == "*":
                                    allow_multiple = True
                                    required = False
                                    _type = "array"
                                if arg_params["nargs"] == "+":
                                    allow_multiple = True
                                    required = True
                                    _type = "array"
                                if arg_params["nargs"] == "?":
                                    allow_multiple = False
                                    required = False
                            else:
                                allow_multiple = False

                            if name == key_param:
                                param_type = "path"
                                required = True
                                allow_multiple = False

                            if method in ["put", "post", "patch"]:
                                schema = operation["requestBody"]["content"][
                                    "multipart/form-data"
                                ]["schema"]
                                schema["properties"][name] = {
                                    "type": _type,
                                    "description": arg_params["help"],
                                }
                                if required:
                                    schema["required"].append(name)
                                prop_schema = schema["properties"][name]
                            else:
                                parameters = {
                                    "name": name,
                                    "in": param_type,
                                    "description": arg_params["help"],
                                    "required": required,
                                    "schema": {
                                        "type": _type,
                                    },
                                    "explode": allow_multiple,
                                }
                                prop_schema = parameters["schema"]
                                operation["parameters"].append(parameters)

                            if allowable_values is not None:
                                prop_schema["enum"] = allowable_values
                            if "default" in arg_params:
                                prop_schema["default"] = arg_params["default"]
                            if arg_params.get("metavar") == "PASSWORD":
                                prop_schema["format"] = "password"
                            if arg_params.get("metavar") == "MAIL":
                                prop_schema["format"] = "mail"
                            # Those lines seems to slow swagger ui too much
                            # if 'pattern' in arg_params.get('extra', {}):
                            #    prop_schema['pattern'] = arg_params['extra']['pattern'][0]

                    resource_list["paths"][path][method.lower()] = operation

            # Includes subcategories
            if "subcategories" in category_params:
                convert_categories(category_params["subcategories"], category)

    del action_map["_global"]
    convert_categories(action_map)

    openapi_json = json.dumps(resource_list)
    # Save the OpenAPI json
    with open(os.getcwd() + "/openapi.json", "w") as f:
        f.write(openapi_json)

    openapi_js = f"var openapiJSON = {openapi_json}"
    with open(os.getcwd() + "/openapi.js", "w") as f:
        f.write(openapi_js)


if __name__ == "__main__":
    sys.exit(main())
