#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" License
    Copyright (C) 2013 YunoHost
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses
"""

"""
    Generate JSON specification files API
"""
import os
import sys
import yaml
import json
import requests

def main():
    """
    """
    with open('../share/actionsmap.yml') as f:
        action_map = yaml.safe_load(f)

    try:
        with open('/etc/yunohost/current_host', 'r') as f:
            domain = f.readline().rstrip()
    except IOError:
        domain = requests.get('http://ip.yunohost.org').text
    with open('../debian/changelog') as f:
        top_changelog = f.readline()
    api_version = top_changelog[top_changelog.find("(")+1:top_changelog.find(")")]

    resource_list = {
        'openapi': '3.0.3',
        'info': {
            'title': 'YunoHost API',
            'description': 'This is the YunoHost API used on all YunoHost instances. This API is essentially used by YunoHost Webadmin.',
            'version': api_version,

        },
        'servers': [
            {'url': 'https://demo.yunohost.org/yunohost/api'},
            {'url': f"https://{domain}/yunohost/api"}
        ],
        'tags': [
            {
                'name': 'public',
                'description': 'Public route'
            }
        ],
        'paths': {
            '/login': {
                'post': {
                    'tags': ['public'],
                    'summary': 'Logs in and returns the authentication cookie',
                    'requestBody': {
                        'required': True,
                        'content': {
                            'multipart/form-data': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'password': {
                                            'type': 'string',
                                            'format': 'password'
                                        }
                                    },
                                    'required': [
                                        'password'
                                    ]
                                }
                            }
                        }
                    },
                    'security': [],
                    'responses': {
                        '200': {
                            'description': 'Successfully login'
                        }
                    }
                }
            }
        },
        'components': {
            'securitySchemes': {
                'cookieAuth': {
                    'type': 'apiKey',
                    'in': 'cookie',
                    'name': 'session.yunohost.admin'
                }
            }
        },
        'security': {'cookieAuth': [] }
    }


    def convert_categories(categories, parent_category=""):
        for category, category_params in categories.items():
            if parent_category:
                category = f"{parent_category} {category}"
            if 'subcategory_help' in category_params:
                category_params['category_help'] = category_params['subcategory_help']

            if 'category_help' not in category_params:
                category_params['category_help'] = ''
            resource_list['tags'].append({
                'name': category,
                'description': category_params['category_help']
            })


            for action, action_params in category_params['actions'].items():
                if 'action_help' not in action_params:
                    action_params['action_help'] = ''
                if 'api' not in action_params:
                    continue
                if not isinstance(action_params['api'], list):
                    action_params['api'] = [action_params['api']]

                for i, api in enumerate(action_params['api']):
                    print(api)
                    method, path = api.split(' ')
                    method = method.lower()
                    key_param = ''
                    if '{' in path:
                        key_param = path[path.find("{")+1:path.find("}")]
                    resource_list['paths'].setdefault(path, {})

                    notes = ''

                    operationId = f"{category}_{action}"
                    if i > 0:
                        operationId += f"_{i}"
                    operation = {
                        'tags': [category],
                        'operationId': operationId,
                        'summary': action_params['action_help'],
                        'description': notes,
                        'responses': {
                            '200': {
                                'description': 'successful operation'
                            }
                        }
                    }

                    if 'arguments' in action_params:
                        if method in ['put', 'post', 'patch']:
                            operation['requestBody'] = {
                                'required': True,
                                'content': {
                                    'multipart/form-data': {
                                        'schema': {
                                            'type': 'object',
                                            'properties': {
                                            },
                                            'required': []
                                        }
                                    }
                                }
                            }
                        else:
                            operation['parameters'] = []
                        for arg_name, arg_params in action_params['arguments'].items():
                            if 'help' not in arg_params:
                                arg_params['help'] = ''
                            param_type = 'query'
                            allow_multiple = False
                            required = True
                            allowable_values = None
                            name = str(arg_name).replace('-', '_')
                            if name[0] == '_':
                                required = False
                                if 'full' in arg_params:
                                    name = arg_params['full'][2:]
                                else:
                                    name = name[2:]
                                name = name.replace('-', '_')

                            if 'nargs' in arg_params:
                                if arg_params['nargs'] == '*':
                                    allow_multiple = True
                                    required = False
                                if arg_params['nargs'] == '+':
                                    allow_multiple = True
                                    required = True
                            else:
                                allow_multiple = False
                            if 'choices' in arg_params:
                                allowable_values = arg_params['choices']
                            if 'action' in arg_params and arg_params['action'] == 'store_true':
                                allowable_values = {
                                    'valueType': 'LIST',
                                    'values': ['true', 'false']
                                }

                            if name == key_param:
                                param_type = 'path'
                                required = True
                                allow_multiple = False

                            if method in ['put', 'post', 'patch']:
                                schema = operation['requestBody']['content']['multipart/form-data']['schema']
                                schema['properties'][name] = {
                                    'type': 'string',
                                    'description': arg_params['help']
                                }
                                if required:
                                    schema['required'].append(name)
                                if allowable_values is not None:
                                    schema['properties'][name]['enum'] = allowable_values
                            else:
                                parameters = {
                                    'name': name,
                                    'in': param_type,
                                    'description': arg_params['help'],
                                    'required': required,
                                    'schema': {
                                        'type': 'string',
                                    },
                                    'explode': allow_multiple
                                }
                                if allowable_values is not None:
                                    parameters['schema']['enum'] = allowable_values

                                operation['parameters'].append(parameters)

                    resource_list['paths'][path][method.lower()] = operation

            # Includes subcategories
            if 'subcategories' in category_params:
                convert_categories(category_params['subcategories'], category)

    del action_map['_global']
    convert_categories(action_map)

    openapi_json = json.dumps(resource_list)
    # Save the OpenAPI json
    with open(os.getcwd() + '/openapi.json', 'w') as f:
        f.write(openapi_json)

    openapi_js = f"var openapiJSON = {openapi_json}"
    with open(os.getcwd() + '/openapi.js', 'w') as f:
        f.write(openapi_js)



if __name__ == '__main__':
    sys.exit(main())
