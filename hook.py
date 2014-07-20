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

""" yunohost_hook.py

    Manage hooks
"""
import os
import sys
import re
import json
import errno
import subprocess

from moulinette.core import MoulinetteError

hook_folder = '/usr/share/yunohost/hooks/'

def hook_add(app, file):
    """
    Store hook script to filsystem

    Keyword argument:
        app -- App to link with
        file -- Script to add (/path/priority-file)

    """
    path, filename = os.path.split(file)
    if '-' in filename:
        priority, action = filename.split('-')
    else:
        priority = '50'
        action = filename

    try: os.listdir(hook_folder + action)
    except OSError: os.makedirs(hook_folder + action)

    finalpath = hook_folder + action +'/'+ priority +'-'+ app
    os.system('cp %s %s' % (file, finalpath))
    os.system('chown -hR admin: %s' % hook_folder)

    return { 'hook': finalpath }


def hook_remove(app):
    """
    Remove hooks linked to a specific app

    Keyword argument:
        app -- Scripts related to app will be removed

    """
    try:
        for action in os.listdir(hook_folder):
            for script in os.listdir(hook_folder + action):
                if script.endswith(app):
                    os.remove(hook_folder + action +'/'+ script)
    except OSError: pass


def hook_callback(action, args=None):
    """
    Execute all scripts binded to an action

    Keyword argument:
        action -- Action name
        args -- Ordered list of arguments to pass to the script

    """
    try: os.listdir(hook_folder + action)
    except OSError: pass
    else:
        if args is None:
            args = []
        elif not isinstance(args, list):
            args = [args]

        for hook in os.listdir(hook_folder + action):
            try:
                hook_exec(file=hook_folder + action +'/'+ hook, args=args)
            except: pass


def hook_check(file):
    """
    Parse the script file and get arguments

    Keyword argument:
        file -- File to check

    """
    try:
        with open(file[:file.index('scripts/')] + 'manifest.json') as f:
            manifest = json.loads(str(f.read()))
    except:
        raise MoulinetteError(errno.EIO, m18n.n('app_manifest_invalid'))

    action = file[file.index('scripts/') + 8:]
    if 'arguments' in manifest and action in manifest['arguments']:
        return manifest['arguments'][action]
    else:
        return {}


def hook_exec(file, args=None):
    """
    Execute hook from a file with arguments

    Keyword argument:
        file -- Script to execute
        args -- Arguments to pass to the script

    """
    from yunohost.app import _value_for_locale

    if isinstance(args, list):
        arg_list = args
    else:
        required_args = hook_check(file)
        if args is None:
            args = {}

        arg_list = []
        for arg in required_args:
            if arg['name'] in args:
                if 'choices' in arg and args[arg['name']] not in arg['choices']:
                    raise MoulinetteError(errno.EINVAL,
                        m18n.n('hook_choice_invalid', args[arg['name']]))
                arg_list.append(args[arg['name']])
            else:
                if os.isatty(1) and 'ask' in arg:
                    # Retrieve proper ask string
                    ask_string = _value_for_locale(arg['ask'])

                    # Append extra strings
                    if 'choices' in arg:
                        ask_string += ' ({:s})'.format('|'.join(arg['choices']))
                    if 'default' in arg:
                        ask_string += ' (default: {:s})'.format(arg['default'])

                    input_string = msignals.prompt(ask_string)

                    if input_string == '' and 'default' in arg:
                        input_string = arg['default']

                    arg_list.append(input_string)
                elif 'default' in arg:
                    arg_list.append(arg['default'])
                else:
                    raise MoulinetteError(errno.EINVAL,
                        m18n.n('hook_argument_missing', arg['name']))

    file_path = "./"
    if "/" in file and file[0:2] != file_path:
        file_path = os.path.dirname(file)
        file = file.replace(file_path +"/", "")

    #TODO: Allow python script

    arg_str = ''
    if arg_list:
        # Concatenate arguments and escape them with double quotes to prevent
        # bash related issue if an argument is empty and is not the last
        arg_str = '\\"{:s}\\"'.format('\\" \\"'.join(arg_list))

    msignals.display(m18n.n('executing_script'))

    p = subprocess.Popen('su - admin -c "cd \\"{:s}\\" && ' \
            '/bin/bash -x \\"{:s}\\" {:s}"'.format(file_path, file, arg_str),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    for line in iter(p.stdout.readline, ''):
        line = line.rstrip()
        msignals.display(line, 'log')
    errorcode = p.poll()
    p.stdout.close()

    return errorcode
