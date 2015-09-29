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
from moulinette.utils.log import getActionLogger

hook_folder = '/usr/share/yunohost/hooks/'
custom_hook_folder = '/etc/yunohost/hooks.d/'

logger = getActionLogger('yunohost.hook')


def hook_add(app, file):
    """
    Store hook script to filsystem

    Keyword argument:
        app -- App to link with
        file -- Script to add (/path/priority-file)

    """
    path, filename = os.path.split(file)
    priority, action = _extract_filename_parts(filename)

    try: os.listdir(custom_hook_folder + action)
    except OSError: os.makedirs(custom_hook_folder + action)

    finalpath = custom_hook_folder + action +'/'+ priority +'-'+ app
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
        for action in os.listdir(custom_hook_folder):
            for script in os.listdir(custom_hook_folder + action):
                if script.endswith(app):
                    os.remove(custom_hook_folder + action +'/'+ script)
    except OSError: pass


def hook_list(action, list_by='name', show_info=False):
    """
    List available hooks for an action

    Keyword argument:
        action -- Action name
        list_by -- Property to list hook by
        show_info -- Show hook information

    """
    result = {}

    # Process the property to list hook by
    if list_by == 'priority':
        if show_info:
            def _append_hook(d, priority, name, path):
                # Use the priority as key and a dict of hooks names
                # with their info as value
                value = { 'path': path }
                try:
                    d[priority][name] = value
                except KeyError:
                    d[priority] = { name: value }
        else:
            def _append_hook(d, priority, name, path):
                # Use the priority as key and the name as value
                try:
                    d[priority].add(name)
                except KeyError:
                    d[priority] = set([name])
    elif list_by == 'name' or list_by == 'folder':
        if show_info:
            def _append_hook(d, priority, name, path):
                # Use the name as key and a list of hooks info - the
                # executed ones with this name - as value
                l = d.get(name, list())
                for h in l:
                    # Only one priority for the hook is accepted
                    if h['priority'] == priority:
                        # Custom hooks overwrite system ones and they
                        # are appended at the end - so overwite it
                        if h['path'] != path:
                            h['path'] = path
                        return
                l.append({ 'priority': priority, 'path': path })
                d[name] = l
        else:
            if list_by == 'name':
                result = set()
            def _append_hook(d, priority, name, path):
                # Add only the name
                d.add(name)
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('hook_list_by_invalid'))

    def _append_folder(d, folder):
        # Iterate over and add hook from a folder
        for f in os.listdir(folder + action):
            path = '%s%s/%s' % (folder, action, f)
            priority, name = _extract_filename_parts(f)
            _append_hook(d, priority, name, path)

    try:
        # Append system hooks first
        if list_by == 'folder':
            result['system'] = dict() if show_info else set()
            _append_folder(result['system'], hook_folder)
        else:
            _append_folder(result, hook_folder)
    except OSError:
        logger.debug("system hook folder not found for action '%s' in %s",
                     action, hook_folder)

    try:
        # Append custom hooks
        if list_by == 'folder':
            result['custom'] = dict() if show_info else set()
            _append_folder(result['custom'], custom_hook_folder)
        else:
            _append_folder(result, custom_hook_folder)
    except OSError:
        logger.debug("custom hook folder not found for action '%s' in %s",
                     action, custom_hook_folder)

    return { 'hooks': result }


def hook_callback(action, hooks=[], args=None):
    """
    Execute all scripts binded to an action

    Keyword argument:
        action -- Action name
        hooks -- List of hooks names to execute
        args -- Ordered list of arguments to pass to the script

    """
    result = { 'succeed': list(), 'failed': list() }
    hooks_dict = {}

    # Retrieve hooks
    if not hooks:
        hooks_dict = hook_list(action, list_by='priority',
                               show_info=True)['hooks']
    else:
        hooks_names = hook_list(action, list_by='name',
                                show_info=True)['hooks']
        # Iterate over given hooks names list
        for n in hooks:
            try:
                hl = hooks_names[n]
            except KeyError:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('hook_name_unknown', n))
            # Iterate over hooks with this name
            for h in hl:
                # Update hooks dict
                d = hooks_dict.get(h['priority'], dict())
                d.update({ n: { 'path': h['path'] }})
                hooks_dict[h['priority']] = d
    if not hooks_dict:
        return result

    # Format arguments
    if args is None:
        args = []
    elif not isinstance(args, list):
        args = [args]

    # Iterate over hooks and execute them
    for priority in sorted(hooks_dict):
        for name, info in iter(hooks_dict[priority].items()):
            filename = '%s-%s' % (priority, name)
            try:
                hook_exec(info['path'], args=args)
            except:
                logger.exception("error while executing hook '%s'",
                                 info['path'])
                result['failed'].append(filename)
            else:
                result['succeed'].append(filename)
    return result


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
    from moulinette.utils.stream import NonBlockingStreamReader
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
        arg_str = '"{:s}"'.format('" "'.join(str(s) for s in arg_list))

    msignals.display(m18n.n('executing_script'))

    p = subprocess.Popen(
            ['sudo', '-u', 'admin', '-H', 'sh', '-c', 'cd "{:s}" && ' \
                '/bin/bash "{:s}" {:s}'.format(file_path, file, arg_str)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            shell=False)

    # Wrap and get process ouput
    stream = NonBlockingStreamReader(p.stdout)
    while True:
        line = stream.readline(True, 0.1)
        if not line:
            # Check if process has terminated
            returncode = p.poll()
            if returncode is not None:
                break
        else:
            msignals.display(line.rstrip(), 'log')
    stream.close()

    return returncode


def _extract_filename_parts(filename):
    """Extract hook parts from filename"""
    if '-' in filename:
        priority, action = filename.split('-', 1)
    else:
        priority = '50'
        action = filename
    return priority, action
