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
from glob import iglob

from moulinette.core import MoulinetteError
from moulinette.utils import log

hook_folder = '/usr/share/yunohost/hooks/'
custom_hook_folder = '/etc/yunohost/hooks.d/'

logger = log.getActionLogger('yunohost.hook')


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


def hook_info(action, name):
    """
    Get information about a given hook

    Keyword argument:
        action -- Action name
        name -- Hook name

    """
    hooks = []
    priorities = set()

    # Search in custom folder first
    for h in iglob('{:s}{:s}/*-{:s}'.format(
            custom_hook_folder, action, name)):
        priority, _ = _extract_filename_parts(os.path.basename(h))
        priorities.add(priority)
        hooks.append({
            'priority': priority,
            'path': h,
        })
    # Append non-overwritten system hooks
    for h in iglob('{:s}{:s}/*-{:s}'.format(
            hook_folder, action, name)):
        priority, _ = _extract_filename_parts(os.path.basename(h))
        if priority not in priorities:
            hooks.append({
                'priority': priority,
                'path': h,
            })

    if not hooks:
        raise MoulinetteError(errno.EINVAL, m18n.n('hook_name_unknown', name=name))
    return {
        'action': action,
        'name': name,
        'hooks': hooks,
    }


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
    result = { 'succeed': {}, 'failed': {} }
    hooks_dict = {}

    # Retrieve hooks
    if not hooks:
        hooks_dict = hook_list(action, list_by='priority',
                               show_info=True)['hooks']
    else:
        hooks_names = hook_list(action, list_by='name',
                                show_info=True)['hooks']

        # Add similar hooks to the list
        # For example: Having a 16-postfix hook in the list will execute a
        # xx-postfix_dkim as well
        all_hooks = []
        for n in hooks:
            for key in hooks_names.keys():
                if key == n or key.startswith("%s_" % n) \
                  and key not in all_hooks:
                    all_hooks.append(key)

        # Iterate over given hooks names list
        for n in all_hooks:
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
            state = 'succeed'
            filename = '%s-%s' % (priority, name)
            try:
                hook_exec(info['path'], args=args, raise_on_error=True)
            except MoulinetteError as e:
                logger.error(str(e))
                state = 'failed'
            try:
                result[state][name].append(info['path'])
            except KeyError:
                result[state][name] = [info['path']]
    return result


def hook_exec(path, args=None, raise_on_error=False, no_trace=False):
    """
    Execute hook from a file with arguments

    Keyword argument:
        path -- Path of the script to execute
        args -- A list of arguments to pass to the script
        raise_on_error -- Raise if the script returns a non-zero exit code
        no_trace -- Do not print each command that will be executed

    """
    from moulinette.utils.process import call_async_output
    from yunohost.app import _value_for_locale

    # Validate hook path
    if path[0] != '/':
        path = os.path.realpath(path)
    if not os.path.isfile(path):
        raise MoulinetteError(errno.EIO, m18n.g('file_not_exist'))

    # Construct command variables
    cmd_fdir, cmd_fname = os.path.split(path)
    cmd_fname = './{0}'.format(cmd_fname)

    cmd_args = ''
    if args and isinstance(args, list):
        # Concatenate arguments and escape them with double quotes to prevent
        # bash related issue if an argument is empty and is not the last
        cmd_args = '"{:s}"'.format('" "'.join(str(s) for s in args))

    # Construct command to execute
    command = ['sudo', '-u', 'admin', '-H', 'sh', '-c']
    if no_trace:
        cmd = 'cd "{0:s}" && /bin/bash "{1:s}" {2:s}'
    else:
        # use xtrace on fd 7 which is redirected to stdout
        cmd = 'cd "{0:s}" && BASH_XTRACEFD=7 /bin/bash -x "{1:s}" {2:s} 7>&1'
    command.append(cmd.format(cmd_fdir, cmd_fname, cmd_args))

    if logger.isEnabledFor(log.DEBUG):
        logger.info(m18n.n('executing_command', command=' '.join(command)))
    else:
        logger.info(m18n.n('executing_script', script='{0}/{1}'.format(
                cmd_fdir, cmd_fname)))

    # Define output callbacks and call command
    callbacks = (
        lambda l: logger.info(l.rstrip()),
        lambda l: logger.warning(l.rstrip()),
    )
    returncode = call_async_output(command, callbacks, shell=False)

    # Check and return process' return code
    if returncode is None:
        if raise_on_error:
            raise MoulinetteError(m18n.n('hook_exec_not_terminated', path=path))
        else:
            logger.error(m18n.n('hook_exec_not_terminated', path=path))
            return 1
    elif raise_on_error and returncode != 0:
        raise MoulinetteError(m18n.n('hook_exec_failed', path=path))
    return returncode


def _extract_filename_parts(filename):
    """Extract hook parts from filename"""
    if '-' in filename:
        priority, action = filename.split('-', 1)
    else:
        priority = '50'
        action = filename
    return priority, action
