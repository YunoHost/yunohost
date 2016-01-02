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

""" yunohost_app.py

    Manage apps
"""
import os
import sys
import json
import shutil
import stat
import yaml
import time
import re
import socket
import urlparse
import errno
import subprocess

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from . import has_min_version
from .service import service_log

logger = getActionLogger('yunohost.app')

repo_path        = '/var/cache/yunohost/repo'
apps_path        = '/usr/share/yunohost/apps'
apps_setting_path= '/etc/yunohost/apps/'
install_tmp      = '/var/cache/yunohost'
app_tmp_folder   = install_tmp + '/from_file'

def app_listlists():
    """
    List fetched lists


    """
    list_list = []
    try:
        for filename in os.listdir(repo_path):
            if '.json' in filename:
                list_list.append(filename[:len(filename)-5])
    except OSError:
        raise MoulinetteError(1, m18n.n('no_appslist_found'))

    return { 'lists' : list_list }


def app_fetchlist(url=None, name=None):
    """
    Fetch application list from app server

    Keyword argument:
        name -- Name of the list (default yunohost)
        url -- URL of remote JSON list (default https://yunohost.org/official.json)

    """
    # Create app path if not exists
    try: os.listdir(repo_path)
    except OSError: os.makedirs(repo_path)

    if url is None:
        url = 'https://yunohost.org/official.json'
        name = 'yunohost'
    else:
        if name is None:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('custom_appslist_name_required'))

    list_file = '%s/%s.json' % (repo_path, name)
    if os.system('wget "%s" -O "%s.tmp"' % (url, list_file)) != 0:
        os.remove('%s.tmp' % list_file)
        raise MoulinetteError(errno.EBADR, m18n.n('appslist_retrieve_error'))

    # Rename fetched temp list
    os.rename('%s.tmp' % list_file, list_file)

    os.system("touch /etc/cron.d/yunohost-applist-%s" % name)
    os.system("echo '00 00 * * * root yunohost app fetchlist -u %s -n %s > /dev/null 2>&1' >/etc/cron.d/yunohost-applist-%s" % (url, name, name))

    msignals.display(m18n.n('appslist_fetched'), 'success')


def app_removelist(name):
    """
    Remove list from the repositories

    Keyword argument:
        name -- Name of the list to remove

    """
    try:
        os.remove('%s/%s.json' % (repo_path, name))
        os.remove("/etc/cron.d/yunohost-applist-%s" % name)
    except OSError:
        raise MoulinetteError(errno.ENOENT, m18n.n('appslist_unknown'))

    msignals.display(m18n.n('appslist_removed'), 'success')


def app_list(offset=None, limit=None, filter=None, raw=False):
    """
    List apps

    Keyword argument:
        filter -- Name filter of app_id or app_name
        offset -- Starting number for app fetching
        limit -- Maximum number of app fetched
        raw -- Return the full app_dict

    """
    if offset: offset = int(offset)
    else: offset = 0
    if limit: limit = int(limit)
    else: limit = 1000

    applists = os.listdir(repo_path)
    app_dict  = {}
    if raw:
        list_dict = {}
    else:
        list_dict=[]

    if not applists:
        app_fetchlist()
        applists = os.listdir(repo_path)

    for applist in applists:
        if '.json' in applist:
            with open(repo_path +'/'+ applist) as json_list:
                app_dict.update(json.loads(str(json_list.read())))

    for app in os.listdir(apps_setting_path):
        if app not in app_dict:
            # Look for forks
            if '__' in app:
                original_app = app[:app.index('__')]
                if original_app in app_dict:
                    app_dict[app] = app_dict[original_app]
                    continue
            with open( apps_setting_path + app +'/manifest.json') as json_manifest:
                app_dict[app] = {"manifest":json.loads(str(json_manifest.read()))}
            app_dict[app]['manifest']['orphan']=True

    if len(app_dict) > (0 + offset) and limit > 0:
        sorted_app_dict = {}
        for sorted_keys in sorted(app_dict.keys())[offset:]:
            sorted_app_dict[sorted_keys] = app_dict[sorted_keys]

        i = 0
        for app_id, app_info_dict in sorted_app_dict.items():
            if i < limit:
                if (filter and ((filter in app_id) or (filter in app_info_dict['manifest']['name']))) or not filter:
                    installed = _is_installed(app_id)

                    if raw:
                        app_info_dict['installed'] = installed
                        if installed:
                            app_info_dict['status'] = _get_app_status(app_id)
                        list_dict[app_id] = app_info_dict
                    else:
                        label = None
                        if installed:
                            app_info_dict_raw = app_info(app=app_id, raw=True)
                            label = app_info_dict_raw['settings']['label']
                        list_dict.append({
                            'id': app_id,
                            'name': app_info_dict['manifest']['name'],
                            'label': label,
                            'description': _value_for_locale(
                                app_info_dict['manifest']['description']),
                            # FIXME: Temporarly allow undefined license
                            'license': app_info_dict['manifest'].get('license',
                                m18n.n('license_undefined')),
                            'installed': installed
                        })
                    i += 1
            else:
               break
    if not raw:
        list_dict = { 'apps': list_dict }
    return list_dict


def app_info(app, show_status=False, raw=False):
    """
    Get app info

    Keyword argument:
        app -- Specific app ID
        show_status -- Show app installation status
        raw -- Return the full app_dict

    """
    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('app_not_installed', app))
    if raw:
        ret = app_list(filter=app, raw=True)[app]
        with open(apps_setting_path + app +'/settings.yml') as f:
            ret['settings'] = yaml.load(f)
        return ret

    app_setting_path = apps_setting_path + app

    # Retrieve manifest and status
    with open(app_setting_path + '/manifest.json') as f:
        manifest = json.loads(str(f.read()))
    status = _get_app_status(app, format_date=True)

    info = {
        'name': manifest['name'],
        'description': _value_for_locale(manifest['description']),
        # FIXME: Temporarly allow undefined license
        'license': manifest.get('license', m18n.n('license_undefined')),
        # FIXME: Temporarly allow undefined version
        'version': manifest.get('version', '-'),
        #TODO: Add more info
    }
    if show_status:
        info['status'] = status
    return info


def app_map(app=None, raw=False, user=None):
    """
    List apps by domain

    Keyword argument:
        user -- Allowed app map for a user
        raw -- Return complete dict
        app -- Specific app to map

    """

    result = {}

    for app_id in os.listdir(apps_setting_path):
        if app and (app != app_id):
            continue

        if user is not None:
            app_dict = app_info(app=app_id, raw=True)
            if ('mode' not in app_dict['settings']) or ('mode' in app_dict['settings'] and app_dict['settings']['mode'] == 'private'):
                if 'allowed_users' in app_dict['settings'] and user not in app_dict['settings']['allowed_users'].split(','):
                    continue

        with open(apps_setting_path + app_id +'/settings.yml') as f:
            app_settings = yaml.load(f)

        if 'domain' not in app_settings:
            continue

        if raw:
            if app_settings['domain'] not in result:
                result[app_settings['domain']] = {}
            result[app_settings['domain']][app_settings['path']] = {
                    'label': app_settings['label'],
                    'id': app_settings['id']
            }
        else:
            result[app_settings['domain']+app_settings['path']] = app_settings['label']

    return result


def app_upgrade(auth, app=[], url=None, file=None):
    """
    Upgrade app

    Keyword argument:
        file -- Folder or tarball for upgrade
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade

    """
    from yunohost.hook import hook_add, hook_remove, hook_exec

    try:
        app_list()
    except MoulinetteError:
        raise MoulinetteError(errno.ENODATA, m18n.n('app_no_upgrade'))

    upgraded_apps = []

    # If no app is specified, upgrade all apps
    if not app:
        if (not url and not file):
            app = os.listdir(apps_setting_path)
    elif not isinstance(app, list):
        app = [ app ]

    for app_id in app:
        installed = _is_installed(app_id)
        if not installed:
            raise MoulinetteError(errno.ENOPKG,
                                  m18n.n('app_not_installed', app_id))

        if app_id in upgraded_apps:
            continue

        current_app_dict = app_info(app_id,  raw=True)
        new_app_dict     = app_info(app_id, raw=True)

        if file:
            manifest = _extract_app_from_file(file)
        elif url:
            manifest = _fetch_app_from_git(url)
        elif new_app_dict is None or 'lastUpdate' not in new_app_dict or 'git' not in new_app_dict:
            msignals.display(m18n.n('custom_app_url_required', app_id), 'warning')
            continue
        elif (new_app_dict['lastUpdate'] > current_app_dict['lastUpdate']) \
              or ('update_time' not in current_app_dict['settings'] \
                   and (new_app_dict['lastUpdate'] > current_app_dict['settings']['install_time'])) \
              or ('update_time' in current_app_dict['settings'] \
                   and (new_app_dict['lastUpdate'] > current_app_dict['settings']['update_time'])):
            manifest = _fetch_app_from_git(app_id)
        else:
            continue

        # Check min version
        if 'min_version' in manifest \
                and not has_min_version(manifest['min_version']):
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('app_recent_version_required', app_id))

        app_setting_path = apps_setting_path +'/'+ app_id

        # Retrieve current app status
        status = _get_app_status(app_id)
        status['remote'] = manifest.get('remote', None)

        # Clean hooks and add new ones
        hook_remove(app_id)
        if 'hooks' in os.listdir(app_tmp_folder):
            for hook in os.listdir(app_tmp_folder +'/hooks'):
                hook_add(app_id, app_tmp_folder +'/hooks/'+ hook)

        # Retrieve arguments list for upgrade script
        # TODO: Allow to specify arguments
        args_list = _parse_args_from_manifest(manifest, 'upgrade', auth=auth)
        args_list.append(app_id)

        # Execute App upgrade script
        os.system('chown -hR admin: %s' % install_tmp)
        if hook_exec(app_tmp_folder +'/scripts/upgrade', args_list) != 0:
            raise MoulinetteError(errno.EIO, m18n.n('installation_failed'))
        else:
            now = int(time.time())
            # TODO: Move install_time away from app_setting
            app_setting(app_id, 'update_time', now)
            status['upgraded_at'] = now

            # Store app status
            with open(app_setting_path + '/status.json', 'w+') as f:
                json.dump(status, f)

            # Replace scripts and manifest
            os.system('rm -rf "%s/scripts" "%s/manifest.json"' % (app_setting_path, app_setting_path))
            os.system('mv "%s/manifest.json" "%s/scripts" %s' % (app_tmp_folder, app_tmp_folder, app_setting_path))

            # So much win
            upgraded_apps.append(app_id)
            msignals.display(m18n.n('app_upgraded', app_id), 'success')

    if not upgraded_apps:
        raise MoulinetteError(errno.ENODATA, m18n.n('app_no_upgrade'))

    msignals.display(m18n.n('upgrade_complete'), 'success')


def app_install(auth, app, label=None, args=None):
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation

    """
    from yunohost.hook import hook_add, hook_remove, hook_exec

    # Fetch or extract sources
    try: os.listdir(install_tmp)
    except OSError: os.makedirs(install_tmp)

    status = {
        'installed_at': None,
        'upgraded_at': None,
        'remote': {
            'type': None,
        },
    }

    if app in app_list(raw=True) or ('@' in app) or ('http://' in app) or ('https://' in app):
        manifest = _fetch_app_from_git(app)
    elif os.path.exists(app):
        manifest = _extract_app_from_file(app)
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))
    status['remote'] = manifest.get('remote', {})

    # Check ID
    if 'id' not in manifest or '__' in manifest['id']:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_id_invalid'))

    app_id = manifest['id']

    # Check min version
    if 'min_version' in manifest \
            and not has_min_version(manifest['min_version']):
        raise MoulinetteError(errno.EPERM,
                              m18n.n('app_recent_version_required', app_id))

    # Check if app can be forked
    instance_number = _installed_instance_number(app_id, last=True) + 1
    if instance_number > 1 :
        if 'multi_instance' not in manifest or not is_true(manifest['multi_instance']):
            raise MoulinetteError(errno.EEXIST,
                                  m18n.n('app_already_installed', app_id))

        # Change app_id to the forked app id
        app_id = app_id + '__' + str(instance_number)

    # Retrieve arguments list for install script
    args_dict = {} if not args else \
        dict(urlparse.parse_qsl(args, keep_blank_values=True))
    args_list = _parse_args_from_manifest(manifest, 'install', args_dict, auth)
    args_list.append(app_id)

    # Prepare App settings
    app_setting_path = apps_setting_path +'/'+ app_id

    #TMP: Remove old settings
    if os.path.exists(app_setting_path): shutil.rmtree(app_setting_path)
    os.makedirs(app_setting_path)
    os.system('touch %s/settings.yml' % app_setting_path)

    # Clean hooks and add new ones
    hook_remove(app_id)
    if 'hooks' in os.listdir(app_tmp_folder):
        for file in os.listdir(app_tmp_folder +'/hooks'):
            hook_add(app_id, app_tmp_folder +'/hooks/'+ file)

    now = int(time.time())
    app_setting(app_id, 'id', app_id)
    # TODO: Move install_time away from app_setting
    app_setting(app_id, 'install_time', now)
    status['installed_at'] = now

    if label:
        app_setting(app_id, 'label', label)
    else:
        app_setting(app_id, 'label', manifest['name'])

    os.system('chown -R admin: '+ app_tmp_folder)

    # Execute App install script
    os.system('chown -hR admin: %s' % install_tmp)
    # Move scripts and manifest to the right place
    os.system('cp %s/manifest.json %s' % (app_tmp_folder, app_setting_path))
    os.system('cp -R %s/scripts %s' % (app_tmp_folder, app_setting_path))
    try:
        if hook_exec(app_tmp_folder + '/scripts/install', args_list) == 0:
            # Store app status
            with open(app_setting_path + '/status.json', 'w+') as f:
                json.dump(status, f)

            # Clean and set permissions
            shutil.rmtree(app_tmp_folder)
            os.system('chmod -R 400 %s' % app_setting_path)
            os.system('chown -R root: %s' % app_setting_path)
            os.system('chown -R admin: %s/scripts' % app_setting_path)
            app_ssowatconf(auth)
            msignals.display(m18n.n('installation_complete'), 'success')
        else:
            raise MoulinetteError(errno.EIO, m18n.n('installation_failed'))
    except:
        # Execute remove script and clean folders
        hook_remove(app_id)
        shutil.rmtree(app_setting_path)
        shutil.rmtree(app_tmp_folder)

        # Reraise proper exception
        try:
            raise
        except MoulinetteError:
            raise
        except KeyboardInterrupt, EOFError:
            raise MoulinetteError(errno.EINTR, m18n.g('operation_interrupted'))
        except Exception as e:
            import traceback
            msignals.display(traceback.format_exc().strip(), 'log')
            raise MoulinetteError(errno.EIO, m18n.n('unexpected_error'))


def app_remove(auth, app):
    """
    Remove app

    Keyword argument:
        app -- App(s) to delete

    """
    from yunohost.hook import hook_exec, hook_remove

    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL, m18n.n('app_not_installed', app))

    app_setting_path = apps_setting_path + app

    #TODO: display fail messages from script
    try:
        shutil.rmtree('/tmp/yunohost_remove')
    except: pass

    os.system('cp -a %s /tmp/yunohost_remove && chown -hR admin: /tmp/yunohost_remove' % app_setting_path)
    os.system('chown -R admin: /tmp/yunohost_remove')
    os.system('chmod -R u+rX /tmp/yunohost_remove')

    args_list = [app]

    if hook_exec('/tmp/yunohost_remove/scripts/remove', args_list) == 0:
        msignals.display(m18n.n('app_removed', app), 'success')

    if os.path.exists(app_setting_path): shutil.rmtree(app_setting_path)
    shutil.rmtree('/tmp/yunohost_remove')
    hook_remove(app)
    app_ssowatconf(auth)


def app_addaccess(auth, apps, users=[]):
    """
    Grant access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.user import user_list, user_info
    from yunohost.hook import hook_callback

    if not users:
        users = user_list(auth)['users'].keys()

    if not isinstance(users, list): users = [users]
    if not isinstance(apps, list): apps = [apps]

    for app in apps:
        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app))

        with open(apps_setting_path + app +'/settings.yml') as f:
            app_settings = yaml.load(f)

        if 'mode' not in app_settings:
            app_setting(app, 'mode', 'private')
            app_settings['mode'] = 'private'

        if app_settings['mode'] == 'private':
            if 'allowed_users' in app_settings:
                new_users = app_settings['allowed_users']
            else:
                new_users = ''

            for allowed_user in users:
                if allowed_user not in new_users.split(','):
                    try:
                        user_info(auth, allowed_user)
                    except MoulinetteError:
                        continue
                    if new_users == '':
                        new_users = allowed_user
                    else:
                        new_users = new_users +','+ allowed_user

            app_setting(app, 'allowed_users', new_users.strip())
            hook_callback('post_app_addaccess', args=[app, new_users])

    app_ssowatconf(auth)

    return { 'allowed_users': new_users.split(',') }


def app_removeaccess(auth, apps, users=[]):
    """
    Revoke access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.user import user_list
    from yunohost.hook import hook_callback

    remove_all = False
    if not users:
        remove_all = True
    if not isinstance(users, list): users = [users]
    if not isinstance(apps, list): apps = [apps]
    for app in apps:
        new_users = ''

        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app))

        with open(apps_setting_path + app +'/settings.yml') as f:
            app_settings = yaml.load(f)

        if 'skipped_uris' not in app_settings or app_settings['skipped_uris'] != '/':
            if remove_all:
                new_users = ''
            elif 'allowed_users' in app_settings:
                for allowed_user in app_settings['allowed_users'].split(','):
                    if allowed_user not in users:
                        if new_users == '':
                            new_users = allowed_user
                        else:
                            new_users = new_users +','+ allowed_user
            else:
                new_users = ''
                for username in user_list(auth)['users'].keys():
                    if username not in users:
                        if new_users == '':
                            new_users = username
                        new_users += ',' + username

            app_setting(app, 'allowed_users', new_users.strip())
            hook_callback('post_app_removeaccess', args=[app, new_users])

    app_ssowatconf(auth)

    return { 'allowed_users': new_users.split(',') }


def app_clearaccess(auth, apps):
    """
    Reset access rights for the app

    Keyword argument:
        apps

    """
    from yunohost.hook import hook_callback

    if not isinstance(apps, list): apps = [apps]

    for app in apps:
        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app))

        with open(apps_setting_path + app +'/settings.yml') as f:
            app_settings = yaml.load(f)

        if 'mode' in app_settings:
            app_setting(app, 'mode', delete=True)

        if 'allowed_users' in app_settings:
            app_setting(app, 'allowed_users', delete=True)

        hook_callback('post_app_clearaccess', args=[app])

    app_ssowatconf(auth)


def app_debug(app):
    """
    Display debug informations for an app

    Keyword argument:
        app
    """
    with open(apps_setting_path + app + '/manifest.json') as f:
        manifest = json.loads(f.read())

    return {
        'name': manifest['id'],
        'label': manifest['name'],
        'services': [{
                "name": x,
                "logs": [{
                    "file_name": y,
                    "file_content": "\n".join(z),
                } for (y, z) in sorted(service_log(x).items(), key=lambda x: x[0])],
            } for x in sorted(manifest.get("services", []))]
    }


def app_makedefault(auth, app, domain=None):
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from yunohost.domain import domain_list

    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL, m18n.n('app_not_installed', app))

    with open(apps_setting_path + app +'/settings.yml') as f:
        app_settings = yaml.load(f)

    app_domain = app_settings['domain']
    app_path   = app_settings['path']

    if domain is None:
        domain = app_domain
    elif domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    if '/' in app_map(raw=True)[domain]:
        raise MoulinetteError(errno.EEXIST,
                              m18n.n('app_location_already_used'))

    try:
        with open('/etc/ssowat/conf.json.persistent') as json_conf:
            ssowat_conf = json.loads(str(json_conf.read()))
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls'][domain +'/'] = app_domain + app_path

    with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
        json.dump(ssowat_conf, f, sort_keys=True, indent=4)

    os.system('chmod 644 /etc/ssowat/conf.json.persistent')

    msignals.display(m18n.n('ssowat_conf_updated'), 'success')


def app_setting(app, key, value=None, delete=False):
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """
    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('app_not_installed', app))

    settings_file = apps_setting_path + app +'/settings.yml'
    try:
        with open(settings_file) as f:
            app_settings = yaml.load(f)
    except IOError:
        # Do not fail if setting file is not there
        app_settings = {}

    if value is None and not delete:
        try:
            return app_settings[key]
        except:
            logger.info("cannot get app setting '%s' for '%s'", key, app)
            return None
    else:
        yaml_settings=['redirected_urls','redirected_regex']
        # Set the value
        if app_settings is None:
            app_settings = {}
        if delete and key in app_settings:
            del app_settings[key]
        else:
            if key in yaml_settings:
                value=yaml.load(value)
            app_settings[key] = value

        with open(settings_file, 'w') as f:
            yaml.safe_dump(app_settings, f, default_flow_style=False)


def app_checkport(port):
    """
    Check availability of a local port

    Keyword argument:
        port -- Port to check

    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("localhost", int(port)))
        s.close()
    except socket.error:
        msignals.display(m18n.n('port_available', int(port)), 'success')
    else:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('port_unavailable', int(port)))


def app_checkurl(auth, url, app=None):
    """
    Check availability of a web path

    Keyword argument:
        url -- Url to check
        app -- Write domain & path to app settings for further checks

    """
    from yunohost.domain import domain_list

    if "https://" == url[:8]:
        url = url[8:]
    elif "http://" == url[:7]:
        url = url[7:]

    if url[-1:] != '/':
        url = url + '/'

    domain = url[:url.index('/')]
    path = url[url.index('/'):]
    installed = False

    if path[-1:] != '/':
        path = path + '/'

    apps_map = app_map(raw=True)

    if domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    if domain in apps_map:
        for p, a in apps_map[domain].items():
            # Skip requested app checking
            if app is not None and a['id'] == app:
                installed = True
                continue
            if path == p:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('app_location_already_used'))
            elif path.startswith(p) and p.count('/') < path.count('/'):
                raise MoulinetteError(errno.EPERM,
                                      m18n.n('app_location_install_failed'))

    if app is not None and not installed:
        app_setting(app, 'domain', value=domain)
        app_setting(app, 'path', value=path)


def app_initdb(user, password=None, db=None, sql=None):
    """
    Create database and initialize it with optionnal attached script

    Keyword argument:
        db -- DB name (user unless set)
        user -- Name of the DB user
        password -- Password of the DB (generated unless set)
        sql -- Initial SQL file

    """
    if db is None:
        db = user

    return_pwd = False
    if password is None:
        password = random_password(12)
        return_pwd = True

    mysql_root_pwd = open('/etc/yunohost/mysql').read().rstrip()
    mysql_command = 'mysql -u root -p%s -e "CREATE DATABASE %s ; GRANT ALL PRIVILEGES ON %s.* TO \'%s\'@localhost IDENTIFIED BY \'%s\';"' % (mysql_root_pwd, db, db, user, password)
    if os.system(mysql_command) != 0:
        raise MoulinetteError(errno.EIO, m18n.n('mysql_db_creation_failed'))
    if sql is not None:
        if os.system('mysql -u %s -p%s %s < %s' % (user, password, db, sql)) != 0:
            raise MoulinetteError(errno.EIO, m18n.n('mysql_db_init_failed'))

    if return_pwd:
        return password

    msignals.display(m18n.n('mysql_db_initialized'), 'success')


def app_ssowatconf(auth):
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import domain_list
    from yunohost.user import user_list

    with open('/etc/yunohost/current_host', 'r') as f:
        main_domain = f.readline().rstrip()

    domains = domain_list(auth)['domains']

    users = {}
    for username in user_list(auth)['users'].keys():
        users[username] = app_map(user=username)

    skipped_urls = []
    skipped_regex = []
    unprotected_urls = []
    unprotected_regex = []
    protected_urls = []
    protected_regex = []
    redirected_regex = { main_domain +'/yunohost[\/]?$': 'https://'+ main_domain +'/yunohost/sso/' }
    redirected_urls ={}

    apps = {}
    try:
        apps_list = app_list()['apps']
    except:
        apps_list = []

    def _get_setting(settings, name):
        s = settings.get(name, None)
        return s.split(',') if s else []

    for app in apps_list:
        if _is_installed(app['id']):
            with open(apps_setting_path + app['id'] +'/settings.yml') as f:
                app_settings = yaml.load(f)
                for item in _get_setting(app_settings, 'skipped_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    skipped_urls.append(app_settings['domain'] + app_settings['path'][:-1] + item)
                for item in _get_setting(app_settings, 'skipped_regex'):
                    skipped_regex.append(item)
                for item in _get_setting(app_settings, 'unprotected_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    unprotected_urls.append(app_settings['domain'] + app_settings['path'][:-1] + item)
                for item in _get_setting(app_settings, 'unprotected_regex'):
                    unprotected_regex.append(item)
                for item in _get_setting(app_settings, 'protected_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    protected_urls.append(app_settings['domain'] + app_settings['path'][:-1] + item)
                for item in _get_setting(app_settings, 'protected_regex'):
                    protected_regex.append(item)
                if 'redirected_urls' in app_settings:
                    redirected_urls.update(app_settings['redirected_urls'])
                if 'redirected_regex' in app_settings:
                    redirected_regex.update(app_settings['redirected_regex'])

    for domain in domains:
        skipped_urls.extend([domain + '/yunohost/admin', domain + '/yunohost/api'])

    conf_dict = {
        'portal_domain': main_domain,
        'portal_path': '/yunohost/sso/',
        'additional_headers': {
            'Auth-User': 'uid',
            'Remote-User': 'uid',
            'Name': 'cn',
            'Email': 'mail'
        },
        'domains': domains,
        'skipped_urls': skipped_urls,
        'unprotected_urls': unprotected_urls,
        'protected_urls': protected_urls,
        'skipped_regex': skipped_regex,
        'unprotected_regex': unprotected_regex,
        'protected_regex': protected_regex,
        'redirected_urls': redirected_urls,
        'redirected_regex': redirected_regex,
        'users': users,
    }

    with open('/etc/ssowat/conf.json', 'w+') as f:
        json.dump(conf_dict, f, sort_keys=True, indent=4)

    msignals.display(m18n.n('ssowat_conf_generated'), 'success')


def _get_app_status(app_id, format_date=False):
    """
    Get app status or create it if needed

    Keyword arguments:
        app_id -- The app id
        format_date -- Format date fields

    """
    app_setting_path = apps_setting_path + app_id
    if not os.path.isdir(app_setting_path):
        raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))
    status = {}

    try:
        with open(app_setting_path + '/status.json') as f:
            status = json.loads(str(f.read()))
    except IOError:
        logger.exception("status file not found for '%s'", app_id)
        # Create app status
        status = {
            'installed_at': app_setting(app_id, 'install_time'),
            'upgraded_at': app_setting(app_id, 'update_time'),
            'remote': { 'type': None },
        }
        with open(app_setting_path + '/status.json', 'w+') as f:
            json.dump(status, f)

    if format_date:
        for f in ['installed_at', 'upgraded_at']:
            v = status.get(f, None)
            if not v:
                status[f] = '-'
            else:
                status[f] = time.strftime(m18n.n('format_datetime_short'),
                                          time.gmtime(v))
    return status


def _extract_app_from_file(path, remove=False):
    """
    Unzip or untar application tarball in app_tmp_folder, or copy it from a directory

    Keyword arguments:
        path -- Path of the tarball or directory
        remove -- Remove the tarball after extraction

    Returns:
        Dict manifest

    """
    global app_tmp_folder

    msignals.display(m18n.n('extracting'))

    if os.path.exists(app_tmp_folder): shutil.rmtree(app_tmp_folder)
    os.makedirs(app_tmp_folder)

    path = os.path.abspath(path)

    if ".zip" in path:
        extract_result = os.system('unzip %s -d %s > /dev/null 2>&1' % (path, app_tmp_folder))
        if remove: os.remove(path)
    elif ".tar" in path:
        extract_result = os.system('tar -xf %s -C %s > /dev/null 2>&1' % (path, app_tmp_folder))
        if remove: os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(app_tmp_folder)
        if path[len(path)-1:] != '/':
            path = path + '/'
        extract_result = os.system('cp -a "%s" %s' % (path, app_tmp_folder))
    else:
        extract_result = 1

    if extract_result != 0:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_extraction_failed'))

    try:
        if len(os.listdir(app_tmp_folder)) == 1:
            for folder in os.listdir(app_tmp_folder):
                app_tmp_folder = app_tmp_folder +'/'+ folder
        with open(app_tmp_folder + '/manifest.json') as json_manifest:
            manifest = json.loads(str(json_manifest.read()))
            manifest['lastUpdate'] = int(time.time())
    except IOError:
        raise MoulinetteError(errno.EIO, m18n.n('app_install_files_invalid'))

    msignals.display(m18n.n('done'))

    manifest['remote'] = {'type': 'file', 'path': path}
    return manifest


def _get_git_last_commit_hash(repository):
    """
    Attempt to retrieve the last commit hash of a git repository

    Keyword arguments:
        repository -- The URL or path of the repository

    """
    try:
        commit = subprocess.check_output(
            "git ls-remote --exit-code {:s} HEAD | awk '{{print $1}}'".format(
                repository),
            shell=True)
    except subprocess.CalledProcessError:
        logger.exception("unable to get last commit from %s", repository)
        raise ValueError("Unable to get last commit with git")
    else:
        return commit.strip()


def _fetch_app_from_git(app):
    """
    Unzip or untar application tarball in app_tmp_folder

    Keyword arguments:
        app -- App_id or git repo URL

    Returns:
        Dict manifest

    """
    global app_tmp_folder

    msignals.display(m18n.n('downloading'))

    git_result_2 = 1

    if ('@' in app) or ('http://' in app) or ('https://' in app):
        if "github.com" in app:
            url = app.replace("git@github.com:", "https://github.com/")
            if ".git" in url[-4:]: url = url[:-4]
            if "/" in url [-1:]: url = url[:-1]
            url = url + "/archive/master.zip"
            if os.system('wget "%s" -O "%s.zip" > /dev/null 2>&1' % (url, app_tmp_folder)) == 0:
                manifest = _extract_app_from_file(app_tmp_folder +'.zip', remove=True)
                del manifest['remote']
        else:
            git_result   = os.system('git clone --depth=1 %s %s' % (app, app_tmp_folder))
            git_result_2 = 0
            try:
                with open(app_tmp_folder + '/manifest.json') as json_manifest:
                    manifest = json.loads(str(json_manifest.read()))
                    manifest['lastUpdate'] = int(time.time())
            except IOError:
                raise MoulinetteError(errno.EIO, m18n.n('app_manifest_invalid'))

        # Store remote repository info into the returned manifest
        manifest['remote'] = {'type': 'git', 'url': app, 'branch': 'master'}
        try:
            revision = _get_git_last_commit_hash(app)
        except: pass
        else:
            manifest['remote']['revision'] = revision

        if git_result_2 == 1:
            return manifest

    else:
        app_dict = app_list(raw=True)

        if app in app_dict:
            app_info = app_dict[app]
            app_info['manifest']['lastUpdate'] = app_info['lastUpdate']
            manifest = app_info['manifest']
        else:
            raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))

        if "github.com" in app_info['git']['url']:
            # FIXME: Retrieve branch defined in app_info
            url = app_info['git']['url'].replace("git@github.com:", "https://github.com/")
            if ".git" in url[-4:]: url = url[:-4]
            if "/" in url [-1:]: url = url[:-1]
            url = url + "/archive/"+ str(app_info['git']['revision']) + ".zip"
            if os.system('wget "%s" -O "%s.zip" > /dev/null 2>&1' % (url, app_tmp_folder)) == 0:
                manifest = _extract_app_from_file(app_tmp_folder +'.zip', remove=True)
        else:
            git_result_2 = 0

        # Store remote repository info into the returned manifest
        manifest['remote'] = {
            'type': 'git',
            'url': app_info['git']['url'],
            'branch': app_info['git']['branch'],
            'revision': app_info['git']['revision'],
        }

        if git_result_2 == 1:
            return manifest

        app_tmp_folder = install_tmp +'/'+ app
        if os.path.exists(app_tmp_folder): shutil.rmtree(app_tmp_folder)

        git_result   = os.system('git clone %s -b %s %s' % (app_info['git']['url'], app_info['git']['branch'], app_tmp_folder))
        git_result_2 = os.system('cd %s && git reset --hard %s' % (app_tmp_folder, str(app_info['git']['revision'])))

    if not git_result == git_result_2 == 0:
        raise MoulinetteError(errno.EIO, m18n.n('app_sources_fetch_failed'))

    msignals.display(m18n.n('done'))

    return manifest


def _installed_instance_number(app, last=False):
    """
    Check if application is installed and return instance number

    Keyword arguments:
        app -- id of App to check
        last -- Return only last instance number

    Returns:
        Number of last installed instance | List or instances

    """
    if last:
        number = 0
        try:
            installed_apps = os.listdir(apps_setting_path)
        except OSError:
            os.makedirs(apps_setting_path)
            return 0

        for installed_app in installed_apps:
            if number == 0 and app == installed_app:
                number = 1
            elif '__' in installed_app:
                if app == installed_app[:installed_app.index('__')]:
                    if int(installed_app[installed_app.index('__') + 2:]) > number:
                        number = int(installed_app[installed_app.index('__') + 2:])

        return number

    else:
        instance_number_list = []
        instances_dict = app_map(app=app, raw=True)
        for key, domain in instances_dict.items():
            for key, path in domain.items():
                instance_number_list.append(path['instance'])

        return sorted(instance_number_list)


def _is_installed(app):
    """
    Check if application is installed

    Keyword arguments:
        app -- id of App to check

    Returns:
        Boolean

    """
    return os.path.isdir(apps_setting_path + app)


def _value_for_locale(values):
    """
    Return proper value for current locale

    Keyword arguments:
        values -- A dict of values associated to their locale

    Returns:
        An utf-8 encoded string

    """
    if not isinstance(values, dict):
        return values

    for lang in [m18n.locale, m18n.default_locale]:
        try:
            return _encode_string(values[lang])
        except KeyError:
            continue

    # Fallback to first value
    return _encode_string(values.values()[0])


def _encode_string(value):
    """
    Return the string encoded in utf-8 if needed
    """
    if isinstance(value, unicode):
        return value.encode('utf8')
    return value


def _parse_args_from_manifest(manifest, action, args={}, auth=None):
    """Parse arguments needed for an action from the manifest

    Retrieve specified arguments for the action from the manifest, and parse
    given args according to that. If some required arguments are not provided,
    its values will be asked if interaction is possible.
    Parsed arguments will be returned as a list of strings to pass directly
    to the proper script.

    Keyword arguments:
        manifest -- The app manifest to use
        action -- The action to retrieve arguments for
        args -- A dictionnary of arguments to parse

    """
    from yunohost.domain import domain_list
    from yunohost.user import user_info

    args_list = []
    try:
        action_args = manifest['arguments'][action]
    except KeyError:
        logger.debug("no arguments found for '%s' in manifest", action)
    else:
        for arg in action_args:
            arg_name = arg['name']
            arg_value = None

            # Attempt to retrieve argument value
            if arg_name in args:
                arg_value = args[arg_name]
            else:
                if os.isatty(1) and 'ask' in arg:
                    # Retrieve proper ask string
                    ask_string = _value_for_locale(arg['ask'])

                    # Append extra strings
                    if 'choices' in arg:
                        ask_string += ' [{:s}]'.format(' | '.join(arg['choices']))
                    if 'default' in arg:
                        ask_string += ' (default: {:s})'.format(arg['default'])

                    input_string = msignals.prompt(ask_string)
                    if not input_string and 'default' in arg:
                        arg_value = arg['default']
                    else:
                        arg_value = input_string
                elif 'default' in arg:
                    arg_value = arg['default']

            # Validate argument value
            if not arg_value and not arg.get('optional', False):
                raise MoulinetteError(errno.EINVAL,
                    m18n.n('app_argument_required', name=arg_name))
            elif not arg_value:
                args_list.append('')
                continue

            # Validate argument choice
            if 'choices' in arg and arg_value not in arg['choices']:
                raise MoulinetteError(errno.EINVAL,
                    m18n.n('app_argument_choice_invalid',
                        name=arg_name, choices=', '.join(arg['choices'])))

            # Validate argument type
            # TODO: Add more type, e.g. boolean
            arg_type = arg.get('type', 'string')
            if arg_type == 'domain':
                if arg_value not in domain_list(auth)['domains']:
                    raise MoulinetteError(errno.EINVAL,
                        m18n.n('app_argument_invalid',
                            name=arg_name, error=m18n.n('domain_unknown')))
            elif arg_type == 'user':
                try:
                    user_info(auth, arg_value)
                except MoulinetteError as e:
                    raise MoulinetteError(errno.EINVAL,
                        m18n.n('app_argument_invalid',
                            name=arg_name, error=e.strerror))
            elif arg_type == 'app':
                if not _is_installed(arg_value):
                    raise MoulinetteError(errno.EINVAL,
                        m18n.n('app_argument_invalid',
                            name=arg_name, error=m18n.n('app_unknown')))
            args_list.append(arg_value)
    return args_list


def is_true(arg):
    """
    Convert a string into a boolean

    Keyword arguments:
        arg -- The string to convert

    Returns:
        Boolean

    """
    true_list = ['yes', 'Yes', 'true', 'True' ]
    for string in true_list:
        if arg == string:
            return True
    return False


def random_password(length=8):
    """
    Generate a random string

    Keyword arguments:
        length -- The string length to generate

    """
    import string, random

    char_set = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return ''.join(random.sample(char_set, length))
