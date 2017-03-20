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
import json
import shutil
import yaml
import time
import re
import socket
import urlparse
import errno
import subprocess
import requests
from collections import OrderedDict

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.service import service_log
from yunohost.utils import packages

logger = getActionLogger('yunohost.app')

REPO_PATH        = '/var/cache/yunohost/repo'
APPS_PATH        = '/usr/share/yunohost/apps'
APPS_SETTING_PATH= '/etc/yunohost/apps/'
INSTALL_TMP      = '/var/cache/yunohost'
APP_TMP_FOLDER   = INSTALL_TMP + '/from_file'

re_github_repo = re.compile(
    r'^(http[s]?://|git@)github.com[/:]'
    '(?P<owner>[\w\-_]+)/(?P<repo>[\w\-_]+)(.git)?'
    '(/tree/(?P<tree>.+))?'
)

re_app_instance_name = re.compile(
    r'^(?P<appid>[\w-]+?)(__(?P<appinstancenb>[1-9][0-9]*))?$'
)


def app_listlists():
    """
    List fetched lists


    """
    list_list = []
    try:
        for filename in os.listdir(REPO_PATH):
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
        url -- URL of remote JSON list (default https://app.yunohost.org/official.json)

    """
    # Create app path if not exists
    if not os.path.exists(REPO_PATH):
        os.makedirs(REPO_PATH)

    if url is None:
        url = 'https://app.yunohost.org/official.json'
        name = 'yunohost'
    elif name is None:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('custom_appslist_name_required'))

    # Download file
    try:
        applist_request = requests.get(url, timeout=30)
    except Exception as e:
        raise MoulinetteError(errno.EBADR, m18n.n('appslist_retrieve_error', error=str(e)))

    if (applist_request.status_code != 200):
        raise MoulinetteError(errno.EBADR, m18n.n('appslist_retrieve_error', error="404, not found"))

    # Validate app list format
    # TODO / Possible improvement : better validation for app list (check that
    # json fields actually look like an app list and not any json file)
    applist = applist_request.text
    try:
        json.loads(applist)
    except ValueError, e:
        raise MoulinetteError(errno.EBADR, m18n.n('appslist_retrieve_bad_format'))

    # Write app list to file
    list_file = '%s/%s.json' % (REPO_PATH, name)
    with open(list_file, "w") as f:
        f.write(applist)

    # Setup a cron job to re-fetch the list at midnight
    open("/etc/cron.d/yunohost-applist-%s" % name, "w").write('00 00 * * * root yunohost app fetchlist -u %s -n %s > /dev/null 2>&1\n' % (url, name))

    logger.success(m18n.n('appslist_fetched'))


def app_removelist(name):
    """
    Remove list from the repositories

    Keyword argument:
        name -- Name of the list to remove

    """
    try:
        os.remove('%s/%s.json' % (REPO_PATH, name))
        os.remove("/etc/cron.d/yunohost-applist-%s" % name)
    except OSError:
        raise MoulinetteError(errno.ENOENT, m18n.n('appslist_unknown'))

    logger.success(m18n.n('appslist_removed'))


def app_list(filter=None, raw=False, installed=False, with_backup=False):
    """
    List apps

    Keyword argument:
        filter -- Name filter of app_id or app_name
        offset -- Starting number for app fetching
        limit -- Maximum number of app fetched
        raw -- Return the full app_dict
        installed -- Return only installed apps
        with_backup -- Return only apps with backup feature (force --installed filter)

    """
    installed = with_backup or installed

    app_dict = {}
    list_dict = {} if raw else []

    try:
        applists = app_listlists()['lists']
        applists[0]
    except (IOError, IndexError):
        app_fetchlist()
        applists = app_listlists()['lists']

    # Construct a dictionnary of apps, based on known app lists
    for applist in applists:
        with open(os.path.join(REPO_PATH, applist + '.json')) as json_list:
            for app, info in json.load(json_list).items():
                if app not in app_dict:
                    info['repository'] = applist
                    app_dict[app] = info

    # Get app list from the app settings directory
    for app in os.listdir(APPS_SETTING_PATH):
        if app not in app_dict:
            # Handle multi-instance case like wordpress__2
            if '__' in app:
                original_app = app[:app.index('__')]
                if original_app in app_dict:
                    app_dict[app] = app_dict[original_app]
                    continue
                # FIXME : What if it's not !?!?

            with open(os.path.join(APPS_SETTING_PATH, app, 'manifest.json')) as json_manifest:
                app_dict[app] = {"manifest": json.load(json_manifest)}

            app_dict[app]['repository'] = None

    # Sort app list
    sorted_app_list = sorted(app_dict.keys())

    for app_id in sorted_app_list:

        app_info_dict = app_dict[app_id]

        # Apply filter if there's one
        if (filter and
           (filter not in app_id) and
           (filter not in app_info_dict['manifest']['name'])):
            continue

        # Ignore non-installed app if user wants only installed apps
        app_installed = _is_installed(app_id)
        if installed and not app_installed:
            continue

        # Ignore apps which don't have backup/restore script if user wants
        # only apps with backup features
        if with_backup and (
            not os.path.isfile(APPS_SETTING_PATH + app_id + '/scripts/backup') or
            not os.path.isfile(APPS_SETTING_PATH + app_id + '/scripts/restore')
        ):
            continue

        if raw:
            app_info_dict['installed'] = app_installed
            if app_installed:
                app_info_dict['status'] = _get_app_status(app_id)

            # dirty: we used to have manifest containing multi_instance value in form of a string
            # but we've switched to bool, this line ensure retrocompatibility
            app_info_dict["manifest"]["multi_instance"] = is_true(app_info_dict["manifest"].get("multi_instance", False))

            list_dict[app_id] = app_info_dict

        else:
            label = None
            if app_installed:
                app_info_dict_raw = app_info(app=app_id, raw=True)
                label = app_info_dict_raw['settings']['label']

            list_dict.append({
                'id': app_id,
                'name': app_info_dict['manifest']['name'],
                'label': label,
                'description': _value_for_locale(app_info_dict['manifest']['description']),
                # FIXME: Temporarly allow undefined license
                'license': app_info_dict['manifest'].get('license', m18n.n('license_undefined')),
                'installed': app_installed
            })

    return {'apps': list_dict} if not raw else list_dict


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
                              m18n.n('app_not_installed', app=app))
    if raw:
        ret = app_list(filter=app, raw=True)[app]
        ret['settings'] = _get_app_settings(app)
        return ret

    app_setting_path = APPS_SETTING_PATH + app

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
    apps = []
    result = {}

    if app is not None:
        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app=app))
        apps = [app,]
    else:
        apps = os.listdir(APPS_SETTING_PATH)

    for app_id in apps:
        app_settings = _get_app_settings(app_id)
        if not app_settings:
            continue
        if 'domain' not in app_settings:
            continue
        if user is not None:
            if ('mode' not in app_settings \
                    or ('mode' in app_settings \
                        and app_settings['mode'] == 'private')) \
                and 'allowed_users' in app_settings \
                and user not in app_settings['allowed_users'].split(','):
                continue

        domain = app_settings['domain']
        path = app_settings.get('path', '/')

        if raw:
            if domain not in result:
                result[domain] = {}
            result[domain][path] = {
                'label': app_settings['label'],
                'id': app_settings['id']
            }
        else:
            result[domain + path] = app_settings['label']

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
        if not url and not file:
            app = [app["id"] for app in app_list(installed=True)["apps"]]
    elif not isinstance(app, list):
        app = [app]

    logger.info("Upgrading apps %s", ", ".join(app))

    for app_instance_name in app:
        installed = _is_installed(app_instance_name)
        if not installed:
            raise MoulinetteError(errno.ENOPKG,
                                  m18n.n('app_not_installed', app=app_instance_name))

        if app_instance_name in upgraded_apps:
            continue

        app_dict = app_info(app_instance_name, raw=True)

        locale_update_time = app_dict['settings'].get('update_time', app_dict['settings']['install_time'])

        if file:
            manifest, extracted_app_folder = _extract_app_from_file(file)
        elif url:
            manifest, extracted_app_folder = _fetch_app_from_git(url)
        elif 'lastUpdate' not in app_dict or 'git' not in app_dict:
            logger.warning(m18n.n('custom_app_url_required', app=app_instance_name))
            continue
        elif app_dict['lastUpdate'] > locale_update_time:
            manifest, extracted_app_folder = _fetch_app_from_git(app_instance_name)
        else:
            continue

        # Check requirements
        _check_manifest_requirements(manifest)

        app_setting_path = APPS_SETTING_PATH +'/'+ app_instance_name
        
        # Retrieve current app status
        status = _get_app_status(app_instance_name)
        status['remote'] = manifest.get('remote', None)

        # Retrieve arguments list for upgrade script
        # TODO: Allow to specify arguments
        args_odict = _parse_args_from_manifest(manifest, 'upgrade', auth=auth)
        args_list = args_odict.values()
        args_list.append(app_instance_name)

        # Prepare env. var. to pass to script
        env_dict = _make_environment_dict(args_odict)
        app_id, app_instance_nb = _parse_app_instance_name(app_instance_name)
        env_dict["YNH_APP_ID"] = app_id
        env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
        env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)

        # Execute App upgrade script
        os.system('chown -hR admin: %s' % INSTALL_TMP)
        if hook_exec(extracted_app_folder + '/scripts/upgrade', args=args_list, env=env_dict, user="root") != 0:
            logger.error(m18n.n('app_upgrade_failed', app=app_instance_name))
        else:
            now = int(time.time())
            # TODO: Move install_time away from app_setting
            app_setting(app_instance_name, 'update_time', now)
            status['upgraded_at'] = now

            # Clean hooks and add new ones
            hook_remove(app_instance_name)
            if 'hooks' in os.listdir(extracted_app_folder):
                for hook in os.listdir(extracted_app_folder +'/hooks'):
                    hook_add(app_instance_name, extracted_app_folder +'/hooks/'+ hook)

            # Store app status
            with open(app_setting_path + '/status.json', 'w+') as f:
                json.dump(status, f)

            # Replace scripts and manifest
            os.system('rm -rf "%s/scripts" "%s/manifest.json"' % (app_setting_path, app_setting_path))
            os.system('mv "%s/manifest.json" "%s/scripts" %s' % (extracted_app_folder, extracted_app_folder, app_setting_path))

            # So much win
            upgraded_apps.append(app_instance_name)
            logger.success(m18n.n('app_upgraded', app=app_instance_name))

    if not upgraded_apps:
        raise MoulinetteError(errno.ENODATA, m18n.n('app_no_upgrade'))

    app_ssowatconf(auth)

    logger.success(m18n.n('upgrade_complete'))


def app_install(auth, app, label=None, args=None, no_remove_on_failure=False):
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation
        no_remove_on_failure -- Debug option to avoid removing the app on a failed installation

    """
    from yunohost.hook import hook_add, hook_remove, hook_exec

    # Fetch or extract sources
    try: os.listdir(INSTALL_TMP)
    except OSError: os.makedirs(INSTALL_TMP)

    status = {
        'installed_at': int(time.time()),
        'upgraded_at': None,
        'remote': {
            'type': None,
        },
    }

    if app in app_list(raw=True) or ('@' in app) or ('http://' in app) or ('https://' in app):
        manifest, extracted_app_folder = _fetch_app_from_git(app)
    elif os.path.exists(app):
        manifest, extracted_app_folder = _extract_app_from_file(app)
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))
    status['remote'] = manifest.get('remote', {})

    # Check ID
    if 'id' not in manifest or '__' in manifest['id']:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_id_invalid'))

    app_id = manifest['id']

    # Check requirements
    _check_manifest_requirements(manifest)

    # Check if app can be forked
    instance_number = _installed_instance_number(app_id, last=True) + 1
    if instance_number > 1 :
        if 'multi_instance' not in manifest or not is_true(manifest['multi_instance']):
            raise MoulinetteError(errno.EEXIST,
                                  m18n.n('app_already_installed', app=app_id))

        # Change app_id to the forked app id
        app_instance_name = app_id + '__' + str(instance_number)
    else:
        app_instance_name = app_id

    # Retrieve arguments list for install script
    args_dict = {} if not args else \
        dict(urlparse.parse_qsl(args, keep_blank_values=True))
    args_odict = _parse_args_from_manifest(manifest, 'install', args=args_dict, auth=auth)
    args_list = args_odict.values()
    args_list.append(app_instance_name)

    # Prepare env. var. to pass to script
    env_dict = _make_environment_dict(args_odict)
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(instance_number)

    # Create app directory
    app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)
    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)
    os.makedirs(app_setting_path)

    # Set initial app settings
    app_settings = {
        'id': app_instance_name,
        'label': label if label else manifest['name'],
    }
    # TODO: Move install_time away from app settings
    app_settings['install_time'] = status['installed_at']
    _set_app_settings(app_instance_name, app_settings)

    os.system('chown -R admin: '+ extracted_app_folder)

    # Execute App install script
    os.system('chown -hR admin: %s' % INSTALL_TMP)
    # Move scripts and manifest to the right place
    os.system('cp %s/manifest.json %s' % (extracted_app_folder, app_setting_path))
    os.system('cp -R %s/scripts %s' % (extracted_app_folder, app_setting_path))

    # Execute the app install script
    install_retcode = 1
    try:
        install_retcode = hook_exec(
            os.path.join(extracted_app_folder, 'scripts/install'),
            args=args_list, env=env_dict, user="root")
    except (KeyboardInterrupt, EOFError):
        install_retcode = -1
    except:
        logger.exception(m18n.n('unexpected_error'))
    finally:
        if install_retcode != 0:
            if not no_remove_on_failure:
                # Setup environment for remove script
                env_dict_remove = {}
                env_dict_remove["YNH_APP_ID"] = app_id
                env_dict_remove["YNH_APP_INSTANCE_NAME"] = app_instance_name
                env_dict_remove["YNH_APP_INSTANCE_NUMBER"] = str(instance_number)

                # Execute remove script
                remove_retcode = hook_exec(
                    os.path.join(extracted_app_folder, 'scripts/remove'),
                    args=[app_instance_name], env=env_dict_remove, user="root")
                if remove_retcode != 0:
                    logger.warning(m18n.n('app_not_properly_removed',
                                          app=app_instance_name))

            # Clean tmp folders
            shutil.rmtree(app_setting_path)
            shutil.rmtree(extracted_app_folder)

            app_ssowatconf(auth)

            if install_retcode == -1:
                raise MoulinetteError(errno.EINTR,
                                      m18n.g('operation_interrupted'))
            raise MoulinetteError(errno.EIO, m18n.n('installation_failed'))

    # Clean hooks and add new ones
    hook_remove(app_instance_name)
    if 'hooks' in os.listdir(extracted_app_folder):
        for file in os.listdir(extracted_app_folder +'/hooks'):
            hook_add(app_instance_name, extracted_app_folder +'/hooks/'+ file)

    # Store app status
    with open(app_setting_path + '/status.json', 'w+') as f:
        json.dump(status, f)

    # Clean and set permissions
    shutil.rmtree(extracted_app_folder)
    os.system('chmod -R 400 %s' % app_setting_path)
    os.system('chown -R root: %s' % app_setting_path)
    os.system('chown -R admin: %s/scripts' % app_setting_path)

    app_ssowatconf(auth)

    logger.success(m18n.n('installation_complete'))


def app_remove(auth, app):
    """
    Remove app

    Keyword argument:
        app -- App(s) to delete

    """
    from yunohost.hook import hook_exec, hook_remove

    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('app_not_installed', app=app))

    app_setting_path = APPS_SETTING_PATH + app

    #TODO: display fail messages from script
    try:
        shutil.rmtree('/tmp/yunohost_remove')
    except: pass

    os.system('cp -a %s /tmp/yunohost_remove && chown -hR admin: /tmp/yunohost_remove' % app_setting_path)
    os.system('chown -R admin: /tmp/yunohost_remove')
    os.system('chmod -R u+rX /tmp/yunohost_remove')

    args_list = [app]

    env_dict = {}
    app_id, app_instance_nb = _parse_app_instance_name(app)
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)

    if hook_exec('/tmp/yunohost_remove/scripts/remove', args=args_list, env=env_dict, user="root") == 0:
        logger.success(m18n.n('app_removed', app=app))

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

    result = {}

    if not users:
        users = user_list(auth)['users'].keys()
    elif not isinstance(users, list):
        users = [users,]
    if not isinstance(apps, list):
        apps = [apps,]

    for app in apps:
        app_settings = _get_app_settings(app)
        if not app_settings:
            continue

        if 'mode' not in app_settings:
            app_setting(app, 'mode', 'private')
            app_settings['mode'] = 'private'

        if app_settings['mode'] == 'private':
            allowed_users = set()
            if 'allowed_users' in app_settings:
                allowed_users = set(app_settings['allowed_users'].split(','))

            for allowed_user in users:
                if allowed_user not in allowed_users:
                    try:
                        user_info(auth, allowed_user)
                    except MoulinetteError:
                        logger.warning(m18n.n('user_unknown', user=allowed_user))
                        continue
                    allowed_users.add(allowed_user)

            new_users = ','.join(allowed_users)
            app_setting(app, 'allowed_users', new_users)
            hook_callback('post_app_addaccess', args=[app, new_users])

            result[app] = allowed_users

    app_ssowatconf(auth)

    return { 'allowed_users': result }


def app_removeaccess(auth, apps, users=[]):
    """
    Revoke access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.user import user_list
    from yunohost.hook import hook_callback

    result = {}

    remove_all = False
    if not users:
        remove_all = True
    elif not isinstance(users, list):
        users = [users,]
    if not isinstance(apps, list):
        apps = [apps,]

    for app in apps:
        app_settings = _get_app_settings(app)
        if not app_settings:
            continue
        allowed_users = set()

        if app_settings.get('skipped_uris', '') != '/':
            if remove_all:
                pass
            elif 'allowed_users' in app_settings:
                for allowed_user in app_settings['allowed_users'].split(','):
                    if allowed_user not in users:
                        allowed_users.add(allowed_user)
            else:
                for allowed_user in user_list(auth)['users'].keys():
                    if allowed_user not in users:
                        allowed_users.add(allowed_user)

            new_users = ','.join(allowed_users)
            app_setting(app, 'allowed_users', new_users)
            hook_callback('post_app_removeaccess', args=[app, new_users])

            result[app] = allowed_users

    app_ssowatconf(auth)

    return { 'allowed_users': result }


def app_clearaccess(auth, apps):
    """
    Reset access rights for the app

    Keyword argument:
        apps

    """
    from yunohost.hook import hook_callback

    if not isinstance(apps, list): apps = [apps]

    for app in apps:
        app_settings = _get_app_settings(app)
        if not app_settings:
            continue

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
    with open(APPS_SETTING_PATH + app + '/manifest.json') as f:
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

    app_settings = _get_app_settings(app)
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
    except ValueError as e:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('ssowat_persistent_conf_read_error', error=e.strerror))
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls'][domain +'/'] = app_domain + app_path

    try:
        with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
            json.dump(ssowat_conf, f, sort_keys=True, indent=4)
    except IOError as e:
        raise MoulinetteError(errno.EPERM,
                              m18n.n('ssowat_persistent_conf_write_error', error=e.strerror))


    os.system('chmod 644 /etc/ssowat/conf.json.persistent')

    logger.success(m18n.n('ssowat_conf_updated'))


def app_setting(app, key, value=None, delete=False):
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """
    app_settings = _get_app_settings(app) or {}

    if value is None and not delete:
        try:
            return app_settings[key]
        except:
            logger.info("cannot get app setting '%s' for '%s'", key, app)
            return None
    else:
        if delete and key in app_settings:
            del app_settings[key]
        else:
            # FIXME: Allow multiple values for some keys?
            if key in ['redirected_urls','redirected_regex']:
                value = yaml.load(value)
            app_settings[key] = value
        _set_app_settings(app, app_settings)


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
        logger.success(m18n.n('port_available', port=int(port)))
    else:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('port_unavailable', port=int(port)))


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
        # Loop through apps
        for p, a in apps_map[domain].items():
            # Skip requested app checking
            if app is not None and a['id'] == app:
                installed = True
                continue
            if path == p:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('app_location_already_used'))
            elif path.startswith(p) or p.startswith(path):
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

    logger.success(m18n.n('mysql_db_initialized'))


def app_ssowatconf(auth):
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.user import user_list

    main_domain = _get_maindomain()
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

    try:
        apps_list = app_list()['apps']
    except:
        apps_list = []

    def _get_setting(settings, name):
        s = settings.get(name, None)
        return s.split(',') if s else []

    for app in apps_list:
        if _is_installed(app['id']):
            with open(APPS_SETTING_PATH + app['id'] +'/settings.yml') as f:
                app_settings = yaml.load(f)
                for item in _get_setting(app_settings, 'skipped_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    skipped_urls.append(app_settings['domain'] + app_settings['path'].rstrip('/') + item)
                for item in _get_setting(app_settings, 'skipped_regex'):
                    skipped_regex.append(item)
                for item in _get_setting(app_settings, 'unprotected_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    unprotected_urls.append(app_settings['domain'] + app_settings['path'].rstrip('/') + item)
                for item in _get_setting(app_settings, 'unprotected_regex'):
                    unprotected_regex.append(item)
                for item in _get_setting(app_settings, 'protected_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    protected_urls.append(app_settings['domain'] + app_settings['path'].rstrip('/') + item)
                for item in _get_setting(app_settings, 'protected_regex'):
                    protected_regex.append(item)
                if 'redirected_urls' in app_settings:
                    redirected_urls.update(app_settings['redirected_urls'])
                if 'redirected_regex' in app_settings:
                    redirected_regex.update(app_settings['redirected_regex'])

    for domain in domains:
        skipped_urls.extend([domain + '/yunohost/admin', domain + '/yunohost/api'])

    # Authorize ACME challenge url
    skipped_regex.append("^[^/]*/%.well%-known/acme%-challenge/.*$")

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

    logger.success(m18n.n('ssowat_conf_generated'))


def _get_app_settings(app_id):
    """
    Get settings of an installed app

    Keyword arguments:
        app_id -- The app id

    """
    if not _is_installed(app_id):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('app_not_installed', app=app_id))
    try:
        with open(os.path.join(
                APPS_SETTING_PATH, app_id, 'settings.yml')) as f:
            settings = yaml.load(f)
        if app_id == settings['id']:
            return settings
    except (IOError, TypeError, KeyError):
        logger.exception(m18n.n('app_not_correctly_installed',
                                app=app_id))
    return {}


def _set_app_settings(app_id, settings):
    """
    Set settings of an app

    Keyword arguments:
        app_id -- The app id
        settings -- Dict with app settings

    """
    with open(os.path.join(
            APPS_SETTING_PATH, app_id, 'settings.yml'), 'w') as f:
        yaml.safe_dump(settings, f, default_flow_style=False)


def _get_app_status(app_id, format_date=False):
    """
    Get app status or create it if needed

    Keyword arguments:
        app_id -- The app id
        format_date -- Format date fields

    """
    app_setting_path = APPS_SETTING_PATH + app_id
    if not os.path.isdir(app_setting_path):
        raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))
    status = {}

    try:
        with open(app_setting_path + '/status.json') as f:
            status = json.loads(str(f.read()))
    except IOError:
        logger.debug("status file not found for '%s'", app_id,
                     exc_info=1)
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
    Unzip or untar application tarball in APP_TMP_FOLDER, or copy it from a directory

    Keyword arguments:
        path -- Path of the tarball or directory
        remove -- Remove the tarball after extraction

    Returns:
        Dict manifest

    """
    logger.info(m18n.n('extracting'))

    if os.path.exists(APP_TMP_FOLDER): shutil.rmtree(APP_TMP_FOLDER)
    os.makedirs(APP_TMP_FOLDER)

    path = os.path.abspath(path)

    if ".zip" in path:
        extract_result = os.system('unzip %s -d %s > /dev/null 2>&1' % (path, APP_TMP_FOLDER))
        if remove: os.remove(path)
    elif ".tar" in path:
        extract_result = os.system('tar -xf %s -C %s > /dev/null 2>&1' % (path, APP_TMP_FOLDER))
        if remove: os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(APP_TMP_FOLDER)
        if path[len(path)-1:] != '/':
            path = path + '/'
        extract_result = os.system('cp -a "%s" %s' % (path, APP_TMP_FOLDER))
    else:
        extract_result = 1

    if extract_result != 0:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_extraction_failed'))

    try:
        extracted_app_folder = APP_TMP_FOLDER
        if len(os.listdir(extracted_app_folder)) == 1:
            for folder in os.listdir(extracted_app_folder):
                extracted_app_folder = extracted_app_folder +'/'+ folder
        with open(extracted_app_folder + '/manifest.json') as json_manifest:
            manifest = json.loads(str(json_manifest.read()))
            manifest['lastUpdate'] = int(time.time())
    except IOError:
        raise MoulinetteError(errno.EIO, m18n.n('app_install_files_invalid'))

    logger.info(m18n.n('done'))

    manifest['remote'] = {'type': 'file', 'path': path}
    return manifest, extracted_app_folder


def _get_git_last_commit_hash(repository, reference='HEAD'):
    """
    Attempt to retrieve the last commit hash of a git repository

    Keyword arguments:
        repository -- The URL or path of the repository

    """
    try:
        commit = subprocess.check_output(
            "git ls-remote --exit-code {0} {1} | awk '{{print $1}}'".format(
                repository, reference),
            shell=True)
    except subprocess.CalledProcessError:
        logger.exception("unable to get last commit from %s", repository)
        raise ValueError("Unable to get last commit with git")
    else:
        return commit.strip()


def _fetch_app_from_git(app):
    """
    Unzip or untar application tarball in APP_TMP_FOLDER

    Keyword arguments:
        app -- App_id or git repo URL

    Returns:
        Dict manifest

    """
    extracted_app_folder = APP_TMP_FOLDER

    app_tmp_archive = '{0}.zip'.format(extracted_app_folder)
    if os.path.exists(extracted_app_folder):
        shutil.rmtree(extracted_app_folder)
    if os.path.exists(app_tmp_archive):
        os.remove(app_tmp_archive)

    logger.info(m18n.n('downloading'))

    if ('@' in app) or ('http://' in app) or ('https://' in app):
        url = app
        branch = 'master'
        github_repo = re_github_repo.match(app)
        if github_repo:
            if github_repo.group('tree'):
                branch = github_repo.group('tree')
            url = "https://github.com/{owner}/{repo}".format(
                owner=github_repo.group('owner'),
                repo=github_repo.group('repo'),
            )
            tarball_url = "{url}/archive/{tree}.zip".format(
                url=url, tree=branch
            )
            try:
                subprocess.check_call([
                    'wget', '-qO', app_tmp_archive, tarball_url])
            except subprocess.CalledProcessError:
                logger.exception('unable to download %s', tarball_url)
                raise MoulinetteError(errno.EIO,
                                      m18n.n('app_sources_fetch_failed'))
            else:
                manifest, extracted_app_folder = _extract_app_from_file(
                    app_tmp_archive, remove=True)
        else:
            tree_index = url.rfind('/tree/')
            if tree_index > 0:
                url = url[:tree_index]
                branch = app[tree_index+6:]
            try:
                # We use currently git 2.1 so we can't use --shallow-submodules
                # option. When git will be in 2.9 (with the new debian version)
                # we will be able to use it. Without this option all the history
                # of the submodules repo is downloaded.
                subprocess.check_call([
                    'git', 'clone', '--depth=1', '--recursive', url,
                    extracted_app_folder])
                subprocess.check_call([
                        'git', 'reset', '--hard', branch
                    ], cwd=extracted_app_folder)
                with open(extracted_app_folder + '/manifest.json') as f:
                    manifest = json.loads(str(f.read()))
            except subprocess.CalledProcessError:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('app_sources_fetch_failed'))
            except IOError:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('app_manifest_invalid'))
            else:
                logger.info(m18n.n('done'))

        # Store remote repository info into the returned manifest
        manifest['remote'] = {'type': 'git', 'url': url, 'branch': branch}
        try:
            revision = _get_git_last_commit_hash(url, branch)
        except: pass
        else:
            manifest['remote']['revision'] = revision
    else:
        app_dict = app_list(raw=True)

        if app in app_dict:
            app_info = app_dict[app]
            app_info['manifest']['lastUpdate'] = app_info['lastUpdate']
            manifest = app_info['manifest']
        else:
            raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))

        if not 'git' in app_info:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_unsupported_remote_type'))
        url = app_info['git']['url']

        if 'github.com' in url:
            tarball_url = "{url}/archive/{tree}.zip".format(
                url=url, tree=app_info['git']['revision']
            )
            try:
                subprocess.check_call([
                    'wget', '-qO', app_tmp_archive, tarball_url])
            except subprocess.CalledProcessError:
                logger.exception('unable to download %s', tarball_url)
                raise MoulinetteError(errno.EIO,
                                      m18n.n('app_sources_fetch_failed'))
            else:
                manifest, extracted_app_folder = _extract_app_from_file(
                    app_tmp_archive, remove=True)
        else:
            try:
                subprocess.check_call([
                    'git', 'clone', app_info['git']['url'],
                    '-b', app_info['git']['branch'], extracted_app_folder])
                subprocess.check_call([
                        'git', 'reset', '--hard',
                        str(app_info['git']['revision'])
                    ], cwd=extracted_app_folder)
                with open(extracted_app_folder + '/manifest.json') as f:
                    manifest = json.loads(str(f.read()))
            except subprocess.CalledProcessError:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('app_sources_fetch_failed'))
            except IOError:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('app_manifest_invalid'))
            else:
                logger.info(m18n.n('done'))

        # Store remote repository info into the returned manifest
        manifest['remote'] = {
            'type': 'git',
            'url': url,
            'branch': app_info['git']['branch'],
            'revision': app_info['git']['revision'],
        }

    return manifest, extracted_app_folder


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
            installed_apps = os.listdir(APPS_SETTING_PATH)
        except OSError:
            os.makedirs(APPS_SETTING_PATH)
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
    return os.path.isdir(APPS_SETTING_PATH + app)


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


def _check_manifest_requirements(manifest):
    """Check if required packages are met from the manifest"""
    requirements = manifest.get('requirements', dict())

    # FIXME: Deprecate min_version key
    if 'min_version' in manifest:
        requirements['yunohost'] = '>> {0}'.format(manifest['min_version'])
        logger.debug("the manifest key 'min_version' is deprecated, "
                     "use 'requirements' instead.")

    # Validate multi-instance app
    if is_true(manifest.get('multi_instance', False)):
        # Handle backward-incompatible change introduced in yunohost >= 2.3.6
        # See https://dev.yunohost.org/issues/156
        yunohost_req = requirements.get('yunohost', None)
        if (not yunohost_req or
                not packages.SpecifierSet(yunohost_req) & '>= 2.3.6'):
            raise MoulinetteError(errno.EINVAL, '{0}{1}'.format(
                m18n.g('colon', m18n.n('app_incompatible')),
                m18n.n('app_package_need_update')))
    elif not requirements:
        return

    logger.info(m18n.n('app_requirements_checking'))

    # Retrieve versions of each required package
    try:
        versions = packages.get_installed_version(
            *requirements.keys(), strict=True, as_dict=True)
    except packages.PackageException as e:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('app_requirements_failed',
                                     error=str(e)))

    # Iterate over requirements
    for pkgname, spec in requirements.items():
        version = versions[pkgname]
        if version not in packages.SpecifierSet(spec):
            raise MoulinetteError(
                errno.EINVAL, m18n.n('app_requirements_unmeet',
                                     pkgname=pkgname, version=version,
                                     spec=spec))

def _parse_args_from_manifest(manifest, action, args={}, auth=None):
    """Parse arguments needed for an action from the manifest

    Retrieve specified arguments for the action from the manifest, and parse
    given args according to that. If some required arguments are not provided,
    its values will be asked if interaction is possible.
    Parsed arguments will be returned as an OrderedDict

    Keyword arguments:
        manifest -- The app manifest to use
        action -- The action to retrieve arguments for
        args -- A dictionnary of arguments to parse

    """
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.user import user_info

    args_dict = OrderedDict()
    try:
        action_args = manifest['arguments'][action]
    except KeyError:
        logger.debug("no arguments found for '%s' in manifest", action)
    else:
        for arg in action_args:
            arg_name = arg['name']
            arg_type = arg.get('type', 'string')
            arg_default = arg.get('default', None)
            arg_choices = arg.get('choices', [])
            arg_value = None

            # Transpose default value for boolean type and set it to
            # false if not defined.
            if arg_type == 'boolean':
                arg_default = 1 if arg_default else 0

            # Attempt to retrieve argument value
            if arg_name in args:
                arg_value = args[arg_name]
            else:
                if 'ask' in arg:
                    # Retrieve proper ask string
                    ask_string = _value_for_locale(arg['ask'])

                    # Append extra strings
                    if arg_type == 'boolean':
                        ask_string += ' [0 | 1]'
                    elif arg_choices:
                        ask_string += ' [{0}]'.format(' | '.join(arg_choices))
                    if arg_default is not None:
                        ask_string += ' (default: {0})'.format(arg_default)

                    # Check for a password argument
                    is_password = True if arg_type == 'password' else False

                    if arg_type == 'domain':
                        arg_default = _get_maindomain()
                        ask_string += ' (default: {0})'.format(arg_default)
                        msignals.display(m18n.n('domains_available'))
                        for domain in domain_list(auth)['domains']:
                            msignals.display("- {}".format(domain))

                    try:
                        input_string = msignals.prompt(ask_string, is_password)
                    except NotImplementedError:
                        input_string = None
                    if (input_string == '' or input_string is None) \
                            and arg_default is not None:
                        arg_value = arg_default
                    else:
                        arg_value = input_string
                elif arg_default is not None:
                    arg_value = arg_default

            # Validate argument value
            if (arg_value is None or arg_value == '') \
                    and not arg.get('optional', False):
                raise MoulinetteError(errno.EINVAL,
                    m18n.n('app_argument_required', name=arg_name))
            elif arg_value is None:
                args_dict[arg_name] = ''
                continue

            # Validate argument choice
            if arg_choices and arg_value not in arg_choices:
                raise MoulinetteError(errno.EINVAL,
                    m18n.n('app_argument_choice_invalid',
                        name=arg_name, choices=', '.join(arg_choices)))

            # Validate argument type
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
            elif arg_type == 'boolean':
                if isinstance(arg_value, bool):
                    arg_value = 1 if arg_value else 0
                else:
                    try:
                        arg_value = int(arg_value)
                        if arg_value not in [0, 1]:
                            raise ValueError()
                    except (TypeError, ValueError):
                        raise MoulinetteError(errno.EINVAL,
                            m18n.n('app_argument_choice_invalid',
                                name=arg_name, choices='0, 1'))
            args_dict[arg_name] = arg_value
    return args_dict

def _make_environment_dict(args_dict):
    """
    Convert a dictionnary containing manifest arguments
    to a dictionnary of env. var. to be passed to scripts

    Keyword arguments:
        arg -- A key/value dictionnary of manifest arguments

    """
    env_dict = {}
    for arg_name, arg_value in args_dict.items():
        env_dict[ "YNH_APP_ARG_%s" % arg_name.upper() ] = arg_value
    return env_dict

def _parse_app_instance_name(app_instance_name):
    """
    Parse a Yunohost app instance name and extracts the original appid
    and the application instance number

    >>> _parse_app_instance_name('yolo') == ('yolo', 1)
    True
    >>> _parse_app_instance_name('yolo1') == ('yolo1', 1)
    True
    >>> _parse_app_instance_name('yolo__0') == ('yolo__0', 1)
    True
    >>> _parse_app_instance_name('yolo__1') == ('yolo', 1)
    True
    >>> _parse_app_instance_name('yolo__23') == ('yolo', 23)
    True
    >>> _parse_app_instance_name('yolo__42__72') == ('yolo__42', 72)
    True
    >>> _parse_app_instance_name('yolo__23qdqsd') == ('yolo__23qdqsd', 1)
    True
    >>> _parse_app_instance_name('yolo__23qdqsd56') == ('yolo__23qdqsd56', 1)
    True
    """
    match = re_app_instance_name.match(app_instance_name)
    appid = match.groupdict().get('appid')
    app_instance_nb = int(match.groupdict().get('appinstancenb')) if match.groupdict().get('appinstancenb') is not None else 1
    return (appid, app_instance_nb)

def is_true(arg):
    """
    Convert a string into a boolean

    Keyword arguments:
        arg -- The string to convert

    Returns:
        Boolean

    """
    if isinstance(arg, bool):
        return arg
    elif isinstance(arg, basestring):
        true_list = ['yes', 'Yes', 'true', 'True' ]
        for string in true_list:
            if arg == string:
                return True
        return False
    else:
        logger.debug('arg should be a boolean or a string, got %r', arg)
        return True if arg else False


def random_password(length=8):
    """
    Generate a random string

    Keyword arguments:
        length -- The string length to generate

    """
    import string, random

    char_set = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return ''.join(random.sample(char_set, length))
