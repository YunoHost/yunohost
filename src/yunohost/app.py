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
import toml
import json
import shutil
import yaml
import time
import re
import urlparse
import subprocess
import glob
import pwd
import grp
import urllib
from collections import OrderedDict
from datetime import datetime

from moulinette import msignals, m18n, msettings
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_json

from yunohost.service import service_log, service_status, _run_service_command
from yunohost.utils import packages
from yunohost.utils.error import YunohostError
from yunohost.log import is_unit_operation, OperationLogger

logger = getActionLogger('yunohost.app')

REPO_PATH = '/var/cache/yunohost/repo'
APPS_PATH = '/usr/share/yunohost/apps'
APPS_SETTING_PATH = '/etc/yunohost/apps/'
INSTALL_TMP = '/var/cache/yunohost'
APP_TMP_FOLDER = INSTALL_TMP + '/from_file'
APPSLISTS_JSON = '/etc/yunohost/appslists.json'

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

    # Migrate appslist system if needed
    # XXX move to a migration when those are implemented
    if _using_legacy_appslist_system():
        _migrate_appslist_system()

    # Get the list
    appslist_list = _read_appslist_list()

    # Convert 'lastUpdate' timestamp to datetime
    for name, infos in appslist_list.items():
        if infos["lastUpdate"] is None:
            infos["lastUpdate"] = 0
        infos["lastUpdate"] = datetime.utcfromtimestamp(infos["lastUpdate"])

    return appslist_list


def app_fetchlist(url=None, name=None):
    """
    Fetch application list(s) from app server. By default, fetch all lists.

    Keyword argument:
        name -- Name of the list
        url -- URL of remote JSON list
    """
    if url and not url.endswith(".json"):
        raise YunohostError("This is not a valid application list url. It should end with .json.")

    # If needed, create folder where actual appslists are stored
    if not os.path.exists(REPO_PATH):
        os.makedirs(REPO_PATH)

    # Migrate appslist system if needed
    # XXX move that to a migration once they are finished
    if _using_legacy_appslist_system():
        _migrate_appslist_system()

    # Read the list of appslist...
    appslists = _read_appslist_list()

    # Determine the list of appslist to be fetched
    appslists_to_be_fetched = []

    # If a url and and a name is given, try to register new list,
    # the fetch only this list
    if url is not None:
        if name:
            operation_logger = OperationLogger('app_fetchlist')
            operation_logger.start()
            _register_new_appslist(url, name)
            # Refresh the appslists dict
            appslists = _read_appslist_list()
            appslists_to_be_fetched = [name]
            operation_logger.success()
        else:
            raise YunohostError('custom_appslist_name_required')

    # If a name is given, look for an appslist with that name and fetch it
    elif name is not None:
        if name not in appslists.keys():
            raise YunohostError('appslist_unknown', appslist=name)
        else:
            appslists_to_be_fetched = [name]

    # Otherwise, fetch all lists
    else:
        appslists_to_be_fetched = appslists.keys()

    import requests  # lazy loading this module for performance reasons
    # Fetch all appslists to be fetched
    for name in appslists_to_be_fetched:

        url = appslists[name]["url"]

        logger.debug("Attempting to fetch list %s at %s" % (name, url))

        # Download file
        try:
            appslist_request = requests.get(url, timeout=30)
        except requests.exceptions.SSLError:
            logger.error(m18n.n('appslist_retrieve_error',
                                appslist=name,
                                error="SSL connection error"))
            continue
        except Exception as e:
            logger.error(m18n.n('appslist_retrieve_error',
                                appslist=name,
                                error=str(e)))
            continue
        if appslist_request.status_code != 200:
            logger.error(m18n.n('appslist_retrieve_error',
                                appslist=name,
                                error="Server returned code %s " %
                                str(appslist_request.status_code)))
            continue

        # Validate app list format
        # TODO / Possible improvement : better validation for app list (check
        # that json fields actually look like an app list and not any json
        # file)
        appslist = appslist_request.text
        try:
            json.loads(appslist)
        except ValueError as e:
            logger.error(m18n.n('appslist_retrieve_bad_format',
                                appslist=name))
            continue

        # Write app list to file
        list_file = '%s/%s.json' % (REPO_PATH, name)
        try:
            with open(list_file, "w") as f:
                f.write(appslist)
        except Exception as e:
            raise YunohostError("Error while writing appslist %s: %s" % (name, str(e)), raw_msg=True)

        now = int(time.time())
        appslists[name]["lastUpdate"] = now

        logger.success(m18n.n('appslist_fetched', appslist=name))

    # Write updated list of appslist
    _write_appslist_list(appslists)


@is_unit_operation()
def app_removelist(operation_logger, name):
    """
    Remove list from the repositories

    Keyword argument:
        name -- Name of the list to remove

    """
    appslists = _read_appslist_list()

    # Make sure we know this appslist
    if name not in appslists.keys():
        raise YunohostError('appslist_unknown', appslist=name)

    operation_logger.start()

    # Remove json
    json_path = '%s/%s.json' % (REPO_PATH, name)
    if os.path.exists(json_path):
        os.remove(json_path)

    # Forget about this appslist
    del appslists[name]
    _write_appslist_list(appslists)

    logger.success(m18n.n('appslist_removed', appslist=name))


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

    appslists = _read_appslist_list()

    for appslist in appslists.keys():

        json_path = "%s/%s.json" % (REPO_PATH, appslist)
        if not os.path.exists(json_path):
            app_fetchlist(name=appslist)

        with open(json_path) as json_list:
            for app, info in json.loads(str(json_list.read())).items():
                if app not in app_dict:
                    info['repository'] = appslist
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
        raise YunohostError('app_not_installed', app=app)

    app_setting_path = APPS_SETTING_PATH + app

    if raw:
        ret = app_list(filter=app, raw=True)[app]
        ret['settings'] = _get_app_settings(app)

        # Determine upgradability
        # In case there is neither update_time nor install_time, we assume the app can/has to be upgraded
        local_update_time = ret['settings'].get('update_time', ret['settings'].get('install_time', 0))

        if 'lastUpdate' not in ret or 'git' not in ret:
            upgradable = "url_required"
        elif ret['lastUpdate'] > local_update_time:
            upgradable = "yes"
        else:
            upgradable = "no"

        ret['upgradable'] = upgradable
        ret['change_url'] = os.path.exists(os.path.join(app_setting_path, "scripts", "change_url"))

        with open(os.path.join(APPS_SETTING_PATH, app, 'manifest.json')) as json_manifest:
            manifest = json.load(json_manifest)

        ret['version'] = manifest.get('version', '-')

        return ret

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
        # TODO: Add more info
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
    from yunohost.permission import user_permission_list
    from yunohost.utils.ldap import _get_ldap_interface

    apps = []
    result = {}

    if app is not None:
        if not _is_installed(app):
            raise YunohostError('app_not_installed', app=app)
        apps = [app, ]
    else:
        apps = os.listdir(APPS_SETTING_PATH)

    for app_id in apps:
        app_settings = _get_app_settings(app_id)
        if not app_settings:
            continue
        if 'domain' not in app_settings:
            continue
        if 'no_sso' in app_settings:  # I don't think we need to check for the value here
            continue
        if user is not None:
            ldap = _get_ldap_interface()
            if not ldap.search(base='ou=permission,dc=yunohost,dc=org',
                               filter='(&(objectclass=permissionYnh)(cn=main.%s)(inheritPermission=uid=%s,ou=users,dc=yunohost,dc=org))' % (app_id, user),
                               attrs=['cn']):
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


@is_unit_operation()
def app_change_url(operation_logger, app, domain, path):
    """
    Modify the URL at which an application is installed.

    Keyword argument:
        app -- Taget app instance name
        domain -- New app domain on which the application will be moved
        path -- New path at which the application will be move

    """
    from yunohost.hook import hook_exec, hook_callback
    from yunohost.domain import _normalize_domain_path, _get_conflicting_apps
    from yunohost.permission import permission_update

    installed = _is_installed(app)
    if not installed:
        raise YunohostError('app_not_installed', app=app)

    if not os.path.exists(os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url")):
        raise YunohostError("app_change_no_change_url_script", app_name=app)

    old_domain = app_setting(app, "domain")
    old_path = app_setting(app, "path")

    # Normalize path and domain format
    old_domain, old_path = _normalize_domain_path(old_domain, old_path)
    domain, path = _normalize_domain_path(domain, path)

    if (domain, path) == (old_domain, old_path):
        raise YunohostError("app_change_url_identical_domains", domain=domain, path=path)

    # Check the url is available
    conflicts = _get_conflicting_apps(domain, path, ignore_app=app)
    if conflicts:
        apps = []
        for path, app_id, app_label in conflicts:
            apps.append(" * {domain:s}{path:s} → {app_label:s} ({app_id:s})".format(
                domain=domain,
                path=path,
                app_id=app_id,
                app_label=app_label,
            ))
        raise YunohostError('app_location_unavailable', apps="\n".join(apps))

    manifest = json.load(open(os.path.join(APPS_SETTING_PATH, app, "manifest.json")))

    # Retrieve arguments list for change_url script
    # TODO: Allow to specify arguments
    args_odict = _parse_args_from_manifest(manifest, 'change_url')
    args_list = [ value[0] for value in args_odict.values() ]
    args_list.append(app)

    # Prepare env. var. to pass to script
    env_dict = _make_environment_dict(args_odict)
    app_id, app_instance_nb = _parse_app_instance_name(app)
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)

    env_dict["YNH_APP_OLD_DOMAIN"] = old_domain
    env_dict["YNH_APP_OLD_PATH"] = old_path
    env_dict["YNH_APP_NEW_DOMAIN"] = domain
    env_dict["YNH_APP_NEW_PATH"] = path

    if domain != old_domain:
        operation_logger.related_to.append(('domain', old_domain))
    operation_logger.extra.update({'env': env_dict})
    operation_logger.start()

    if os.path.exists(os.path.join(APP_TMP_FOLDER, "scripts")):
        shutil.rmtree(os.path.join(APP_TMP_FOLDER, "scripts"))

    shutil.copytree(os.path.join(APPS_SETTING_PATH, app, "scripts"),
                    os.path.join(APP_TMP_FOLDER, "scripts"))

    if os.path.exists(os.path.join(APP_TMP_FOLDER, "conf")):
        shutil.rmtree(os.path.join(APP_TMP_FOLDER, "conf"))

    shutil.copytree(os.path.join(APPS_SETTING_PATH, app, "conf"),
                    os.path.join(APP_TMP_FOLDER, "conf"))

    # Execute App change_url script
    os.system('chown -R admin: %s' % INSTALL_TMP)
    os.system('chmod +x %s' % os.path.join(os.path.join(APP_TMP_FOLDER, "scripts")))
    os.system('chmod +x %s' % os.path.join(os.path.join(APP_TMP_FOLDER, "scripts", "change_url")))

    if hook_exec(os.path.join(APP_TMP_FOLDER, 'scripts/change_url'),
                 args=args_list, env=env_dict)[0] != 0:
        msg = "Failed to change '%s' url." % app
        logger.error(msg)
        operation_logger.error(msg)

        # restore values modified by app_checkurl
        # see begining of the function
        app_setting(app, "domain", value=old_domain)
        app_setting(app, "path", value=old_path)
        return

    # this should idealy be done in the change_url script but let's avoid common mistakes
    app_setting(app, 'domain', value=domain)
    app_setting(app, 'path', value=path)

    permission_update(app, permission="main", add_url=[domain+path], remove_url=[old_domain+old_path], sync_perm=True)

    # avoid common mistakes
    if _run_service_command("reload", "nginx") is False:
        # grab nginx errors
        # the "exit 0" is here to avoid check_output to fail because 'nginx -t'
        # will return != 0 since we are in a failed state
        nginx_errors = subprocess.check_output("nginx -t; exit 0",
                                               stderr=subprocess.STDOUT,
                                               shell=True).rstrip()

        raise YunohostError("app_change_url_failed_nginx_reload", nginx_errors=nginx_errors)

    logger.success(m18n.n("app_change_url_success",
                          app=app, domain=domain, path=path))

    hook_callback('post_app_change_url', args=args_list, env=env_dict)


def app_upgrade(app=[], url=None, file=None):
    """
    Upgrade app

    Keyword argument:
        file -- Folder or tarball for upgrade
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade

    """
    if packages.dpkg_is_broken():
        raise YunohostError("dpkg_is_broken")

    from yunohost.hook import hook_add, hook_remove, hook_exec, hook_callback
    from yunohost.permission import permission_sync_to_user

    # Retrieve interface
    is_api = msettings.get('interface') == 'api'

    try:
        app_list()
    except YunohostError:
        raise YunohostError('app_no_upgrade')

    not_upgraded_apps = []

    apps = app
    # If no app is specified, upgrade all apps
    if not apps:
        # FIXME : not sure what's supposed to happen if there is a url and a file but no apps...
        if not url and not file:
            apps = [app["id"] for app in app_list(installed=True)["apps"]]
    elif not isinstance(app, list):
        apps = [app]

    # Remove possible duplicates
    apps = [app for i,app in enumerate(apps) if apps not in apps[:i]]

    # Abort if any of those app is in fact not installed..
    for app in [app for app in apps if not _is_installed(app)]:
        raise YunohostError('app_not_installed', app=app)

    if len(apps) == 0:
        raise YunohostError('app_no_upgrade')
    if len(apps) > 1:
        logger.info(m18n.n("app_upgrade_several_apps", apps=", ".join(apps)))

    for app_instance_name in apps:
        logger.info(m18n.n('app_upgrade_app_name', app=app_instance_name))

        app_dict = app_info(app_instance_name, raw=True)

        if file:
            manifest, extracted_app_folder = _extract_app_from_file(file)
        elif url:
            manifest, extracted_app_folder = _fetch_app_from_git(url)
        elif app_dict["upgradable"] == "url_required":
            logger.warning(m18n.n('custom_app_url_required', app=app_instance_name))
            continue
        elif app_dict["upgradable"] == "yes":
            manifest, extracted_app_folder = _fetch_app_from_git(app_instance_name)
        else:
            logger.success(m18n.n('app_already_up_to_date', app=app_instance_name))
            continue

        # Check requirements
        _check_manifest_requirements(manifest, app_instance_name=app_instance_name)
        _check_services_status_for_app(manifest.get("services", []))

        app_setting_path = APPS_SETTING_PATH + '/' + app_instance_name

        # Retrieve current app status
        status = _get_app_status(app_instance_name)
        status['remote'] = manifest.get('remote', None)

        # Retrieve arguments list for upgrade script
        # TODO: Allow to specify arguments
        args_odict = _parse_args_from_manifest(manifest, 'upgrade')
        args_list = [ value[0] for value in args_odict.values() ]
        args_list.append(app_instance_name)

        # Prepare env. var. to pass to script
        env_dict = _make_environment_dict(args_odict)
        app_id, app_instance_nb = _parse_app_instance_name(app_instance_name)
        env_dict["YNH_APP_ID"] = app_id
        env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
        env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)

        # Start register change on system
        related_to = [('app', app_instance_name)]
        operation_logger = OperationLogger('app_upgrade', related_to, env=env_dict)
        operation_logger.start()

        # Apply dirty patch to make php5 apps compatible with php7
        _patch_php5(extracted_app_folder)

        # Execute App upgrade script
        os.system('chown -hR admin: %s' % INSTALL_TMP)
        if hook_exec(extracted_app_folder + '/scripts/upgrade',
                     args=args_list, env=env_dict)[0] != 0:
            msg = m18n.n('app_upgrade_failed', app=app_instance_name)
            not_upgraded_apps.append(app_instance_name)
            logger.error(msg)
            operation_logger.error(msg)
        else:
            now = int(time.time())
            # TODO: Move install_time away from app_setting
            app_setting(app_instance_name, 'update_time', now)
            status['upgraded_at'] = now

            # Clean hooks and add new ones
            hook_remove(app_instance_name)
            if 'hooks' in os.listdir(extracted_app_folder):
                for hook in os.listdir(extracted_app_folder + '/hooks'):
                    hook_add(app_instance_name, extracted_app_folder + '/hooks/' + hook)

            # Store app status
            with open(app_setting_path + '/status.json', 'w+') as f:
                json.dump(status, f)

            # Replace scripts and manifest and conf (if exists)
            os.system('rm -rf "%s/scripts" "%s/manifest.json %s/conf"' % (app_setting_path, app_setting_path, app_setting_path))
            os.system('mv "%s/manifest.json" "%s/scripts" %s' % (extracted_app_folder, extracted_app_folder, app_setting_path))

            for file_to_copy in ["actions.json", "actions.toml", "config_panel.json", "config_panel.toml", "conf"]:
                if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
                    os.system('cp -R %s/%s %s' % (extracted_app_folder, file_to_copy, app_setting_path))

            # So much win
            logger.success(m18n.n('app_upgraded', app=app_instance_name))

            hook_callback('post_app_upgrade', args=args_list, env=env_dict)
            operation_logger.success()

    if not_upgraded_apps:
        raise YunohostError('app_not_upgraded', apps=', '.join(not_upgraded_apps))

    permission_sync_to_user()

    logger.success(m18n.n('upgrade_complete'))


@is_unit_operation()
def app_install(operation_logger, app, label=None, args=None, no_remove_on_failure=False, force=False):
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation
        no_remove_on_failure -- Debug option to avoid removing the app on a failed installation
        force -- Do not ask for confirmation when installing experimental / low-quality apps
    """
    if packages.dpkg_is_broken():
        raise YunohostError("dpkg_is_broken")

    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.hook import hook_add, hook_remove, hook_exec, hook_callback
    from yunohost.log import OperationLogger
    from yunohost.permission import permission_add, permission_update, permission_remove, permission_sync_to_user
    ldap = _get_ldap_interface()

    # Fetch or extract sources
    try:
        os.listdir(INSTALL_TMP)
    except OSError:
        os.makedirs(INSTALL_TMP)

    status = {
        'installed_at': int(time.time()),
        'upgraded_at': None,
        'remote': {
            'type': None,
        },
    }

    def confirm_install(confirm):

        # Ignore if there's nothing for confirm (good quality app), if --force is used
        # or if request on the API (confirm already implemented on the API side)
        if confirm is None or force or msettings.get('interface') == 'api':
            return

        answer = msignals.prompt(m18n.n('confirm_app_install_' + confirm,
                                   answers='Y/N'))
        if answer.upper() != "Y":
            raise YunohostError("aborting")

    raw_app_list = app_list(raw=True)

    if app in raw_app_list or ('@' in app) or ('http://' in app) or ('https://' in app):
        if app in raw_app_list:
            state = raw_app_list[app].get("state", "notworking")
            level = raw_app_list[app].get("level", None)
            confirm = "danger"
            if state in ["working", "validated"]:
                if isinstance(level, int) and level >= 3:
                    confirm = None
                elif isinstance(level, int) and level > 0:
                    confirm = "warning"
        else:
            confirm = "thirdparty"

        confirm_install(confirm)

        manifest, extracted_app_folder = _fetch_app_from_git(app)
    elif os.path.exists(app):
        confirm_install("thirdparty")
        manifest, extracted_app_folder = _extract_app_from_file(app)
    else:
        raise YunohostError('app_unknown')
    status['remote'] = manifest.get('remote', {})

    # Check ID
    if 'id' not in manifest or '__' in manifest['id']:
        raise YunohostError('app_id_invalid')

    app_id = manifest['id']

    # Check requirements
    _check_manifest_requirements(manifest, app_id)
    _check_services_status_for_app(manifest.get("services", []))

    # Check if app can be forked
    instance_number = _installed_instance_number(app_id, last=True) + 1
    if instance_number > 1:
        if 'multi_instance' not in manifest or not is_true(manifest['multi_instance']):
            raise YunohostError('app_already_installed', app=app_id)

        # Change app_id to the forked app id
        app_instance_name = app_id + '__' + str(instance_number)
    else:
        app_instance_name = app_id

    # Retrieve arguments list for install script
    args_dict = {} if not args else \
        dict(urlparse.parse_qsl(args, keep_blank_values=True))
    args_odict = _parse_args_from_manifest(manifest, 'install', args=args_dict)
    args_list = [ value[0] for value in args_odict.values() ]
    args_list.append(app_instance_name)

    # Prepare env. var. to pass to script
    env_dict = _make_environment_dict(args_odict)
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app_instance_name
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(instance_number)

    # Start register change on system
    operation_logger.extra.update({'env': env_dict})

    # Tell the operation_logger to redact all password-type args
    # Also redact the % escaped version of the password that might appear in
    # the 'args' section of metadata (relevant for password with non-alphanumeric char)
    data_to_redact = [ value[0] for value in args_odict.values() if value[1] == "password" ]
    data_to_redact += [ urllib.quote(data) for data in data_to_redact if urllib.quote(data) != data ]
    operation_logger.data_to_redact.extend(data_to_redact)

    operation_logger.related_to = [s for s in operation_logger.related_to if s[0] != "app"]
    operation_logger.related_to.append(("app", app_id))
    operation_logger.start()

    logger.info(m18n.n("app_start_install", app=app_id))

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

    # Apply dirty patch to make php5 apps compatible with php7
    _patch_php5(extracted_app_folder)

    os.system('chown -R admin: ' + extracted_app_folder)

    # Execute App install script
    os.system('chown -hR admin: %s' % INSTALL_TMP)
    # Move scripts and manifest to the right place
    os.system('cp %s/manifest.json %s' % (extracted_app_folder, app_setting_path))
    os.system('cp -R %s/scripts %s' % (extracted_app_folder, app_setting_path))

    for file_to_copy in ["actions.json", "actions.toml", "config_panel.json", "config_panel.toml", "conf"]:
        if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
            os.system('cp -R %s/%s %s' % (extracted_app_folder, file_to_copy, app_setting_path))

    # Create permission before the install (useful if the install script redefine the permission)
    # Note that sync_perm is disabled to avoid triggering a whole bunch of code and messages
    # can't be sure that we don't have one case when it's needed
    permission_add(app=app_instance_name, permission="main", sync_perm=False)

    # Execute the app install script
    install_retcode = 1
    try:
        install_retcode = hook_exec(
            os.path.join(extracted_app_folder, 'scripts/install'),
            args=args_list, env=env_dict
        )[0]
    except (KeyboardInterrupt, EOFError):
        install_retcode = -1
    except Exception:
        import traceback
        logger.exception(m18n.n('unexpected_error', error=u"\n" + traceback.format_exc()))
    finally:
        if install_retcode != 0:
            error_msg = operation_logger.error(m18n.n('unexpected_error', error='shell command return code: %s' % install_retcode))
            if not no_remove_on_failure:
                # Setup environment for remove script
                env_dict_remove = {}
                env_dict_remove["YNH_APP_ID"] = app_id
                env_dict_remove["YNH_APP_INSTANCE_NAME"] = app_instance_name
                env_dict_remove["YNH_APP_INSTANCE_NUMBER"] = str(instance_number)

                # Execute remove script
                operation_logger_remove = OperationLogger('remove_on_failed_install',
                                                          [('app', app_instance_name)],
                                                          env=env_dict_remove)
                operation_logger_remove.start()

                remove_retcode = hook_exec(
                    os.path.join(extracted_app_folder, 'scripts/remove'),
                    args=[app_instance_name], env=env_dict_remove
                )[0]
                # Remove all permission in LDAP
                result = ldap.search(base='ou=permission,dc=yunohost,dc=org',
                                    filter='(&(objectclass=permissionYnh)(cn=*.%s))' % app_instance_name, attrs=['cn'])
                permission_list = [p['cn'][0] for p in result]
                for l in permission_list:
                    permission_remove(app_instance_name, l.split('.')[0], force=True)

                if remove_retcode != 0:
                    msg = m18n.n('app_not_properly_removed',
                                 app=app_instance_name)
                    logger.warning(msg)
                    operation_logger_remove.error(msg)
                else:
                    operation_logger_remove.success()

            # Clean tmp folders
            shutil.rmtree(app_setting_path)
            shutil.rmtree(extracted_app_folder)

            app_ssowatconf()

            if packages.dpkg_is_broken():
                logger.error(m18n.n("this_action_broke_dpkg"))

            if install_retcode == -1:
                msg = m18n.n('operation_interrupted') + " " + error_msg
                raise YunohostError(msg, raw_msg=True)
            msg = error_msg
            raise YunohostError(msg, raw_msg=True)

    # Clean hooks and add new ones
    hook_remove(app_instance_name)
    if 'hooks' in os.listdir(extracted_app_folder):
        for file in os.listdir(extracted_app_folder + '/hooks'):
            hook_add(app_instance_name, extracted_app_folder + '/hooks/' + file)

    # Store app status
    with open(app_setting_path + '/status.json', 'w+') as f:
        json.dump(status, f)

    # Clean and set permissions
    shutil.rmtree(extracted_app_folder)
    os.system('chmod -R 400 %s' % app_setting_path)
    os.system('chown -R root: %s' % app_setting_path)
    os.system('chown -R admin: %s/scripts' % app_setting_path)

    # Add path in permission if it's defined in the app install script
    app_settings = _get_app_settings(app_instance_name)
    domain = app_settings.get('domain', None)
    path = app_settings.get('path', None)
    if domain and path:
        permission_update(app_instance_name, permission="main", add_url=[domain+path], sync_perm=False)

    permission_sync_to_user()

    logger.success(m18n.n('installation_complete'))

    hook_callback('post_app_install', args=args_list, env=env_dict)


@is_unit_operation()
def app_remove(operation_logger, app):
    """
    Remove app

    Keyword argument:
        app -- App(s) to delete

    """
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.hook import hook_exec, hook_remove, hook_callback
    from yunohost.permission import permission_remove, permission_sync_to_user
    if not _is_installed(app):
        raise YunohostError('app_not_installed', app=app)

    operation_logger.start()

    logger.info(m18n.n("app_start_remove", app=app))

    app_setting_path = APPS_SETTING_PATH + app

    # TODO: display fail messages from script
    try:
        shutil.rmtree('/tmp/yunohost_remove')
    except:
        pass

    # Apply dirty patch to make php5 apps compatible with php7 (e.g. the remove
    # script might date back from jessie install)
    _patch_php5(app_setting_path)

    os.system('cp -a %s /tmp/yunohost_remove && chown -hR admin: /tmp/yunohost_remove' % app_setting_path)
    os.system('chown -R admin: /tmp/yunohost_remove')
    os.system('chmod -R u+rX /tmp/yunohost_remove')

    args_list = [app]

    env_dict = {}
    app_id, app_instance_nb = _parse_app_instance_name(app)
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
    operation_logger.extra.update({'env': env_dict})
    operation_logger.flush()

    if hook_exec('/tmp/yunohost_remove/scripts/remove', args=args_list,
                 env=env_dict)[0] == 0:
        logger.success(m18n.n('app_removed', app=app))

        hook_callback('post_app_remove', args=args_list, env=env_dict)

    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)
    shutil.rmtree('/tmp/yunohost_remove')
    hook_remove(app)

    # Remove all permission in LDAP
    ldap = _get_ldap_interface()
    result = ldap.search(base='ou=permission,dc=yunohost,dc=org',
                         filter='(&(objectclass=permissionYnh)(cn=*.%s))' % app, attrs=['cn'])
    permission_list = [p['cn'][0] for p in result]
    for l in permission_list:
        permission_remove(app, l.split('.')[0], force=True, sync_perm=False)

    permission_sync_to_user()

    if packages.dpkg_is_broken():
        raise YunohostError("this_action_broke_dpkg")


@is_unit_operation(['permission','app'])
def app_addaccess(operation_logger, apps, users=[]):
    """
    Grant access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.permission import user_permission_update

    permission = user_permission_update(operation_logger, app=apps, permission="main", add_username=users)

    result = {p : v['main']['allowed_users'] for p, v in permission['permissions'].items()}

    return {'allowed_users': result}


@is_unit_operation(['permission','app'])
def app_removeaccess(operation_logger, apps, users=[]):
    """
    Revoke access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.permission import user_permission_update

    permission = user_permission_update(operation_logger, app=apps, permission="main", del_username=users)

    result = {p : v['main']['allowed_users'] for p, v in permission['permissions'].items()}

    return {'allowed_users': result}


@is_unit_operation(['permission','app'])
def app_clearaccess(operation_logger, apps):
    """
    Reset access rights for the app

    Keyword argument:
        apps

    """
    from yunohost.permission import user_permission_clear

    permission = user_permission_clear(operation_logger, app=apps, permission="main")

    result = {p : v['main']['allowed_users'] for p, v in permission['permissions'].items()}

    return {'allowed_users': result}

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


@is_unit_operation()
def app_makedefault(operation_logger, app, domain=None):
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from yunohost.domain import domain_list

    app_settings = _get_app_settings(app)
    app_domain = app_settings['domain']
    app_path = app_settings['path']

    if domain is None:
        domain = app_domain
        operation_logger.related_to.append(('domain', domain))
    elif domain not in domain_list()['domains']:
        raise YunohostError('domain_unknown')

    operation_logger.start()
    if '/' in app_map(raw=True)[domain]:
        raise YunohostError('app_make_default_location_already_used', app=app, domain=app_domain,
                            other_app=app_map(raw=True)[domain]["/"]["id"])

    try:
        with open('/etc/ssowat/conf.json.persistent') as json_conf:
            ssowat_conf = json.loads(str(json_conf.read()))
    except ValueError as e:
        raise YunohostError('ssowat_persistent_conf_read_error', error=e)
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls'][domain + '/'] = app_domain + app_path

    try:
        with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
            json.dump(ssowat_conf, f, sort_keys=True, indent=4)
    except IOError as e:
        raise YunohostError('ssowat_persistent_conf_write_error', error=e)

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
        except Exception as e:
            logger.debug("cannot get app setting '%s' for '%s' (%s)", key, app, e)
            return None
    else:
        if delete and key in app_settings:
            del app_settings[key]
        else:
            # FIXME: Allow multiple values for some keys?
            if key in ['redirected_urls', 'redirected_regex']:
                value = yaml.load(value)
            app_settings[key] = value
        _set_app_settings(app, app_settings)


def app_checkport(port):
    """
    Check availability of a local port

    Keyword argument:
        port -- Port to check

    """

    # This import cannot be moved on top of file because it create a recursive
    # import...
    from yunohost.tools import tools_port_available
    if tools_port_available(port):
        logger.success(m18n.n('port_available', port=int(port)))
    else:
        raise YunohostError('port_unavailable', port=int(port))


def app_register_url(app, domain, path):
    """
    Book/register a web path for a given app

    Keyword argument:
        app -- App which will use the web path
        domain -- The domain on which the app should be registered (e.g. your.domain.tld)
        path -- The path to be registered (e.g. /coffee)
    """

    # This line can't be moved on top of file, otherwise it creates an infinite
    # loop of import with tools.py...
    from .domain import _get_conflicting_apps, _normalize_domain_path

    domain, path = _normalize_domain_path(domain, path)

    # We cannot change the url of an app already installed simply by changing
    # the settings...

    installed = app in app_list(installed=True, raw=True).keys()
    if installed:
        settings = _get_app_settings(app)
        if "path" in settings.keys() and "domain" in settings.keys():
            raise YunohostError('app_already_installed_cant_change_url')

    # Check the url is available
    conflicts = _get_conflicting_apps(domain, path)
    if conflicts:
        apps = []
        for path, app_id, app_label in conflicts:
            apps.append(" * {domain:s}{path:s} → {app_label:s} ({app_id:s})".format(
                domain=domain,
                path=path,
                app_id=app_id,
                app_label=app_label,
            ))

        raise YunohostError('app_location_unavailable', apps="\n".join(apps))

    app_setting(app, 'domain', value=domain)
    app_setting(app, 'path', value=path)


def app_checkurl(url, app=None):
    """
    Check availability of a web path

    Keyword argument:
        url -- Url to check
        app -- Write domain & path to app settings for further checks

    """

    logger.error("Packagers /!\\ : 'app checkurl' is deprecated ! Please use the helper 'ynh_webpath_register' instead !")

    from yunohost.domain import domain_list, _normalize_domain_path

    if "https://" == url[:8]:
        url = url[8:]
    elif "http://" == url[:7]:
        url = url[7:]

    if url[-1:] != '/':
        url = url + '/'

    domain = url[:url.index('/')]
    path = url[url.index('/'):]
    installed = False

    domain, path = _normalize_domain_path(domain, path)

    apps_map = app_map(raw=True)

    if domain not in domain_list()['domains']:
        raise YunohostError('domain_unknown')

    if domain in apps_map:
        # Loop through apps
        for p, a in apps_map[domain].items():
            # Skip requested app checking
            if app is not None and a['id'] == app:
                installed = True
                continue
            if path == p:
                raise YunohostError('app_location_already_used', app=a["id"], path=path)
            # can't install "/a/b/" if "/a/" exists
            elif path.startswith(p) or p.startswith(path):
                raise YunohostError('app_location_install_failed', other_path=p, other_app=a['id'])

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

    logger.error("Packagers /!\\ : 'app initdb' is deprecated ! Please use the helper 'ynh_mysql_setup_db' instead !")

    if db is None:
        db = user

    return_pwd = False
    if password is None:
        password = random_password(12)
        return_pwd = True

    mysql_root_pwd = open('/etc/yunohost/mysql').read().rstrip()
    mysql_command = 'mysql -u root -p%s -e "CREATE DATABASE %s ; GRANT ALL PRIVILEGES ON %s.* TO \'%s\'@localhost IDENTIFIED BY \'%s\';"' % (mysql_root_pwd, db, db, user, password)
    if os.system(mysql_command) != 0:
        raise YunohostError('mysql_db_creation_failed')
    if sql is not None:
        if os.system('mysql -u %s -p%s %s < %s' % (user, password, db, sql)) != 0:
            raise YunohostError('mysql_db_init_failed')

    if return_pwd:
        return password

    logger.success(m18n.n('mysql_db_initialized'))


def app_ssowatconf():
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.user import user_list
    from yunohost.permission import user_permission_list

    main_domain = _get_maindomain()
    domains = domain_list()['domains']

    skipped_urls = []
    skipped_regex = []
    unprotected_urls = []
    unprotected_regex = []
    protected_urls = []
    protected_regex = []
    redirected_regex = {main_domain + '/yunohost[\/]?$': 'https://' + main_domain + '/yunohost/sso/'}
    redirected_urls = {}

    try:
        apps_list = app_list(installed=True)['apps']
    except Exception as e:
        logger.debug("cannot get installed app list because %s", e)
        apps_list = []

    def _get_setting(settings, name):
        s = settings.get(name, None)
        return s.split(',') if s else []

    for app in apps_list:
        with open(APPS_SETTING_PATH + app['id'] + '/settings.yml') as f:
            app_settings = yaml.load(f)

            if 'no_sso' in app_settings:
                continue

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
    skipped_regex.append("^[^/]*/%.well%-known/autoconfig/mail/config%-v1%.1%.xml.*$")

    permission = {}
    for a in user_permission_list()['permissions'].values():
        for p in a.values():
            if 'URL' in p:
                for u in p['URL']:
                    permission[u] = p['allowed_users']

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
        'users': {username: app_map(user=username)
                  for username in user_list()['users'].keys()},
        'permission': permission,
    }

    with open('/etc/ssowat/conf.json', 'w+') as f:
        json.dump(conf_dict, f, sort_keys=True, indent=4)

    logger.debug(m18n.n('ssowat_conf_generated'))


def app_change_label(app, new_label):
    installed = _is_installed(app)
    if not installed:
        raise YunohostError('app_not_installed', app=app)

    app_setting(app, "label", value=new_label)

    app_ssowatconf()


# actions todo list:
# * docstring

def app_action_list(app):
    logger.warning(m18n.n('experimental_feature'))

    # this will take care of checking if the app is installed
    app_info_dict = app_info(app)

    return {
        "app": app,
        "app_name": app_info_dict["name"],
        "actions": _get_app_actions(app)
    }


def app_action_run(app, action, args=None):
    logger.warning(m18n.n('experimental_feature'))

    from yunohost.hook import hook_exec
    import tempfile

    # will raise if action doesn't exist
    actions = app_action_list(app)["actions"]
    actions = {x["id"]: x for x in actions}

    if action not in actions:
        raise YunohostError("action '%s' not available for app '%s', available actions are: %s" % (action, app, ", ".join(actions.keys())), raw_msg=True)

    action_declaration = actions[action]

    # Retrieve arguments list for install script
    args_dict = dict(urlparse.parse_qsl(args, keep_blank_values=True)) if args else {}
    args_odict = _parse_args_for_action(actions[action], args=args_dict)
    args_list = [ value[0] for value in args_odict.values() ]

    app_id, app_instance_nb = _parse_app_instance_name(app)

    env_dict = _make_environment_dict(args_odict, prefix="ACTION_")
    env_dict["YNH_APP_ID"] = app_id
    env_dict["YNH_APP_INSTANCE_NAME"] = app
    env_dict["YNH_APP_INSTANCE_NUMBER"] = str(app_instance_nb)
    env_dict["YNH_ACTION"] = action

    _, path = tempfile.mkstemp()

    with open(path, "w") as script:
        script.write(action_declaration["command"])

    os.chmod(path, 700)

    if action_declaration.get("cwd"):
        cwd = action_declaration["cwd"].replace("$app", app_id)
    else:
        cwd = "/etc/yunohost/apps/" + app

    retcode = hook_exec(
        path,
        args=args_list,
        env=env_dict,
        chdir=cwd,
        user=action_declaration.get("user", "root"),
    )[0]

    if retcode not in action_declaration.get("accepted_return_codes", [0]):
        raise YunohostError("Error while executing action '%s' of app '%s': return code %s" % (action, app, retcode), raw_msg=True)

    os.remove(path)

    return logger.success("Action successed!")


# Config panel todo list:
# * docstrings
# * merge translations on the json once the workflow is in place
def app_config_show_panel(app):
    logger.warning(m18n.n('experimental_feature'))

    from yunohost.hook import hook_exec

    # this will take care of checking if the app is installed
    app_info_dict = app_info(app)

    config_panel = _get_app_config_panel(app)
    config_script = os.path.join(APPS_SETTING_PATH, app, 'scripts', 'config')

    app_id, app_instance_nb = _parse_app_instance_name(app)

    if not config_panel or not os.path.exists(config_script):
        return {
            "app_id": app_id,
            "app": app,
            "app_name": app_info_dict["name"],
            "config_panel": [],
        }

    env = {
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
    }

    return_code, parsed_values = hook_exec(config_script,
                                args=["show"],
                                env=env,
                                return_format="plain_dict"
                                )

    if return_code != 0:
        raise Exception("script/config show return value code: %s (considered as an error)", return_code)

    logger.debug("Generating global variables:")
    for tab in config_panel.get("panel", []):
        tab_id = tab["id"]  # this makes things easier to debug on crash
        for section in tab.get("sections", []):
            section_id = section["id"]
            for option in section.get("options", []):
                option_name = option["name"]
                generated_name = ("YNH_CONFIG_%s_%s_%s" % (tab_id, section_id, option_name)).upper()
                option["name"] = generated_name
                logger.debug(" * '%s'.'%s'.'%s' -> %s", tab.get("name"), section.get("name"), option.get("name"), generated_name)

                if generated_name in parsed_values:
                    # code is not adapted for that so we have to mock expected format :/
                    if option.get("type") == "boolean":
                        if parsed_values[generated_name].lower() in ("true", "1", "y"):
                            option["default"] = parsed_values[generated_name]
                        else:
                            del option["default"]
                    else:
                        option["default"] = parsed_values[generated_name]

                    args_dict = _parse_args_in_yunohost_format(
                        [{option["name"]: parsed_values[generated_name]}],
                        [option]
                    )
                    option["default"] = args_dict[option["name"]][0]
                else:
                    logger.debug("Variable '%s' is not declared by config script, using default", generated_name)
                    # do nothing, we'll use the default if present

    return {
        "app_id": app_id,
        "app": app,
        "app_name": app_info_dict["name"],
        "config_panel": config_panel,
    }


def app_config_apply(app, args):
    logger.warning(m18n.n('experimental_feature'))

    from yunohost.hook import hook_exec

    installed = _is_installed(app)
    if not installed:
        raise YunohostError('app_not_installed', app=app)

    config_panel = _get_app_config_panel(app)
    config_script = os.path.join(APPS_SETTING_PATH, app, 'scripts', 'config')

    if not config_panel or not os.path.exists(config_script):
        # XXX real exception
        raise Exception("Not config-panel.json nor scripts/config")

    app_id, app_instance_nb = _parse_app_instance_name(app)
    env = {
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
    }
    args = dict(urlparse.parse_qsl(args, keep_blank_values=True)) if args else {}

    for tab in config_panel.get("panel", []):
        tab_id = tab["id"]  # this makes things easier to debug on crash
        for section in tab.get("sections", []):
            section_id = section["id"]
            for option in section.get("options", []):
                option_name = option["name"]
                generated_name = ("YNH_CONFIG_%s_%s_%s" % (tab_id, section_id, option_name)).upper()

                if generated_name in args:
                    logger.debug("include into env %s=%s", generated_name, args[generated_name])
                    env[generated_name] = args[generated_name]
                else:
                    logger.debug("no value for key id %s", generated_name)

    # for debug purpose
    for key in args:
        if key not in env:
            logger.warning("Ignore key '%s' from arguments because it is not in the config", key)

    return_code = hook_exec(config_script,
                            args=["apply"],
                            env=env,
                            )[0]

    if return_code != 0:
        raise Exception("'script/config apply' return value code: %s (considered as an error)", return_code)

    logger.success("Config updated as expected")


def _get_app_actions(app_id):
    "Get app config panel stored in json or in toml"
    actions_toml_path = os.path.join(APPS_SETTING_PATH, app_id, 'actions.toml')
    actions_json_path = os.path.join(APPS_SETTING_PATH, app_id, 'actions.json')

    # sample data to get an idea of what is going on
    # this toml extract:
    #

    # [restart_service]
    # name = "Restart service"
    # command = "echo pouet $YNH_ACTION_SERVICE"
    # user = "root"  # optional
    # cwd = "/" # optional
    # accepted_return_codes = [0, 1, 2, 3]  # optional
    # description.en = "a dummy stupid exemple or restarting a service"
    #
    #     [restart_service.arguments.service]
    #     type = "string",
    #     ask.en = "service to restart"
    #     example = "nginx"
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'restart_service',
    #               OrderedDict([(u'name', u'Restart service'),
    #                            (u'command', u'echo pouet $YNH_ACTION_SERVICE'),
    #                            (u'user', u'root'),
    #                            (u'cwd', u'/'),
    #                            (u'accepted_return_codes', [0, 1, 2, 3]),
    #                            (u'description',
    #                             OrderedDict([(u'en',
    #                                           u'a dummy stupid exemple or restarting a service')])),
    #                            (u'arguments',
    #                             OrderedDict([(u'service',
    #                                           OrderedDict([(u'type', u'string'),
    #                                                        (u'ask',
    #                                                         OrderedDict([(u'en',
    #                                                                       u'service to restart')])),
    #                                                        (u'example',
    #                                                         u'nginx')]))]))])),
    #
    #
    # and needs to be converted into this:
    #
    # [{u'accepted_return_codes': [0, 1, 2, 3],
    #   u'arguments': [{u'ask': {u'en': u'service to restart'},
    #     u'example': u'nginx',
    #     u'name': u'service',
    #     u'type': u'string'}],
    #   u'command': u'echo pouet $YNH_ACTION_SERVICE',
    #   u'cwd': u'/',
    #   u'description': {u'en': u'a dummy stupid exemple or restarting a service'},
    #   u'id': u'restart_service',
    #   u'name': u'Restart service',
    #   u'user': u'root'}]

    if os.path.exists(actions_toml_path):
        toml_actions = toml.load(open(actions_toml_path, "r"), _dict=OrderedDict)

        # transform toml format into json format
        actions = []

        for key, value in toml_actions.items():
            action = dict(**value)
            action["id"] = key

            arguments = []
            for argument_name, argument in value.get("arguments", {}).items():
                argument = dict(**argument)
                argument["name"] = argument_name

                arguments.append(argument)

            action["arguments"] = arguments
            actions.append(action)

        return actions

    elif os.path.exists(actions_json_path):
        return json.load(open(actions_json_path))

    return None


def _get_app_config_panel(app_id):
    "Get app config panel stored in json or in toml"
    config_panel_toml_path = os.path.join(APPS_SETTING_PATH, app_id, 'config_panel.toml')
    config_panel_json_path = os.path.join(APPS_SETTING_PATH, app_id, 'config_panel.json')

    # sample data to get an idea of what is going on
    # this toml extract:
    #
    # version = "0.1"
    # name = "Unattended-upgrades configuration panel"
    #
    # [main]
    # name = "Unattended-upgrades configuration"
    #
    #     [main.unattended_configuration]
    #     name = "50unattended-upgrades configuration file"
    #
    #         [main.unattended_configuration.upgrade_level]
    #         name = "Choose the sources of packages to automatically upgrade."
    #         default = "Security only"
    #         type = "text"
    #         help = "We can't use a choices field for now. In the meantime please choose between one of this values:<br>Security only, Security and updates."
    #         # choices = ["Security only", "Security and updates"]

    #         [main.unattended_configuration.ynh_update]
    #         name = "Would you like to update YunoHost packages automatically ?"
    #         type = "bool"
    #         default = true
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'version', u'0.1'),
    #              (u'name', u'Unattended-upgrades configuration panel'),
    #              (u'main',
    #               OrderedDict([(u'name', u'Unattended-upgrades configuration'),
    #                            (u'unattended_configuration',
    #                             OrderedDict([(u'name',
    #                                           u'50unattended-upgrades configuration file'),
    #                                          (u'upgrade_level',
    #                                           OrderedDict([(u'name',
    #                                                         u'Choose the sources of packages to automatically upgrade.'),
    #                                                        (u'default',
    #                                                         u'Security only'),
    #                                                        (u'type', u'text'),
    #                                                        (u'help',
    #                                                         u"We can't use a choices field for now. In the meantime please choose between one of this values:<br>Security only, Security and updates.")])),
    #                                          (u'ynh_update',
    #                                           OrderedDict([(u'name',
    #                                                         u'Would you like to update YunoHost packages automatically ?'),
    #                                                        (u'type', u'bool'),
    #                                                        (u'default', True)])),
    #
    # and needs to be converted into this:
    #
    # {u'name': u'Unattended-upgrades configuration panel',
    #  u'panel': [{u'id': u'main',
    #    u'name': u'Unattended-upgrades configuration',
    #    u'sections': [{u'id': u'unattended_configuration',
    #      u'name': u'50unattended-upgrades configuration file',
    #      u'options': [{u'//': u'"choices" : ["Security only", "Security and updates"]',
    #        u'default': u'Security only',
    #        u'help': u"We can't use a choices field for now. In the meantime please choose between one of this values:<br>Security only, Security and updates.",
    #        u'id': u'upgrade_level',
    #        u'name': u'Choose the sources of packages to automatically upgrade.',
    #        u'type': u'text'},
    #       {u'default': True,
    #        u'id': u'ynh_update',
    #        u'name': u'Would you like to update YunoHost packages automatically ?',
    #        u'type': u'bool'},

    if os.path.exists(config_panel_toml_path):
        toml_config_panel = toml.load(open(config_panel_toml_path, "r"), _dict=OrderedDict)

        # transform toml format into json format
        config_panel = {
            "name": toml_config_panel["name"],
            "version": toml_config_panel["version"],
            "panel": [],
        }

        panels = filter(lambda (key, value): key not in ("name", "version")
                                             and isinstance(value, OrderedDict),
                        toml_config_panel.items())

        for key, value in panels:
            panel = {
                "id": key,
                "name": value["name"],
                "sections": [],
            }

            sections = filter(lambda (k, v): k not in ("name",)
                                             and isinstance(v, OrderedDict),
                              value.items())

            for section_key, section_value in sections:
                section = {
                    "id": section_key,
                    "name": section_value["name"],
                    "options": [],
                }

                options = filter(lambda (k, v): k not in ("name",)
                                                and isinstance(v, OrderedDict),
                                 section_value.items())

                for option_key, option_value in options:
                    option = dict(option_value)
                    option["name"] = option_key
                    option["ask"] = {"en": option["ask"]}
                    if "help" in option:
                        option["help"] = {"en": option["help"]}
                    section["options"].append(option)

                panel["sections"].append(section)

            config_panel["panel"].append(panel)

        return config_panel

    elif os.path.exists(config_panel_json_path):
        return json.load(open(config_panel_json_path))

    return None


def _get_app_settings(app_id):
    """
    Get settings of an installed app

    Keyword arguments:
        app_id -- The app id

    """
    if not _is_installed(app_id):
        raise YunohostError('app_not_installed', app=app_id)
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
        raise YunohostError('app_unknown')
    status = {}

    regen_status = True
    try:
        with open(app_setting_path + '/status.json') as f:
            status = json.loads(str(f.read()))
        regen_status = False
    except IOError:
        logger.debug("status file not found for '%s'", app_id,
                     exc_info=1)
    except Exception as e:
        logger.warning("could not open or decode %s : %s ... regenerating.", app_setting_path + '/status.json', str(e))

    if regen_status:
        # Create app status
        status = {
            'installed_at': app_setting(app_id, 'install_time'),
            'upgraded_at': app_setting(app_id, 'update_time'),
            'remote': {'type': None},
        }
        with open(app_setting_path + '/status.json', 'w+') as f:
            json.dump(status, f)

    if format_date:
        for f in ['installed_at', 'upgraded_at']:
            v = status.get(f, None)
            if not v:
                status[f] = '-'
            else:
                status[f] = datetime.utcfromtimestamp(v)
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
    logger.debug(m18n.n('extracting'))

    if os.path.exists(APP_TMP_FOLDER):
        shutil.rmtree(APP_TMP_FOLDER)
    os.makedirs(APP_TMP_FOLDER)

    path = os.path.abspath(path)

    if ".zip" in path:
        extract_result = os.system('unzip %s -d %s > /dev/null 2>&1' % (path, APP_TMP_FOLDER))
        if remove:
            os.remove(path)
    elif ".tar" in path:
        extract_result = os.system('tar -xf %s -C %s > /dev/null 2>&1' % (path, APP_TMP_FOLDER))
        if remove:
            os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(APP_TMP_FOLDER)
        if path[-1] != '/':
            path = path + '/'
        extract_result = os.system('cp -a "%s" %s' % (path, APP_TMP_FOLDER))
    else:
        extract_result = 1

    if extract_result != 0:
        raise YunohostError('app_extraction_failed')

    try:
        extracted_app_folder = APP_TMP_FOLDER
        if len(os.listdir(extracted_app_folder)) == 1:
            for folder in os.listdir(extracted_app_folder):
                extracted_app_folder = extracted_app_folder + '/' + folder
        with open(extracted_app_folder + '/manifest.json') as json_manifest:
            manifest = json.loads(str(json_manifest.read()))
            manifest['lastUpdate'] = int(time.time())
    except IOError:
        raise YunohostError('app_install_files_invalid')
    except ValueError as e:
        raise YunohostError('app_manifest_invalid', error=e)

    logger.debug(m18n.n('done'))

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

    logger.debug(m18n.n('downloading'))

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
                raise YunohostError('app_sources_fetch_failed')
            else:
                manifest, extracted_app_folder = _extract_app_from_file(
                    app_tmp_archive, remove=True)
        else:
            tree_index = url.rfind('/tree/')
            if tree_index > 0:
                url = url[:tree_index]
                branch = app[tree_index + 6:]
            try:
                # We use currently git 2.1 so we can't use --shallow-submodules
                # option. When git will be in 2.9 (with the new debian version)
                # we will be able to use it. Without this option all the history
                # of the submodules repo is downloaded.
                subprocess.check_call([
                    'git', 'clone', '-b', branch, '--single-branch', '--recursive', '--depth=1', url,
                    extracted_app_folder])
                subprocess.check_call([
                    'git', 'reset', '--hard', branch
                ], cwd=extracted_app_folder)
                with open(extracted_app_folder + '/manifest.json') as f:
                    manifest = json.loads(str(f.read()))
            except subprocess.CalledProcessError:
                raise YunohostError('app_sources_fetch_failed')
            except ValueError as e:
                raise YunohostError('app_manifest_invalid', error=e)
            else:
                logger.debug(m18n.n('done'))

        # Store remote repository info into the returned manifest
        manifest['remote'] = {'type': 'git', 'url': url, 'branch': branch}
        try:
            revision = _get_git_last_commit_hash(url, branch)
        except Exception as e:
            logger.debug("cannot get last commit hash because: %s ", e)
        else:
            manifest['remote']['revision'] = revision
    else:
        app_dict = app_list(raw=True)

        if app in app_dict:
            app_info = app_dict[app]
            app_info['manifest']['lastUpdate'] = app_info['lastUpdate']
            manifest = app_info['manifest']
        else:
            raise YunohostError('app_unknown')

        if 'git' not in app_info:
            raise YunohostError('app_unsupported_remote_type')
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
                raise YunohostError('app_sources_fetch_failed')
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
                raise YunohostError('app_sources_fetch_failed')
            except ValueError as e:
                raise YunohostError('app_manifest_invalid', error=e)
            else:
                logger.debug(m18n.n('done'))

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


def _check_manifest_requirements(manifest, app_instance_name):
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
        # See https://github.com/YunoHost/issues/issues/156
        yunohost_req = requirements.get('yunohost', None)
        if (not yunohost_req or
                not packages.SpecifierSet(yunohost_req) & '>= 2.3.6'):
            raise YunohostError('{0}{1}'.format(
                m18n.g('colon', m18n.n('app_incompatible'), app=app_instance_name),
                m18n.n('app_package_need_update', app=app_instance_name)))
    elif not requirements:
        return

    logger.debug(m18n.n('app_requirements_checking', app=app_instance_name))

    # Retrieve versions of each required package
    try:
        versions = packages.get_installed_version(
            *requirements.keys(), strict=True, as_dict=True)
    except packages.PackageException as e:
        raise YunohostError('app_requirements_failed', error=str(e), app=app_instance_name)

    # Iterate over requirements
    for pkgname, spec in requirements.items():
        version = versions[pkgname]
        if version not in packages.SpecifierSet(spec):
            raise YunohostError('app_requirements_unmeet',
                                pkgname=pkgname, version=version,
                                spec=spec, app=app_instance_name)


def _parse_args_from_manifest(manifest, action, args={}):
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
    if action not in manifest['arguments']:
        logger.debug("no arguments found for '%s' in manifest", action)
        return OrderedDict()

    action_args = manifest['arguments'][action]
    return _parse_args_in_yunohost_format(args, action_args)


def _parse_args_for_action(action, args={}):
    """Parse arguments needed for an action from the actions list

    Retrieve specified arguments for the action from the manifest, and parse
    given args according to that. If some required arguments are not provided,
    its values will be asked if interaction is possible.
    Parsed arguments will be returned as an OrderedDict

    Keyword arguments:
        action -- The action
        args -- A dictionnary of arguments to parse

    """
    args_dict = OrderedDict()

    if 'arguments' not in action:
        logger.debug("no arguments found for '%s' in manifest", action)
        return args_dict

    action_args = action['arguments']

    return _parse_args_in_yunohost_format(args, action_args)


def _parse_args_in_yunohost_format(args, action_args):
    """Parse arguments store in either manifest.json or actions.json
    """
    from yunohost.domain import (domain_list, _get_maindomain,
                                 _get_conflicting_apps, _normalize_domain_path)
    from yunohost.user import user_info, user_list

    args_dict = OrderedDict()

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

        # do not print for webadmin
        if arg_type == 'display_text' and msettings.get('interface') != 'api':
            print(_value_for_locale(arg['ask']))
            continue

        # Attempt to retrieve argument value
        if arg_name in args:
            arg_value = args[arg_name]
        else:
            if 'ask' in arg:
                # Retrieve proper ask string
                ask_string = _value_for_locale(arg['ask'])

                # Append extra strings
                if arg_type == 'boolean':
                    ask_string += ' [yes | no]'
                elif arg_choices:
                    ask_string += ' [{0}]'.format(' | '.join(arg_choices))

                if arg_default is not None:
                    if arg_type == 'boolean':
                        ask_string += ' (default: {0})'.format("yes" if arg_default == 1 else "no")
                    else:
                        ask_string += ' (default: {0})'.format(arg_default)

                # Check for a password argument
                is_password = True if arg_type == 'password' else False

                if arg_type == 'domain':
                    arg_default = _get_maindomain()
                    ask_string += ' (default: {0})'.format(arg_default)
                    msignals.display(m18n.n('domains_available'))
                    for domain in domain_list()['domains']:
                        msignals.display("- {}".format(domain))

                elif arg_type == 'user':
                    msignals.display(m18n.n('users_available'))
                    for user in user_list()['users'].keys():
                        msignals.display("- {}".format(user))

                elif arg_type == 'password':
                    msignals.display(m18n.n('good_practices_about_user_password'))

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

        # If the value is empty (none or '')
        # then check if arg is optional or not
        if arg_value is None or arg_value == '':
            if arg.get("optional", False):
                # Argument is optional, keep an empty value
                # and that's all for this arg !
                args_dict[arg_name] = ('', arg_type)
                continue
            else:
                # The argument is required !
                raise YunohostError('app_argument_required', name=arg_name)

        # Validate argument choice
        if arg_choices and arg_value not in arg_choices:
            raise YunohostError('app_argument_choice_invalid', name=arg_name, choices=', '.join(arg_choices))

        # Validate argument type
        if arg_type == 'domain':
            if arg_value not in domain_list()['domains']:
                raise YunohostError('app_argument_invalid', name=arg_name, error=m18n.n('domain_unknown'))
        elif arg_type == 'user':
            try:
                user_info(arg_value)
            except YunohostError as e:
                raise YunohostError('app_argument_invalid', name=arg_name, error=e)
        elif arg_type == 'app':
            if not _is_installed(arg_value):
                raise YunohostError('app_argument_invalid', name=arg_name, error=m18n.n('app_unknown'))
        elif arg_type == 'boolean':
            if isinstance(arg_value, bool):
                arg_value = 1 if arg_value else 0
            else:
                if str(arg_value).lower() in ["1", "yes", "y"]:
                    arg_value = 1
                elif str(arg_value).lower() in ["0", "no", "n"]:
                    arg_value = 0
                else:
                    raise YunohostError('app_argument_choice_invalid', name=arg_name, choices='yes, no, y, n, 1, 0')
        elif arg_type == 'password':
            forbidden_chars = "{}"
            if any(char in arg_value for char in forbidden_chars):
                raise YunohostError('pattern_password_app', forbidden_chars=forbidden_chars)
            from yunohost.utils.password import assert_password_is_strong_enough
            assert_password_is_strong_enough('user', arg_value)
        args_dict[arg_name] = (arg_value, arg_type)

    # END loop over action_args...

    # If there's only one "domain" and "path", validate that domain/path
    # is an available url and normalize the path.

    domain_args = [ (name, value[0]) for name, value in args_dict.items() if value[1] == "domain" ]
    path_args = [ (name, value[0]) for name, value in args_dict.items() if value[1] == "path" ]

    if len(domain_args) == 1 and len(path_args) == 1:

        domain = domain_args[0][1]
        path = path_args[0][1]
        domain, path = _normalize_domain_path(domain, path)

        # Check the url is available
        conflicts = _get_conflicting_apps(domain, path)
        if conflicts:
            apps = []
            for path, app_id, app_label in conflicts:
                apps.append(" * {domain:s}{path:s} → {app_label:s} ({app_id:s})".format(
                    domain=domain,
                    path=path,
                    app_id=app_id,
                    app_label=app_label,
                ))

            raise YunohostError('app_location_unavailable', apps="\n".join(apps))

        # (We save this normalized path so that the install script have a
        # standard path format to deal with no matter what the user inputted)
        args_dict[path_args[0][0]] = (path, "path")

    return args_dict


def _make_environment_dict(args_dict, prefix="APP_ARG_"):
    """
    Convert a dictionnary containing manifest arguments
    to a dictionnary of env. var. to be passed to scripts

    Keyword arguments:
        arg -- A key/value dictionnary of manifest arguments

    """
    env_dict = {}
    for arg_name, arg_value_and_type in args_dict.items():
        env_dict["YNH_%s%s" % (prefix, arg_name.upper())] = arg_value_and_type[0]
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
    assert match, "Could not parse app instance name : %s" % app_instance_name
    appid = match.groupdict().get('appid')
    app_instance_nb = int(match.groupdict().get('appinstancenb')) if match.groupdict().get('appinstancenb') is not None else 1
    return (appid, app_instance_nb)


def _using_legacy_appslist_system():
    """
    Return True if we're using the old fetchlist scheme.
    This is determined by the presence of some cron job yunohost-applist-foo
    """

    return glob.glob("/etc/cron.d/yunohost-applist-*") != []


def _migrate_appslist_system():
    """
    Migrate from the legacy fetchlist system to the new one
    """
    legacy_crons = glob.glob("/etc/cron.d/yunohost-applist-*")

    for cron_path in legacy_crons:
        appslist_name = os.path.basename(cron_path).replace("yunohost-applist-", "")
        logger.debug(m18n.n('appslist_migrating', appslist=appslist_name))

        # Parse appslist url in cron
        cron_file_content = open(cron_path).read().strip()
        appslist_url_parse = re.search("-u (https?://[^ ]+)", cron_file_content)

        # Abort if we did not find an url
        if not appslist_url_parse or not appslist_url_parse.groups():
            # Bkp the old cron job somewhere else
            bkp_file = "/etc/yunohost/%s.oldlist.bkp" % appslist_name
            os.rename(cron_path, bkp_file)
            # Notice the user
            logger.warning(m18n.n('appslist_could_not_migrate',
                           appslist=appslist_name,
                           bkp_file=bkp_file))
        # Otherwise, register the list and remove the legacy cron
        else:
            appslist_url = appslist_url_parse.groups()[0]
            try:
                _register_new_appslist(appslist_url, appslist_name)
            # Might get an exception if two legacy cron jobs conflict
            # in terms of url...
            except Exception as e:
                logger.error(str(e))
                # Bkp the old cron job somewhere else
                bkp_file = "/etc/yunohost/%s.oldlist.bkp" % appslist_name
                os.rename(cron_path, bkp_file)
                # Notice the user
                logger.warning(m18n.n('appslist_could_not_migrate',
                               appslist=appslist_name,
                               bkp_file=bkp_file))
            else:
                os.remove(cron_path)


def _install_appslist_fetch_cron():

    cron_job_file = "/etc/cron.daily/yunohost-fetch-appslists"

    logger.debug("Installing appslist fetch cron job")

    cron_job = []
    cron_job.append("#!/bin/bash")
    # We add a random delay between 0 and 60 min to avoid every instance fetching
    # the appslist at the same time every night
    cron_job.append("(sleep $((RANDOM%3600));")
    cron_job.append("yunohost app fetchlist > /dev/null 2>&1) &")

    with open(cron_job_file, "w") as f:
        f.write('\n'.join(cron_job))

    _set_permissions(cron_job_file, "root", "root", 0o755)


# FIXME - Duplicate from certificate.py, should be moved into a common helper
# thing...
def _set_permissions(path, user, group, permissions):
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    os.chown(path, uid, gid)
    os.chmod(path, permissions)


def _read_appslist_list():
    """
    Read the json corresponding to the list of appslists
    """

    # If file does not exists yet, return empty dict
    if not os.path.exists(APPSLISTS_JSON):
        return {}

    # Read file content
    with open(APPSLISTS_JSON, "r") as f:
        appslists_json = f.read()

    # Parse json, throw exception if what we got from file is not a valid json
    try:
        appslists = json.loads(appslists_json)
    except ValueError:
        raise YunohostError('appslist_corrupted_json', filename=APPSLISTS_JSON)

    return appslists


def _write_appslist_list(appslist_lists):
    """
    Update the json containing list of appslists
    """

    # Write appslist list
    try:
        with open(APPSLISTS_JSON, "w") as f:
            json.dump(appslist_lists, f)
    except Exception as e:
        raise YunohostError("Error while writing list of appslist %s: %s" %
                            (APPSLISTS_JSON, str(e)), raw_msg=True)


def _register_new_appslist(url, name):
    """
    Add a new appslist to be fetched regularly.
    Raise an exception if url or name conflicts with an existing list.
    """

    appslist_list = _read_appslist_list()

    # Check if name conflicts with an existing list
    if name in appslist_list:
        raise YunohostError('appslist_name_already_tracked', name=name)

    # Check if url conflicts with an existing list
    known_appslist_urls = [appslist["url"] for _, appslist in appslist_list.items()]

    if url in known_appslist_urls:
        raise YunohostError('appslist_url_already_tracked', url=url)

    logger.debug("Registering new appslist %s at %s" % (name, url))

    appslist_list[name] = {
        "url": url,
        "lastUpdate": None
    }

    _write_appslist_list(appslist_list)

    _install_appslist_fetch_cron()


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
        true_list = ['yes', 'Yes', 'true', 'True']
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
    import string
    import random

    char_set = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return ''.join([random.SystemRandom().choice(char_set) for x in range(length)])


def unstable_apps():

    raw_app_installed = app_list(installed=True, raw=True)
    output = []

    for app, infos in raw_app_installed.items():

        repo = infos.get("repository", None)
        state = infos.get("state", None)

        if repo is None or state in ["inprogress", "notworking"]:
            output.append(app)

    return output


def _check_services_status_for_app(services):

    logger.debug("Checking that required services are up and running...")

    # Some apps use php-fpm or php5-fpm which is now php7.0-fpm
    def replace_alias(service):
        if service in ["php-fpm", "php5-fpm"]:
            return "php7.0-fpm"
        else:
            return service
    services = [replace_alias(s) for s in services]

    # We only check those, mostly to ignore "custom" services
    # (added by apps) and because those are the most popular
    # services
    service_filter = ["nginx", "php7.0-fpm", "mysql", "postfix"]
    services = [str(s) for s in services if s in service_filter]

    # List services currently down and raise an exception if any are found
    faulty_services = [s for s in services if service_status(s)["active"] != "active"]
    if faulty_services:
        raise YunohostError('app_action_cannot_be_ran_because_required_services_down',
                            services=', '.join(faulty_services))


def _patch_php5(app_folder):

    files_to_patch = []
    files_to_patch.extend(glob.glob("%s/conf/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/.*" % app_folder))
    files_to_patch.append("%s/manifest.json" % app_folder)

    for filename in files_to_patch:

        # Ignore non-regular files
        if not os.path.isfile(filename):
            continue

        c = "sed -i -e 's@/etc/php5@/etc/php/7.0@g' " \
            "-e 's@/var/run/php5-fpm@/var/run/php/php7.0-fpm@g' " \
            "-e 's@php5@php7.0@g' " \
            "%s" % filename
        os.system(c)
