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
import urllib
from collections import OrderedDict
from datetime import datetime

from moulinette import msignals, m18n, msettings
from moulinette.utils.log import getActionLogger
from moulinette.utils.network import download_json
from moulinette.utils.filesystem import read_file, read_json, read_toml, read_yaml, write_to_file, write_to_json, write_to_yaml, chmod, chown, mkdir

from yunohost.service import service_log, service_status, _run_service_command
from yunohost.utils import packages
from yunohost.utils.error import YunohostError
from yunohost.log import is_unit_operation, OperationLogger

logger = getActionLogger('yunohost.app')

APPS_PATH = '/usr/share/yunohost/apps'
APPS_SETTING_PATH = '/etc/yunohost/apps/'
INSTALL_TMP = '/var/cache/yunohost'
APP_TMP_FOLDER = INSTALL_TMP + '/from_file'

APPS_CATALOG_CACHE = '/var/cache/yunohost/repo'
APPS_CATALOG_CONF = '/etc/yunohost/apps_catalog.yml'
APPS_CATALOG_CRON_PATH = "/etc/cron.daily/yunohost-fetch-apps-catalog"
APPS_CATALOG_API_VERSION = 2
APPS_CATALOG_DEFAULT_URL = "https://app.yunohost.org/default"

re_github_repo = re.compile(
    r'^(http[s]?://|git@)github.com[/:]'
    '(?P<owner>[\w\-_]+)/(?P<repo>[\w\-_]+)(.git)?'
    '(/tree/(?P<tree>.+))?'
)

re_app_instance_name = re.compile(
    r'^(?P<appid>[\w-]+?)(__(?P<appinstancenb>[1-9][0-9]*))?$'
)


def app_catalog(full=False, with_categories=False):
    """
    Return a dict of apps available to installation from Yunohost's app catalog
    """

    # Get app list from catalog cache
    catalog = _load_apps_catalog()
    installed_apps = set(_installed_apps())

    # Trim info for apps if not using --full
    for app, infos in catalog["apps"].items():
        infos["installed"] = app in installed_apps

        infos["manifest"]["description"] = _value_for_locale(infos['manifest']['description'])

        if not full:
            catalog["apps"][app] = {
                "description": infos['manifest']['description'],
                "level": infos["level"],
            }

    # Trim info for categories if not using --full
    for category in catalog["categories"]:
        category["title"] = _value_for_locale(category["title"])
        category["description"] = _value_for_locale(category["description"])
        for subtags in category.get("subtags", []):
            subtags["title"] = _value_for_locale(subtags["title"])

    if not full:
        catalog["categories"] = [{"id": c["id"],
                                  "description": c["description"]}
                                 for c in catalog["categories"]]

    if not with_categories:
        return {"apps": catalog["apps"]}
    else:
        return {"apps": catalog["apps"], "categories": catalog["categories"]}


def app_list(full=False):
    """
    List installed apps
    """
    out = []
    for app_id in sorted(_installed_apps()):
        app_info_dict = app_info(app_id, full=full)
        app_info_dict["id"] = app_id
        out.append(app_info_dict)

    return {'apps': out}


def app_info(app, full=False):
    """
    Get info for a specific app
    """
    if not _is_installed(app):
        raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())

    local_manifest = _get_manifest_of_app(os.path.join(APPS_SETTING_PATH, app))
    settings = _get_app_settings(app)

    ret = {
        'description': _value_for_locale(local_manifest['description']),
        'name': local_manifest['name'],
        'version': local_manifest.get('version', '-'),
    }

    if not full:
        return ret

    ret["manifest"] = local_manifest
    ret['settings'] = settings

    absolute_app_name = app if "__" not in app else app[:app.index('__')]  # idk this is the name of the app even for multiinstance apps (so wordpress__2 -> wordpress)
    ret["from_catalog"] = _load_apps_catalog()["apps"].get(absolute_app_name, {})
    ret['upgradable'] = _app_upgradable(ret)
    ret['supports_change_url'] = os.path.exists(os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url"))
    ret['supports_backup_restore'] = (os.path.exists(os.path.join(APPS_SETTING_PATH, app, "scripts", "backup")) and
                                      os.path.exists(os.path.join(APPS_SETTING_PATH, app, "scripts", "restore")))
    ret['supports_multi_instance'] = is_true(local_manifest.get("multi_instance", False))
    return ret


def _app_upgradable(app_infos):

    # Determine upgradability
    # In case there is neither update_time nor install_time, we assume the app can/has to be upgraded

    if not app_infos.get("from_catalog", None):
        return "url_required"
    if not app_infos["from_catalog"].get("lastUpdate") or not app_infos["from_catalog"].get("git"):
        return "url_required"

    settings = app_infos["settings"]
    local_update_time = settings.get('update_time', settings.get('install_time', 0))
    if app_infos["from_catalog"]['lastUpdate'] > local_update_time:
        return "yes"
    else:
        return "no"


def app_map(app=None, raw=False, user=None):
    """
    List apps by domain

    Keyword argument:
        user -- Allowed app map for a user
        raw -- Return complete dict
        app -- Specific app to map

    """

    from yunohost.permission import user_permission_list

    apps = []
    result = {}
    permissions = user_permission_list(full=True)["permissions"]

    if app is not None:
        if not _is_installed(app):
            raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())
        apps = [app, ]
    else:
        apps = os.listdir(APPS_SETTING_PATH)

    for app_id in apps:
        app_settings = _get_app_settings(app_id)
        if not app_settings:
            continue
        if 'domain' not in app_settings:
            continue
        if 'path' not in app_settings:
            # we assume that an app that doesn't have a path doesn't have an HTTP api
            continue
        # This 'no_sso' settings sound redundant to not having $path defined ....
        # At least from what I can see, all apps using it don't have a path defined ...
        if 'no_sso' in app_settings:  # I don't think we need to check for the value here
            continue
        # Users must at least have access to the main permission to have access to extra permissions
        if user:
            if not app_id + ".main" in permissions:
                logger.warning("Uhoh, no main permission was found for app %s ... sounds like an app was only partially removed due to another bug :/" % app_id)
                continue
            main_perm = permissions[app_id + ".main"]
            if user not in main_perm["corresponding_users"] and "visitors" not in main_perm["allowed"]:
                continue

        domain = app_settings['domain']
        path = app_settings['path'].rstrip('/')
        label = app_settings['label']

        def _sanitized_absolute_url(perm_url):
            # Nominal case : url is relative to the app's path
            if perm_url.startswith("/"):
                perm_domain = domain
                perm_path = path + perm_url.rstrip("/")
            # Otherwise, the urls starts with a domain name, like domain.tld/foo/bar
            # We want perm_domain = domain.tld and perm_path = "/foo/bar"
            else:
                perm_domain, perm_path = perm_url.split("/", 1)
                perm_path = "/" + perm_path.rstrip("/")

            return perm_domain, perm_path

        this_app_perms = {p: i for p, i in permissions.items() if p.startswith(app_id + ".") and i["url"]}
        for perm_name, perm_info in this_app_perms.items():
            # If we're building the map for a specific user, check the user
            # actually is allowed for this specific perm
            if user and user not in perm_info["corresponding_users"] and "visitors" not in perm_info["allowed"]:
                continue
            if perm_info["url"].startswith("re:"):
                # Here, we have an issue if the chosen url is a regex, because
                # the url we want to add to the dict is going to be turned into
                # a clickable link (or analyzed by other parts of yunohost
                # code...). To put it otherwise : in the current code of ssowat,
                # you can't give access a user to a regex.
                #
                # Instead, as drafted by Josue, we could rework the ssowat logic
                # about how routes and their permissions are defined. So for example,
                # have a dict of
                # {  "/route1": ["visitors", "user1", "user2", ...],  # Public route
                #    "/route2_with_a_regex$": ["user1", "user2"],     # Private route
                #    "/route3": None,                                 # Skipped route idk
                # }
                # then each time a user try to request and url, we only keep the
                # longest matching rule and check the user is allowed etc...
                #
                # The challenge with this is (beside actually implementing it)
                # is that it creates a whole new mechanism that ultimately
                # replace all the existing logic about
                # protected/unprotected/skipped uris and regexes and we gotta
                # handle / migrate all the legacy stuff somehow if we don't
                # want to end up with a total mess in the future idk
                logger.error("Permission %s can't be added to the SSOwat configuration because it doesn't support regexes so far..." % perm_name)
                continue

            perm_domain, perm_path = _sanitized_absolute_url(perm_info["url"])

            if perm_name.endswith(".main"):
                perm_label = label
            else:
                # e.g. if perm_name is wordpress.admin, we want "Blog (Admin)" (where Blog is the label of this app)
                perm_label = "%s (%s)" % (label, perm_name.rsplit(".")[-1].replace("_", " ").title())

            if raw:
                if domain not in result:
                    result[perm_domain] = {}
                result[perm_domain][perm_path] = {
                    'label': perm_label,
                    'id': app_id
                }
            else:
                result[perm_domain + perm_path] = perm_label

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

    installed = _is_installed(app)
    if not installed:
        raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())

    if not os.path.exists(os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url")):
        raise YunohostError("app_change_url_no_script", app_name=app)

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

    manifest = _get_manifest_of_app(os.path.join(APPS_SETTING_PATH, app))

    # Retrieve arguments list for change_url script
    # TODO: Allow to specify arguments
    args_odict = _parse_args_from_manifest(manifest, 'change_url')
    args_list = [value[0] for value in args_odict.values()]
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

    app_ssowatconf()

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
    from yunohost.hook import hook_add, hook_remove, hook_exec, hook_callback
    from yunohost.permission import permission_sync_to_user

    apps = app
    # If no app is specified, upgrade all apps
    if not apps:
        # FIXME : not sure what's supposed to happen if there is a url and a file but no apps...
        if not url and not file:
            apps = _installed_apps()
    elif not isinstance(app, list):
        apps = [app]

    # Remove possible duplicates
    apps = [app_ for i, app_ in enumerate(apps) if app_ not in apps[:i]]

    # Abort if any of those app is in fact not installed..
    for app in [app_ for app_ in apps if not _is_installed(app_)]:
        raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())

    if len(apps) == 0:
        raise YunohostError('apps_already_up_to_date')
    if len(apps) > 1:
        logger.info(m18n.n("app_upgrade_several_apps", apps=", ".join(apps)))

    for number, app_instance_name in enumerate(apps):
        logger.info(m18n.n('app_upgrade_app_name', app=app_instance_name))

        app_dict = app_info(app_instance_name, full=True)

        if file and isinstance(file, dict):
            # We use this dirty hack to test chained upgrades in unit/functional tests
            manifest, extracted_app_folder = _extract_app_from_file(file[app_instance_name])
        elif file:
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
        _assert_system_is_sane_for_app(manifest, "pre")

        app_setting_path = APPS_SETTING_PATH + '/' + app_instance_name

        # Retrieve arguments list for upgrade script
        # TODO: Allow to specify arguments
        args_odict = _parse_args_from_manifest(manifest, 'upgrade')
        args_list = [value[0] for value in args_odict.values()]
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

        # Attempt to patch legacy helpers ...
        _patch_legacy_helpers(extracted_app_folder)

        # Apply dirty patch to make php5 apps compatible with php7
        _patch_php5(extracted_app_folder)

        # Execute App upgrade script
        os.system('chown -hR admin: %s' % INSTALL_TMP)

        # Execute the app upgrade script
        upgrade_failed = True
        try:
            upgrade_retcode = hook_exec(extracted_app_folder + '/scripts/upgrade',
                                        args=args_list, env=env_dict)[0]

            upgrade_failed = True if upgrade_retcode != 0 else False
            if upgrade_failed:
                error = m18n.n('app_upgrade_script_failed')
                logger.exception(m18n.n("app_upgrade_failed", app=app_instance_name, error=error))
                failure_message_with_debug_instructions = operation_logger.error(error)
                if msettings.get('interface') != 'api':
                    dump_app_log_extract_for_debugging(operation_logger)
        # Script got manually interrupted ... N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            upgrade_retcode = -1
            error = m18n.n('operation_interrupted')
            logger.exception(m18n.n("app_upgrade_failed", app=app_instance_name, error=error))
            failure_message_with_debug_instructions = operation_logger.error(error)
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback
            error = m18n.n('unexpected_error', error=u"\n" + traceback.format_exc())
            logger.exception(m18n.n("app_install_failed", app=app_instance_name, error=error))
            failure_message_with_debug_instructions = operation_logger.error(error)
        finally:
            # Whatever happened (install success or failure) we check if it broke the system
            # and warn the user about it
            try:
                broke_the_system = False
                _assert_system_is_sane_for_app(manifest, "post")
            except Exception as e:
                broke_the_system = True
                logger.exception(m18n.n("app_upgrade_failed", app=app_instance_name, error=str(e)))
                failure_message_with_debug_instructions = operation_logger.error(str(e))

            # If upgrade failed or broke the system,
            # raise an error and interrupt all other pending upgrades
            if upgrade_failed or broke_the_system:

                # display this if there are remaining apps
                if apps[number + 1:]:
                    not_upgraded_apps = apps[number:]
                    logger.error(m18n.n('app_not_upgraded',
                                        failed_app=app_instance_name,
                                        apps=', '.join(not_upgraded_apps)))

                raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)

            # Otherwise we're good and keep going !
            now = int(time.time())
            app_setting(app_instance_name, 'update_time', now)
            app_setting(app_instance_name, 'current_revision', manifest.get('remote', {}).get('revision', "?"))

            # Clean hooks and add new ones
            hook_remove(app_instance_name)
            if 'hooks' in os.listdir(extracted_app_folder):
                for hook in os.listdir(extracted_app_folder + '/hooks'):
                    hook_add(app_instance_name, extracted_app_folder + '/hooks/' + hook)

            # Replace scripts and manifest and conf (if exists)
            os.system('rm -rf "%s/scripts" "%s/manifest.toml %s/manifest.json %s/conf"' % (app_setting_path, app_setting_path, app_setting_path, app_setting_path))

            if os.path.exists(os.path.join(extracted_app_folder, "manifest.json")):
                os.system('mv "%s/manifest.json" "%s/scripts" %s' % (extracted_app_folder, extracted_app_folder, app_setting_path))
            if os.path.exists(os.path.join(extracted_app_folder, "manifest.toml")):
                os.system('mv "%s/manifest.toml" "%s/scripts" %s' % (extracted_app_folder, extracted_app_folder, app_setting_path))

            for file_to_copy in ["actions.json", "actions.toml", "config_panel.json", "config_panel.toml", "conf"]:
                if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
                    os.system('cp -R %s/%s %s' % (extracted_app_folder, file_to_copy, app_setting_path))

            # So much win
            logger.success(m18n.n('app_upgraded', app=app_instance_name))

            hook_callback('post_app_upgrade', args=args_list, env=env_dict)
            operation_logger.success()

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

    from yunohost.hook import hook_add, hook_remove, hook_exec, hook_callback
    from yunohost.log import OperationLogger
    from yunohost.permission import user_permission_list, permission_create, permission_url, permission_delete, permission_sync_to_user, user_permission_update

    # Fetch or extract sources
    if not os.path.exists(INSTALL_TMP):
        os.makedirs(INSTALL_TMP)

    def confirm_install(confirm):
        # Ignore if there's nothing for confirm (good quality app), if --force is used
        # or if request on the API (confirm already implemented on the API side)
        if confirm is None or force or msettings.get('interface') == 'api':
            return

        if confirm in ["danger", "thirdparty"]:
            answer = msignals.prompt(m18n.n('confirm_app_install_' + confirm,
                                       answers='Yes, I understand'),
                                    color="red")
            if answer != "Yes, I understand":
                raise YunohostError("aborting")

        else:
            answer = msignals.prompt(m18n.n('confirm_app_install_' + confirm,
                                       answers='Y/N'),
                                    color="yellow")
            if answer.upper() != "Y":
                raise YunohostError("aborting")

    raw_app_list = _load_apps_catalog()["apps"]

    if app in raw_app_list or ('@' in app) or ('http://' in app) or ('https://' in app):

        # If we got an app name directly (e.g. just "wordpress"), we gonna test this name
        if app in raw_app_list:
            app_name_to_test = app
        # If we got an url like "https://github.com/foo/bar_ynh, we want to
        # extract "bar" and test if we know this app
        elif ('http://' in app) or ('https://' in app):
            app_name_to_test = app.strip("/").split("/")[-1].replace("_ynh", "")
        else:
            # FIXME : watdo if '@' in app ?
            app_name_to_test = None

        if app_name_to_test in raw_app_list:

            state = raw_app_list[app_name_to_test].get("state", "notworking")
            level = raw_app_list[app_name_to_test].get("level", None)
            confirm = "danger"
            if state in ["working", "validated"]:
                if isinstance(level, int) and level >= 5:
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

    # Check ID
    if 'id' not in manifest or '__' in manifest['id']:
        raise YunohostError('app_id_invalid')

    app_id = manifest['id']

    # Check requirements
    _check_manifest_requirements(manifest, app_id)
    _assert_system_is_sane_for_app(manifest, "pre")

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
    args_list = [value[0] for value in args_odict.values()]
    args_list.append(app_instance_name)

    # Validate domain / path availability for webapps
    _validate_and_normalize_webpath(manifest, args_odict, extracted_app_folder)

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
    data_to_redact = [value[0] for value in args_odict.values() if value[1] == "password"]
    data_to_redact += [urllib.quote(data) for data in data_to_redact if urllib.quote(data) != data]
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
        'install_time': int(time.time()),
        'current_revision': manifest.get('remote', {}).get('revision', "?")
    }
    _set_app_settings(app_instance_name, app_settings)

    # Attempt to patch legacy helpers ...
    _patch_legacy_helpers(extracted_app_folder)

    # Apply dirty patch to make php5 apps compatible with php7
    _patch_php5(extracted_app_folder)

    os.system('chown -R admin: ' + extracted_app_folder)

    # Execute App install script
    os.system('chown -hR admin: %s' % INSTALL_TMP)
    # Move scripts and manifest to the right place
    if os.path.exists(os.path.join(extracted_app_folder, "manifest.json")):
        os.system('cp %s/manifest.json %s' % (extracted_app_folder, app_setting_path))
    if os.path.exists(os.path.join(extracted_app_folder, "manifest.toml")):
        os.system('cp %s/manifest.toml %s' % (extracted_app_folder, app_setting_path))
    os.system('cp -R %s/scripts %s' % (extracted_app_folder, app_setting_path))

    for file_to_copy in ["actions.json", "actions.toml", "config_panel.json", "config_panel.toml", "conf"]:
        if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
            os.system('cp -R %s/%s %s' % (extracted_app_folder, file_to_copy, app_setting_path))

    # Initialize the main permission for the app
    # After the install, if apps don't have a domain and path defined, the default url '/' is removed from the permission
    permission_create(app_instance_name+".main", url="/", allowed=["all_users"])

    # Execute the app install script
    install_failed = True
    try:
        install_retcode = hook_exec(
            os.path.join(extracted_app_folder, 'scripts/install'),
            args=args_list, env=env_dict
        )[0]
        # "Common" app install failure : the script failed and returned exit code != 0
        install_failed = True if install_retcode != 0 else False
        if install_failed:
            error = m18n.n('app_install_script_failed')
            logger.exception(m18n.n("app_install_failed", app=app_id, error=error))
            failure_message_with_debug_instructions = operation_logger.error(error)
            if msettings.get('interface') != 'api':
                dump_app_log_extract_for_debugging(operation_logger)
    # Script got manually interrupted ... N.B. : KeyboardInterrupt does not inherit from Exception
    except (KeyboardInterrupt, EOFError):
        error = m18n.n('operation_interrupted')
        logger.exception(m18n.n("app_install_failed", app=app_id, error=error))
        failure_message_with_debug_instructions = operation_logger.error(error)
    # Something wrong happened in Yunohost's code (most probably hook_exec)
    except Exception as e:
        import traceback
        error = m18n.n('unexpected_error', error=u"\n" + traceback.format_exc())
        logger.exception(m18n.n("app_install_failed", app=app_id, error=error))
        failure_message_with_debug_instructions = operation_logger.error(error)
    finally:
        # Whatever happened (install success or failure) we check if it broke the system
        # and warn the user about it
        try:
            broke_the_system = False
            _assert_system_is_sane_for_app(manifest, "post")
        except Exception as e:
            broke_the_system = True
            logger.exception(m18n.n("app_install_failed", app=app_id, error=str(e)))
            failure_message_with_debug_instructions = operation_logger.error(str(e))

        # If the install failed or broke the system, we remove it
        if install_failed or broke_the_system:

            # This option is meant for packagers to debug their apps more easily
            if no_remove_on_failure:
                raise YunohostError("The installation of %s failed, but was not cleaned up as requested by --no-remove-on-failure." % app_id, raw_msg=True)
            else:
                logger.warning(m18n.n("app_remove_after_failed_install"))

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

            # Try to remove the app
            try:
                remove_retcode = hook_exec(
                    os.path.join(extracted_app_folder, 'scripts/remove'),
                    args=[app_instance_name], env=env_dict_remove
                )[0]
            # Here again, calling hook_exec could fail miserably, or get
            # manually interrupted (by mistake or because script was stuck)
            # In that case we still want to proceed with the rest of the
            # removal (permissions, /etc/yunohost/apps/{app} ...)
            except (KeyboardInterrupt, EOFError, Exception):
                remove_retcode = -1
                import traceback
                logger.exception(m18n.n('unexpected_error', error=u"\n" + traceback.format_exc()))

            # Remove all permission in LDAP
            for permission_name in user_permission_list()["permissions"].keys():
                if permission_name.startswith(app_instance_name+"."):
                    permission_delete(permission_name, force=True, sync_perm=False)

            if remove_retcode != 0:
                msg = m18n.n('app_not_properly_removed',
                             app=app_instance_name)
                logger.warning(msg)
                operation_logger_remove.error(msg)
            else:
                try:
                    _assert_system_is_sane_for_app(manifest, "post")
                except Exception as e:
                    operation_logger_remove.error(e)
                else:
                    operation_logger_remove.success()

            # Clean tmp folders
            shutil.rmtree(app_setting_path)
            shutil.rmtree(extracted_app_folder)

            permission_sync_to_user()

            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)

    # Clean hooks and add new ones
    hook_remove(app_instance_name)
    if 'hooks' in os.listdir(extracted_app_folder):
        for file in os.listdir(extracted_app_folder + '/hooks'):
            hook_add(app_instance_name, extracted_app_folder + '/hooks/' + file)

    # Clean and set permissions
    shutil.rmtree(extracted_app_folder)
    os.system('chmod -R 400 %s' % app_setting_path)
    os.system('chown -R root: %s' % app_setting_path)
    os.system('chown -R admin: %s/scripts' % app_setting_path)

    # If an app doesn't have at least a domain and a path, assume it's not a webapp and remove the default "/" permission
    app_settings = _get_app_settings(app_instance_name)
    domain = app_settings.get('domain', None)
    path = app_settings.get('path', None)
    if not (domain and path):
        permission_url(app_instance_name + ".main", url=None, sync_perm=False)

    _migrate_legacy_permissions(app_instance_name)

    permission_sync_to_user()

    logger.success(m18n.n('installation_complete'))

    hook_callback('post_app_install', args=args_list, env=env_dict)


def dump_app_log_extract_for_debugging(operation_logger):

    with open(operation_logger.log_path, "r") as f:
        lines = f.readlines()

    lines_to_display = []
    for line in lines:

        if not ": " in line.strip():
            continue

        # A line typically looks like
        # 2019-10-19 16:10:27,611: DEBUG - + mysql -u piwigo --password=********** -B piwigo
        # And we just want the part starting by "DEBUG - "
        line = line.strip().split(": ", 1)[1]
        lines_to_display.append(line)

        if line.endswith("+ ynh_exit_properly"):
            break
        elif len(lines_to_display) > 20:
            lines_to_display.pop(0)

    logger.warning("Here's an extract of the logs before the crash. It might help debugging the error:")
    for line in lines_to_display:
        logger.info(line)


def _migrate_legacy_permissions(app):

    from yunohost.permission import user_permission_list, user_permission_update

    # Check if app is apparently using the legacy permission management, defined by the presence of something like
    # ynh_app_setting_set on unprotected_uris (or yunohost app setting)
    install_script_path = os.path.join(APPS_SETTING_PATH, app, 'scripts/install')
    install_script_content = open(install_script_path, "r").read()
    if not re.search(r"(yunohost app setting|ynh_app_setting_set) .*(unprotected|skipped)_uris", install_script_content):
        return

    app_settings = _get_app_settings(app)
    app_perm_currently_allowed = user_permission_list()["permissions"][app + ".main"]["allowed"]

    settings_say_it_should_be_public = (app_settings.get("unprotected_uris", None) == "/"
                                        or app_settings.get("skipped_uris", None) == "/")

    # If the current permission says app is protected, but there are legacy rules saying it should be public...
    if app_perm_currently_allowed == ["all_users"] and settings_say_it_should_be_public:
        # Make it public
        user_permission_update(app + ".main", add="visitors", sync_perm=False)

    # If the current permission says app is public, but there are no setting saying it should be public...
    if app_perm_currently_allowed == ["visitors"] and not settings_say_it_should_be_public:
        # Make is private
        user_permission_update(app + ".main", remove="visitors", sync_perm=False)


@is_unit_operation()
def app_remove(operation_logger, app):
    """
    Remove app

    Keyword argument:
        app -- App(s) to delete

    """
    from yunohost.hook import hook_exec, hook_remove, hook_callback
    from yunohost.permission import user_permission_list, permission_delete, permission_sync_to_user
    if not _is_installed(app):
        raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())

    operation_logger.start()

    logger.info(m18n.n("app_start_remove", app=app))

    app_setting_path = APPS_SETTING_PATH + app

    # TODO: display fail messages from script
    try:
        shutil.rmtree('/tmp/yunohost_remove')
    except Exception:
        pass

    # Attempt to patch legacy helpers ...
    _patch_legacy_helpers(app_setting_path)

    # Apply dirty patch to make php5 apps compatible with php7 (e.g. the remove
    # script might date back from jessie install)
    _patch_php5(app_setting_path)

    manifest = _get_manifest_of_app(app_setting_path)

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

    try:
        ret = hook_exec('/tmp/yunohost_remove/scripts/remove',
                        args=args_list,
                        env=env_dict)[0]
    # Here again, calling hook_exec could fail miserably, or get
    # manually interrupted (by mistake or because script was stuck)
    # In that case we still want to proceed with the rest of the
    # removal (permissions, /etc/yunohost/apps/{app} ...)
    except (KeyboardInterrupt, EOFError, Exception):
        ret = -1
        import traceback
        logger.exception(m18n.n('unexpected_error', error=u"\n" + traceback.format_exc()))

    if ret == 0:
        logger.success(m18n.n('app_removed', app=app))
        hook_callback('post_app_remove', args=args_list, env=env_dict)
    else:
        logger.warning(m18n.n('app_not_properly_removed', app=app))

    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)
    shutil.rmtree('/tmp/yunohost_remove')
    hook_remove(app)

    # Remove all permission in LDAP
    for permission_name in user_permission_list()["permissions"].keys():
        if permission_name.startswith(app+"."):
            permission_delete(permission_name, force=True, sync_perm=False)

    permission_sync_to_user()
    _assert_system_is_sane_for_app(manifest, "post")


def app_addaccess(apps, users=[]):
    """
    Grant access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.permission import user_permission_update

    logger.warning("/!\\ Packagers ! This app is using the legacy permission system. Please use the new helpers ynh_permission_{create,url,update,delete} and the 'visitors' group to manage permissions.")

    output = {}
    for app in apps:
        permission = user_permission_update(app+".main", add=users, remove="all_users")
        output[app] = permission["corresponding_users"]

    return {'allowed_users': output}


def app_removeaccess(apps, users=[]):
    """
    Revoke access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.permission import user_permission_update

    logger.warning("/!\\ Packagers ! This app is using the legacy permission system. Please use the new helpers ynh_permission_{create,url,update,delete} and the 'visitors' group to manage permissions.")

    output = {}
    for app in apps:
        permission = user_permission_update(app+".main", remove=users)
        output[app] = permission["corresponding_users"]

    return {'allowed_users': output}


def app_clearaccess(apps):
    """
    Reset access rights for the app

    Keyword argument:
        apps

    """
    from yunohost.permission import user_permission_reset

    logger.warning("/!\\ Packagers ! This app is using the legacy permission system. Please use the new helpers ynh_permission_{create,url,update,delete} and the 'visitors' group to manage permissions.")

    output = {}
    for app in apps:
        permission = user_permission_reset(app+".main")
        output[app] = permission["corresponding_users"]

    return {'allowed_users': output}


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

    # TODO / FIXME : current trick is to add this to conf.json.persisten
    # This is really not robust and should be improved
    # e.g. have a flag in /etc/yunohost/apps/$app/ to say that this is the
    # default app or idk...
    if not os.path.exists('/etc/ssowat/conf.json.persistent'):
        ssowat_conf = {}
    else:
        ssowat_conf = read_json('/etc/ssowat/conf.json.persistent')

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls'][domain + '/'] = app_domain + app_path

    write_to_json('/etc/ssowat/conf.json.persistent', ssowat_conf)
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

    if delete and key in app_settings:
        del app_settings[key]
    else:
        # FIXME: Allow multiple values for some keys?
        if key in ['redirected_urls', 'redirected_regex']:
            value = yaml.load(value)
        if any(key.startswith(word+"_") for word in ["unprotected", "protected", "skipped"]):
            logger.warning("/!\\ Packagers! This app is still using the skipped/protected/unprotected_uris/regex settings which are now obsolete and deprecated... Instead, you should use the new helpers 'ynh_permission_{create,urls,update,delete}' and the 'visitors' group to initialize the public/private access. Check out the documentation at the bottom of yunohost.org/groups_and_permissions to learn how to use the new permission mechanism.")

        app_settings[key] = value
    _set_app_settings(app, app_settings)

    # Fucking legacy permission management.
    # We need this because app temporarily set the app as unprotected to configure it with curl...
    if key.startswith("unprotected_") or key.startswith("skipped_") and value == "/":
        from permission import user_permission_update
        user_permission_update(app + ".main", add="visitors")


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

    if _is_installed(app):
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


def app_ssowatconf():
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import domain_list, _get_maindomain
    from yunohost.user import user_list
    from yunohost.permission import user_permission_list

    main_domain = _get_maindomain()
    domains = domain_list()['domains']
    all_permissions = user_permission_list(full=True)['permissions']

    skipped_urls = []
    skipped_regex = []
    unprotected_urls = []
    unprotected_regex = []
    protected_urls = []
    protected_regex = []
    redirected_regex = {main_domain + '/yunohost[\/]?$': 'https://' + main_domain + '/yunohost/sso/'}
    redirected_urls = {}

    def _get_setting(settings, name):
        s = settings.get(name, None)
        return s.split(',') if s else []

    for app in _installed_apps():

        app_settings = read_yaml(APPS_SETTING_PATH + app + '/settings.yml')

        if 'domain' not in app_settings:
            continue
        if 'path' not in app_settings:
            continue

        # This 'no_sso' settings sound redundant to not having $path defined ....
        # At least from what I can see, all apps using it don't have a path defined ...
        if 'no_sso' in app_settings:
            continue

        domain = app_settings['domain']
        path = app_settings['path'].rstrip('/')

        def _sanitized_absolute_url(perm_url):
            # Nominal case : url is relative to the app's path
            if perm_url.startswith("/"):
                perm_domain = domain
                perm_path = path + perm_url.rstrip("/")
            # Otherwise, the urls starts with a domain name, like domain.tld/foo/bar
            # We want perm_domain = domain.tld and perm_path = "/foo/bar"
            else:
                perm_domain, perm_path = perm_url.split("/", 1)
                perm_path = "/" + perm_path.rstrip("/")

            return perm_domain + perm_path

        # Skipped
        skipped_urls += [_sanitized_absolute_url(uri) for uri in _get_setting(app_settings, 'skipped_uris')]
        skipped_regex += _get_setting(app_settings, 'skipped_regex')

        # Redirected
        redirected_urls.update(app_settings.get('redirected_urls', {}))
        redirected_regex.update(app_settings.get('redirected_regex', {}))

        # Legacy permission system using (un)protected_uris and _regex managed in app settings...
        unprotected_urls += [_sanitized_absolute_url(uri) for uri in _get_setting(app_settings, 'unprotected_uris')]
        protected_urls += [_sanitized_absolute_url(uri) for uri in _get_setting(app_settings, 'protected_uris')]
        unprotected_regex += _get_setting(app_settings, 'unprotected_regex')
        protected_regex += _get_setting(app_settings, 'protected_regex')

        # New permission system
        this_app_perms = {name: info for name, info in all_permissions.items() if name.startswith(app + ".")}
        for perm_name, perm_info in this_app_perms.items():

            # Ignore permissions for which there's no url defined
            if not perm_info["url"]:
                continue

            # FIXME : gotta handle regex-urls here... meh
            url = _sanitized_absolute_url(perm_info["url"])
            if "visitors" in perm_info["allowed"]:
                if url not in unprotected_urls:
                    unprotected_urls.append(url)

                # Legacy stuff : we remove now protected-urls that might have been declared as unprotected earlier...
                protected_urls = [u for u in protected_urls if u != url]
            else:
                if url not in protected_urls:
                    protected_urls.append(url)

                # Legacy stuff : we remove now unprotected-urls / skipped-urls that might have been declared as protected earlier...
                unprotected_urls = [u for u in unprotected_urls if u != url]
                skipped_urls = [u for u in skipped_urls if u != url]

    for domain in domains:
        skipped_urls.extend([domain + '/yunohost/admin', domain + '/yunohost/api'])

    # Authorize ynh remote diagnosis, ACME challenge and mail autoconfig urls
    skipped_regex.append("^[^/]*/%.well%-known/ynh%-diagnosis/.*$")
    skipped_regex.append("^[^/]*/%.well%-known/acme%-challenge/.*$")
    skipped_regex.append("^[^/]*/%.well%-known/autoconfig/mail/config%-v1%.1%.xml.*$")


    permissions_per_url = {}
    for perm_name, perm_info in all_permissions.items():
        # Ignore permissions for which there's no url defined
        if not perm_info["url"]:
            continue
        permissions_per_url[perm_info["url"]] = perm_info['corresponding_users']


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
        'permissions': permissions_per_url,
    }

    with open('/etc/ssowat/conf.json', 'w+') as f:
        json.dump(conf_dict, f, sort_keys=True, indent=4)

    logger.debug(m18n.n('ssowat_conf_generated'))


def app_change_label(app, new_label):
    installed = _is_installed(app)
    if not installed:
        raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())

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


@is_unit_operation()
def app_action_run(operation_logger, app, action, args=None):
    logger.warning(m18n.n('experimental_feature'))

    from yunohost.hook import hook_exec
    import tempfile

    # will raise if action doesn't exist
    actions = app_action_list(app)["actions"]
    actions = {x["id"]: x for x in actions}

    if action not in actions:
        raise YunohostError("action '%s' not available for app '%s', available actions are: %s" % (action, app, ", ".join(actions.keys())), raw_msg=True)

    operation_logger.start()

    action_declaration = actions[action]

    # Retrieve arguments list for install script
    args_dict = dict(urlparse.parse_qsl(args, keep_blank_values=True)) if args else {}
    args_odict = _parse_args_for_action(actions[action], args=args_dict)
    args_list = [value[0] for value in args_odict.values()]

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
        msg = "Error while executing action '%s' of app '%s': return code %s" % (action, app, retcode)
        operation_logger.error(msg)
        raise YunohostError(msg, raw_msg=True)

    os.remove(path)

    operation_logger.success()
    return logger.success("Action successed!")


# Config panel todo list:
# * docstrings
# * merge translations on the json once the workflow is in place
@is_unit_operation()
def app_config_show_panel(operation_logger, app):
    logger.warning(m18n.n('experimental_feature'))

    from yunohost.hook import hook_exec

    # this will take care of checking if the app is installed
    app_info_dict = app_info(app)

    operation_logger.start()
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
        "logs": operation_logger.success(),
    }


@is_unit_operation()
def app_config_apply(operation_logger, app, args):
    logger.warning(m18n.n('experimental_feature'))

    from yunohost.hook import hook_exec

    installed = _is_installed(app)
    if not installed:
        raise YunohostError('app_not_installed', app=app, all_apps=_get_all_installed_apps_id())

    config_panel = _get_app_config_panel(app)
    config_script = os.path.join(APPS_SETTING_PATH, app, 'scripts', 'config')

    if not config_panel or not os.path.exists(config_script):
        # XXX real exception
        raise Exception("Not config-panel.json nor scripts/config")

    operation_logger.start()
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
        msg = "'script/config apply' return value code: %s (considered as an error)" % return_code
        operation_logger.error(msg)
        raise Exception(msg)

    logger.success("Config updated as expected")
    return {
        "logs": operation_logger.success(),
    }


def _get_all_installed_apps_id():
    """
    Return something like:
       ' * app1
         * app2
         * ...'
    """

    all_apps_ids = sorted(_installed_apps())

    all_apps_ids_formatted = "\n * ".join(all_apps_ids)
    all_apps_ids_formatted = "\n * " + all_apps_ids_formatted

    return all_apps_ids_formatted


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

        panels = filter(lambda (key, value): key not in ("name", "version") and isinstance(value, OrderedDict),
                        toml_config_panel.items())

        for key, value in panels:
            panel = {
                "id": key,
                "name": value["name"],
                "sections": [],
            }

            sections = filter(lambda (k, v): k not in ("name",) and isinstance(v, OrderedDict),
                              value.items())

            for section_key, section_value in sections:
                section = {
                    "id": section_key,
                    "name": section_value["name"],
                    "options": [],
                }

                options = filter(lambda (k, v): k not in ("name",) and isinstance(v, OrderedDict),
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
        raise YunohostError('app_not_installed', app=app_id, all_apps=_get_all_installed_apps_id())
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
        manifest = _get_manifest_of_app(extracted_app_folder)
        manifest['lastUpdate'] = int(time.time())
    except IOError:
        raise YunohostError('app_install_files_invalid')
    except ValueError as e:
        raise YunohostError('app_manifest_invalid', error=e)

    logger.debug(m18n.n('done'))

    manifest['remote'] = {'type': 'file', 'path': path}
    return manifest, extracted_app_folder


def _get_manifest_of_app(path):
    "Get app manifest stored in json or in toml"

    # sample data to get an idea of what is going on
    # this toml extract:
    #
    # license = "free"
    # url = "https://example.com"
    # multi_instance = true
    # version = "1.0~ynh1"
    # packaging_format = 1
    # services = ["nginx", "php7.0-fpm", "mysql"]
    # id = "ynhexample"
    # name = "YunoHost example app"
    #
    # [requirements]
    # yunohost = ">= 3.5"
    #
    # [maintainer]
    # url = "http://example.com"
    # name = "John doe"
    # email = "john.doe@example.com"
    #
    # [description]
    # fr = "Exemple de package d'application pour YunoHost."
    # en = "Example package for YunoHost application."
    #
    # [arguments]
    #     [arguments.install.domain]
    #     type = "domain"
    #     example = "example.com"
    #         [arguments.install.domain.ask]
    #         fr = "Choisissez un nom de domaine pour ynhexample"
    #         en = "Choose a domain name for ynhexample"
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'license', u'free'),
    #              (u'url', u'https://example.com'),
    #              (u'multi_instance', True),
    #              (u'version', u'1.0~ynh1'),
    #              (u'packaging_format', 1),
    #              (u'services', [u'nginx', u'php7.0-fpm', u'mysql']),
    #              (u'id', u'ynhexample'),
    #              (u'name', u'YunoHost example app'),
    #              (u'requirements', OrderedDict([(u'yunohost', u'>= 3.5')])),
    #              (u'maintainer',
    #               OrderedDict([(u'url', u'http://example.com'),
    #                            (u'name', u'John doe'),
    #                            (u'email', u'john.doe@example.com')])),
    #              (u'description',
    #               OrderedDict([(u'fr',
    #                             u"Exemple de package d'application pour YunoHost."),
    #                            (u'en',
    #                             u'Example package for YunoHost application.')])),
    #              (u'arguments',
    #               OrderedDict([(u'install',
    #                             OrderedDict([(u'domain',
    #                                           OrderedDict([(u'type', u'domain'),
    #                                                        (u'example',
    #                                                         u'example.com'),
    #                                                        (u'ask',
    #                                                         OrderedDict([(u'fr',
    #                                                                       u'Choisissez un nom de domaine pour ynhexample'),
    #                                                                      (u'en',
    #                                                                       u'Choose a domain name for ynhexample')]))])),
    #
    # and needs to be converted into this:
    #
    # {
    #     "name": "YunoHost example app",
    #     "id": "ynhexample",
    #     "packaging_format": 1,
    #     "description": {
    #     ¦   "en": "Example package for YunoHost application.",
    #     ¦   "fr": "Exemple de package d’application pour YunoHost."
    #     },
    #     "version": "1.0~ynh1",
    #     "url": "https://example.com",
    #     "license": "free",
    #     "maintainer": {
    #     ¦   "name": "John doe",
    #     ¦   "email": "john.doe@example.com",
    #     ¦   "url": "http://example.com"
    #     },
    #     "requirements": {
    #     ¦   "yunohost": ">= 3.5"
    #     },
    #     "multi_instance": true,
    #     "services": [
    #     ¦   "nginx",
    #     ¦   "php7.0-fpm",
    #     ¦   "mysql"
    #     ],
    #     "arguments": {
    #     ¦   "install" : [
    #     ¦   ¦   {
    #     ¦   ¦   ¦   "name": "domain",
    #     ¦   ¦   ¦   "type": "domain",
    #     ¦   ¦   ¦   "ask": {
    #     ¦   ¦   ¦   ¦   "en": "Choose a domain name for ynhexample",
    #     ¦   ¦   ¦   ¦   "fr": "Choisissez un nom de domaine pour ynhexample"
    #     ¦   ¦   ¦   },
    #     ¦   ¦   ¦   "example": "example.com"
    #     ¦   ¦   },

    if os.path.exists(os.path.join(path, "manifest.toml")):
        manifest_toml = read_toml(os.path.join(path, "manifest.toml"))

        manifest = manifest_toml.copy()

        if "arguments" not in manifest:
            return manifest

        if "install" not in manifest["arguments"]:
            return manifest

        install_arguments = []
        for name, values in manifest_toml.get("arguments", {}).get("install", {}).items():
            args = values.copy()
            args["name"] = name

            install_arguments.append(args)

        manifest["arguments"]["install"] = install_arguments

        return manifest
    elif os.path.exists(os.path.join(path, "manifest.json")):
        return read_json(os.path.join(path, "manifest.json"))
    else:
        return None


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
                manifest = _get_manifest_of_app(extracted_app_folder)
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
        app_dict = _load_apps_catalog()["apps"]

        if app not in app_dict:
            raise YunohostError('app_unknown')
        elif 'git' not in app_dict[app]:
            raise YunohostError('app_unsupported_remote_type')

        app_info = app_dict[app]
        app_info['manifest']['lastUpdate'] = app_info['lastUpdate']
        manifest = app_info['manifest']
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
                manifest = _get_manifest_of_app(extracted_app_folder)
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


def _installed_apps():
    return os.listdir(APPS_SETTING_PATH)


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

    if not requirements:
        return

    logger.debug(m18n.n('app_requirements_checking', app=app_instance_name))

    # Iterate over requirements
    for pkgname, spec in requirements.items():
        if not packages.meets_version_specifier(pkgname, spec):
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
    from yunohost.domain import domain_list, _get_maindomain
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
            if not arg_value in user_list()["users"].keys():
                raise YunohostError('app_argument_invalid', name=arg_name, error=m18n.n('user_unknown', user=arg_value))
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

    return args_dict


def _validate_and_normalize_webpath(manifest, args_dict, app_folder):

    from yunohost.domain import _get_conflicting_apps, _normalize_domain_path

    # If there's only one "domain" and "path", validate that domain/path
    # is an available url and normalize the path.

    domain_args = [(name, value[0]) for name, value in args_dict.items() if value[1] == "domain"]
    path_args = [(name, value[0]) for name, value in args_dict.items() if value[1] == "path"]

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

    # This is likely to be a full-domain app...
    elif len(domain_args) == 1 and len(path_args) == 0:

        # Confirm that this is a full-domain app This should cover most cases
        # ...  though anyway the proper solution is to implement some mechanism
        # in the manifest for app to declare that they require a full domain
        # (among other thing) so that we can dynamically check/display this
        # requirement on the webadmin form and not miserably fail at submit time

        # Full-domain apps typically declare something like path_url="/" or path=/
        # and use ynh_webpath_register or yunohost_app_checkurl inside the install script
        install_script_content = open(os.path.join(app_folder, 'scripts/install')).read()

        if re.search(r"\npath(_url)?=[\"']?/[\"']?\n", install_script_content) \
           and re.search(r"(ynh_webpath_register|yunohost app checkurl)", install_script_content):

            domain = domain_args[0][1]
            if _get_conflicting_apps(domain, "/"):
                raise YunohostError('app_full_domain_unavailable', domain=domain)


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


#
# ############################### #
#  Applications list management   #
# ############################### #
#


def _initialize_apps_catalog_system():
    """
    This function is meant to intialize the apps_catalog system with YunoHost's default app catalog.

    It also creates the cron job that will update the list every day
    """

    default_apps_catalog_list = [{"id": "default", "url": APPS_CATALOG_DEFAULT_URL}]

    cron_job = []
    cron_job.append("#!/bin/bash")
    # We add a random delay between 0 and 60 min to avoid every instance fetching
    # the apps catalog at the same time every night
    cron_job.append("(sleep $((RANDOM%3600));")
    cron_job.append("yunohost tools update --apps > /dev/null) &")
    try:
        logger.debug("Initializing apps catalog system with YunoHost's default app list")
        write_to_yaml(APPS_CATALOG_CONF, default_apps_catalog_list)

        logger.debug("Installing apps catalog fetch daily cron job")
        write_to_file(APPS_CATALOG_CRON_PATH, '\n'.join(cron_job))
        chown(APPS_CATALOG_CRON_PATH, uid="root", gid="root")
        chmod(APPS_CATALOG_CRON_PATH, 0o755)
    except Exception as e:
        raise YunohostError("Could not initialize the apps catalog system... : %s" % str(e))

    logger.success(m18n.n("apps_catalog_init_success"))


def _read_apps_catalog_list():
    """
    Read the json corresponding to the list of apps catalogs
    """

    # Legacy code - can be removed after moving to buster (if the migration got merged before buster)
    if os.path.exists('/etc/yunohost/appslists.json'):
        from yunohost.tools import _get_migration_by_name
        migration = _get_migration_by_name("futureproof_apps_catalog_system")
        migration.run()

    try:
        list_ = read_yaml(APPS_CATALOG_CONF)
        # Support the case where file exists but is empty
        # by returning [] if list_ is None
        return list_ if list_ else []
    except Exception as e:
        raise YunohostError("Could not read the apps_catalog list ... : %s" % str(e))


def _actual_apps_catalog_api_url(base_url):

    return "{base_url}/v{version}/apps.json".format(base_url=base_url, version=APPS_CATALOG_API_VERSION)


def _update_apps_catalog():
    """
    Fetches the json for each apps_catalog and update the cache

    apps_catalog_list is for example :
     [   {"id": "default", "url": "https://app.yunohost.org/default/"}  ]

    Then for each apps_catalog, the actual json URL to be fetched is like :
       https://app.yunohost.org/default/vX/apps.json

    And store it in :
        /var/cache/yunohost/repo/default.json
    """

    apps_catalog_list = _read_apps_catalog_list()

    logger.info(m18n.n("apps_catalog_updating"))

    # Create cache folder if needed
    if not os.path.exists(APPS_CATALOG_CACHE):
        logger.debug("Initialize folder for apps catalog cache")
        mkdir(APPS_CATALOG_CACHE, mode=0o750, parents=True, uid='root')

    for apps_catalog in apps_catalog_list:
        apps_catalog_id = apps_catalog["id"]
        actual_api_url = _actual_apps_catalog_api_url(apps_catalog["url"])

        # Fetch the json
        try:
            apps_catalog_content = download_json(actual_api_url)
        except Exception as e:
            raise YunohostError("apps_catalog_failed_to_download", apps_catalog=apps_catalog_id, error=str(e))

        # Remember the apps_catalog api version for later
        apps_catalog_content["from_api_version"] = APPS_CATALOG_API_VERSION

        # Save the apps_catalog data in the cache
        cache_file = "{cache_folder}/{list}.json".format(cache_folder=APPS_CATALOG_CACHE, list=apps_catalog_id)
        try:
            write_to_json(cache_file, apps_catalog_content)
        except Exception as e:
            raise YunohostError("Unable to write cache data for %s apps_catalog : %s" % (apps_catalog_id, str(e)))

    logger.success(m18n.n("apps_catalog_update_success"))


def _load_apps_catalog():
    """
    Read all the apps catalog cache files and build a single dict (merged_catalog)
    corresponding to all known apps and categories
    """

    merged_catalog = {
        "apps": {},
        "categories": []
    }

    for apps_catalog_id in [L["id"] for L in _read_apps_catalog_list()]:

        # Let's load the json from cache for this catalog
        cache_file = "{cache_folder}/{list}.json".format(cache_folder=APPS_CATALOG_CACHE, list=apps_catalog_id)

        try:
            apps_catalog_content = read_json(cache_file) if os.path.exists(cache_file) else None
        except Exception as e:
            raise ("Unable to read cache for apps_catalog %s : %s" % (apps_catalog_id, str(e)))

        # Check that the version of the data matches version ....
        # ... otherwise it means we updated yunohost in the meantime
        # and need to update the cache for everything to be consistent
        if not apps_catalog_content or apps_catalog_content.get("from_api_version") != APPS_CATALOG_API_VERSION:
            logger.info(m18n.n("apps_catalog_obsolete_cache"))
            _update_apps_catalog()
            apps_catalog_content = read_json(cache_file)

        del apps_catalog_content["from_api_version"]

        # Add apps from this catalog to the output
        for app, info in apps_catalog_content["apps"].items():

            # (N.B. : there's a small edge case where multiple apps catalog could be listing the same apps ...
            #         in which case we keep only the first one found)
            if app in merged_catalog["apps"]:
                logger.warning("Duplicate app %s found between apps catalog %s and %s"
                               % (app, apps_catalog_id, merged_catalog["apps"][app]['repository']))
                continue

            info['repository'] = apps_catalog_id
            merged_catalog["apps"][app] = info

        # Annnnd categories
        merged_catalog["categories"] += apps_catalog_content["categories"]

    return merged_catalog

#
# ############################### #
#        Small utilities          #
# ############################### #
#


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
        return arg.lower() in ['yes', 'true', 'on']
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

    output = []

    for infos in app_list(full=True):

        if not infos.get("from_catalog") or infos.get("from_catalog").get("state") in ["inprogress", "notworking"]:
            output.append(infos["id"])

    return output


def _assert_system_is_sane_for_app(manifest, when):

    logger.debug("Checking that required services are up and running...")

    services = manifest.get("services", [])

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

    if "nginx" not in services:
        services = ["nginx"] + services
    if "fail2ban" not in services:
        services.append("fail2ban")

    # List services currently down and raise an exception if any are found
    faulty_services = [s for s in services if service_status(s)["status"] != "running"]
    if faulty_services:
        if when == "pre":
            raise YunohostError('app_action_cannot_be_ran_because_required_services_down',
                                services=', '.join(faulty_services))
        elif when == "post":
            raise YunohostError('app_action_broke_system',
                                services=', '.join(faulty_services))

    if packages.dpkg_is_broken():
        if when == "pre":
            raise YunohostError("dpkg_is_broken")
        elif when == "post":
            raise YunohostError("this_action_broke_dpkg")


def _patch_php5(app_folder):

    files_to_patch = []
    files_to_patch.extend(glob.glob("%s/conf/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/.*" % app_folder))
    files_to_patch.append("%s/manifest.json" % app_folder)
    files_to_patch.append("%s/manifest.toml" % app_folder)

    for filename in files_to_patch:

        # Ignore non-regular files
        if not os.path.isfile(filename):
            continue

        c = "sed -i -e 's@/etc/php5@/etc/php/7.0@g' " \
            "-e 's@/var/run/php5-fpm@/var/run/php/php7.0-fpm@g' " \
            "-e 's@php5@php7.0@g' " \
            "%s" % filename
        os.system(c)

def _patch_legacy_helpers(app_folder):

    files_to_patch = []
    files_to_patch.extend(glob.glob("%s/scripts/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/.*" % app_folder))

    stuff_to_replace = {
        # Replace
        #    sudo yunohost app initdb $db_user -p $db_pwd
        # by
        #    ynh_mysql_setup_db --db_user=$db_user --db_name=$db_user --db_pwd=$db_pwd
        "yunohost app initdb": (
            r"(sudo )?yunohost app initdb \"?(\$\{?\w+\}?)\"?\s+-p\s\"?(\$\{?\w+\}?)\"?",
            r"ynh_mysql_setup_db --db_user=\2 --db_name=\2 --db_pwd=\3"),
        # Replace
        #    sudo yunohost app checkport whaterver
        # by
        #    ynh_port_available whatever
        "yunohost app checkport": (
            r"(sudo )?yunohost app checkport",
            r"ynh_port_available"),
        # We can't migrate easily port-available
        # .. but at the time of writing this code, only two non-working apps are using it.
        "yunohost tools port-available": (None, None),
        # Replace
        #    yunohost app checkurl "${domain}${path_url}" -a "${app}"
        # by
        #    ynh_webpath_register --app=${app} --domain=${domain} --path_url=${path_url}
        "yunohost app checkurl": (
            r"(sudo )?yunohost app checkurl \"?(\$\{?\w+\}?)\/?(\$\{?\w+\}?)\"?\s+-a\s\"?(\$\{?\w+\}?)\"?",
            r"ynh_webpath_register --app=\4 --domain=\2 --path_url=\3"),
    }

    stuff_to_replace_compiled = {h: (re.compile(r[0]), r[1]) if r[0] else (None,None) for h, r in stuff_to_replace.items()}

    for filename in files_to_patch:

        # Ignore non-regular files
        if not os.path.isfile(filename):
            continue

        content = read_file(filename)
        replaced_stuff = False

        for helper, regexes in stuff_to_replace_compiled.items():
            pattern, replace = regexes
            # If helper is used, attempt to patch the file
            if helper in content and pattern != "":
                content = pattern.sub(replace, content)
                replaced_stuff = True

            # If the helpert is *still* in the content, it means that we
            # couldn't patch the deprecated helper in the previous lines.  In
            # that case, abort the install or whichever step is performed
            if helper in content:
                raise YunohostError("This app is likely pretty old and uses deprecated / outdated helpers that can't be migrated easily. It can't be installed anymore.")

        if replaced_stuff:

            # Check the app do load the helper
            # If it doesn't, add the instruction ourselve (making sure it's after the #!/bin/bash if it's there...
            if filename.split("/")[-1] in ["install", "remove", "upgrade", "backup", "restore"]:
                source_helpers = "source /usr/share/yunohost/helpers"
                if source_helpers not in content:
                    content.replace("#!/bin/bash", "#!/bin/bash\n"+source_helpers)
                if source_helpers not in content:
                    content = source_helpers + "\n" + content

            # Actually write the new content in the file
            write_to_file(filename, content)
            # And complain about those damn deprecated helpers
            logger.error("/!\ Packagers ! This app uses a very old deprecated helpers ... Yunohost automatically patched the helpers to use the new recommended practice, but please do consider fixing the upstream code right now ...")
