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

""" yunohost_tools.py

    Specific tools
"""
import re
import os
import yaml
import json
import subprocess
import pwd
import socket
from xmlrpclib import Fault
from importlib import import_module
from collections import OrderedDict

from moulinette import msignals, m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output, call_async_output
from moulinette.utils.filesystem import read_json, write_to_json
from yunohost.app import app_fetchlist, app_info, app_upgrade, app_ssowatconf, app_list, _install_appslist_fetch_cron
from yunohost.domain import domain_add, domain_list, _get_maindomain, _set_maindomain
from yunohost.dyndns import _dyndns_available, _dyndns_provides
from yunohost.firewall import firewall_upnp
from yunohost.service import service_status, service_start, service_enable
from yunohost.regenconf import regen_conf
from yunohost.monitor import monitor_disk, monitor_system
from yunohost.utils.packages import ynh_packages_version, _dump_sources_list, _list_upgradable_apt_packages
from yunohost.utils.network import get_public_ip
from yunohost.utils.error import YunohostError
from yunohost.log import is_unit_operation, OperationLogger

# FIXME this is a duplicate from apps.py
APPS_SETTING_PATH = '/etc/yunohost/apps/'
MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations_state.json"

logger = getActionLogger('yunohost.tools')


def tools_ldapinit():
    """
    YunoHost LDAP initialization


    """

    with open('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml') as f:
        ldap_map = yaml.load(f)

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    for rdn, attr_dict in ldap_map['parents'].items():
        try:
            ldap.add(rdn, attr_dict)
        except Exception as e:
            logger.warn("Error when trying to inject '%s' -> '%s' into ldap: %s" % (rdn, attr_dict, e))

    for rdn, attr_dict in ldap_map['children'].items():
        try:
            ldap.add(rdn, attr_dict)
        except Exception as e:
            logger.warn("Error when trying to inject '%s' -> '%s' into ldap: %s" % (rdn, attr_dict, e))

    for rdn, attr_dict in ldap_map['depends_children'].items():
        try:
            ldap.add(rdn, attr_dict)
        except Exception as e:
            logger.warn("Error when trying to inject '%s' -> '%s' into ldap: %s" % (rdn, attr_dict, e))

    admin_dict = {
        'cn': 'admin',
        'uid': 'admin',
        'description': 'LDAP Administrator',
        'gidNumber': '1007',
        'uidNumber': '1007',
        'homeDirectory': '/home/admin',
        'loginShell': '/bin/bash',
        'objectClass': ['organizationalRole', 'posixAccount', 'simpleSecurityObject'],
        'userPassword': 'yunohost'
    }

    ldap.update('cn=admin', admin_dict)

    # Force nscd to refresh cache to take admin creation into account
    subprocess.call(['nscd', '-i', 'passwd'])

    # Check admin actually exists now
    try:
        pwd.getpwnam("admin")
    except KeyError:
        logger.error(m18n.n('ldap_init_failed_to_create_admin'))
        raise YunohostError('installation_failed')

    logger.success(m18n.n('ldap_initialized'))


def tools_adminpw(new_password, check_strength=True):
    """
    Change admin password

    Keyword argument:
        new_password

    """
    from yunohost.user import _hash_user_password
    from yunohost.utils.password import assert_password_is_strong_enough
    import spwd

    if check_strength:
        assert_password_is_strong_enough("admin", new_password)

    # UNIX seems to not like password longer than 127 chars ...
    # e.g. SSH login gets broken (or even 'su admin' when entering the password)
    if len(new_password) >= 127:
        raise YunohostError('admin_password_too_long')

    new_hash = _hash_user_password(new_password)

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    try:
        ldap.update("cn=admin", {"userPassword": new_hash, })
    except:
        logger.exception('unable to change admin password')
        raise YunohostError('admin_password_change_failed')
    else:
        # Write as root password
        try:
            hash_root = spwd.getspnam("root").sp_pwd

            with open('/etc/shadow', 'r') as before_file:
                before = before_file.read()

            with open('/etc/shadow', 'w') as after_file:
                after_file.write(before.replace("root:" + hash_root,
                                                "root:" + new_hash.replace('{CRYPT}', '')))
        except IOError:
            logger.warning(m18n.n('root_password_desynchronized'))
            return

        logger.info(m18n.n("root_password_replaced_by_admin_password"))
        logger.success(m18n.n('admin_password_changed'))


@is_unit_operation()
def tools_maindomain(operation_logger, new_domain=None):
    """
    Check the current main domain, or change it

    Keyword argument:
        new_domain -- The new domain to be set as the main domain

    """

    # If no new domain specified, we return the current main domain
    if not new_domain:
        return {'current_main_domain': _get_maindomain()}

    # Check domain exists
    if new_domain not in domain_list()['domains']:
        raise YunohostError('domain_unknown')

    operation_logger.related_to.append(('domain', new_domain))
    operation_logger.start()

    # Apply changes to ssl certs
    ssl_key = "/etc/ssl/private/yunohost_key.pem"
    ssl_crt = "/etc/ssl/private/yunohost_crt.pem"
    new_ssl_key = "/etc/yunohost/certs/%s/key.pem" % new_domain
    new_ssl_crt = "/etc/yunohost/certs/%s/crt.pem" % new_domain

    try:
        if os.path.exists(ssl_key) or os.path.lexists(ssl_key):
            os.remove(ssl_key)
        if os.path.exists(ssl_crt) or os.path.lexists(ssl_crt):
            os.remove(ssl_crt)

        os.symlink(new_ssl_key, ssl_key)
        os.symlink(new_ssl_crt, ssl_crt)

        _set_maindomain(new_domain)
    except Exception as e:
        logger.warning("%s" % e, exc_info=1)
        raise YunohostError('maindomain_change_failed')

    _set_hostname(new_domain)

    # Generate SSOwat configuration file
    app_ssowatconf()

    # Regen configurations
    try:
        with open('/etc/yunohost/installed', 'r'):
            regen_conf()
    except IOError:
        pass

    logger.success(m18n.n('maindomain_changed'))


def _set_hostname(hostname, pretty_hostname=None):
    """
    Change the machine hostname using hostnamectl
    """

    if _is_inside_container():
        logger.warning("You are inside a container and hostname cannot easily be changed")
        return

    if not pretty_hostname:
        pretty_hostname = "(YunoHost/%s)" % hostname

    # First clear nsswitch cache for hosts to make sure hostname is resolved...
    subprocess.call(['nscd', '-i', 'hosts'])

    # Then call hostnamectl
    commands = [
        "sudo hostnamectl --static    set-hostname".split() + [hostname],
        "sudo hostnamectl --transient set-hostname".split() + [hostname],
        "sudo hostnamectl --pretty    set-hostname".split() + [pretty_hostname]
    ]

    for command in commands:
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        out, _ = p.communicate()

        if p.returncode != 0:
            logger.warning(command)
            logger.warning(out)
            raise YunohostError('domain_hostname_failed')
        else:
            logger.debug(out)


def _is_inside_container():
    """
    Check if we're inside a container (i.e. LXC)

    Returns True or False
    """

    # See https://www.2daygeek.com/check-linux-system-physical-virtual-machine-virtualization-technology/
    p = subprocess.Popen("sudo systemd-detect-virt".split(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    out, _ = p.communicate()
    container = ['lxc', 'lxd', 'docker']
    return out.split()[0] in container


@is_unit_operation()
def tools_postinstall(operation_logger, domain, password, ignore_dyndns=False,
                      force_password=False):
    """
    YunoHost post-install

    Keyword argument:
        domain -- YunoHost main domain
        ignore_dyndns -- Do not subscribe domain to a DynDNS service (only
        needed for nohost.me, noho.st domains)
        password -- YunoHost admin password

    """
    from yunohost.utils.password import assert_password_is_strong_enough

    dyndns_provider = "dyndns.yunohost.org"

    # Do some checks at first
    if os.path.isfile('/etc/yunohost/installed'):
        raise YunohostError('yunohost_already_installed')

    # Check password
    if not force_password:
        assert_password_is_strong_enough("admin", password)

    if not ignore_dyndns:
        # Check if yunohost dyndns can handle the given domain
        # (i.e. is it a .nohost.me ? a .noho.st ?)
        try:
            is_nohostme_or_nohost = _dyndns_provides(dyndns_provider, domain)
        # If an exception is thrown, most likely we don't have internet
        # connectivity or something. Assume that this domain isn't manageable
        # and inform the user that we could not contact the dyndns host server.
        except:
            logger.warning(m18n.n('dyndns_provider_unreachable',
                                  provider=dyndns_provider))
            is_nohostme_or_nohost = False

        # If this is a nohost.me/noho.st, actually check for availability
        if is_nohostme_or_nohost:
            # (Except if the user explicitly said he/she doesn't care about dyndns)
            if ignore_dyndns:
                dyndns = False
            # Check if the domain is available...
            elif _dyndns_available(dyndns_provider, domain):
                dyndns = True
            # If not, abort the postinstall
            else:
                raise YunohostError('dyndns_unavailable', domain=domain)
        else:
            dyndns = False
    else:
        dyndns = False

    operation_logger.start()
    logger.info(m18n.n('yunohost_installing'))

    regen_conf(['nslcd', 'nsswitch'], force=True)

    # Initialize LDAP for YunoHost
    # TODO: Improve this part by integrate ldapinit into conf_regen hook
    tools_ldapinit()

    # Create required folders
    folders_to_create = [
        '/etc/yunohost/apps',
        '/etc/yunohost/certs',
        '/var/cache/yunohost/repo',
        '/home/yunohost.backup',
        '/home/yunohost.app'
    ]

    for folder in filter(lambda x: not os.path.exists(x), folders_to_create):
        os.makedirs(folder)

    # Change folders permissions
    os.system('chmod 755 /home/yunohost.app')

    # Set hostname to avoid amavis bug
    if os.system('hostname -d >/dev/null') != 0:
        os.system('hostname yunohost.yunohost.org')

    # Add a temporary SSOwat rule to redirect SSO to admin page
    try:
        with open('/etc/ssowat/conf.json.persistent') as json_conf:
            ssowat_conf = json.loads(str(json_conf.read()))
    except ValueError as e:
        raise YunohostError('ssowat_persistent_conf_read_error', error=str(e))
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls']['/'] = domain + '/yunohost/admin'

    try:
        with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
            json.dump(ssowat_conf, f, sort_keys=True, indent=4)
    except IOError as e:
        raise YunohostError('ssowat_persistent_conf_write_error', error=str(e))

    os.system('chmod 644 /etc/ssowat/conf.json.persistent')

    # Create SSL CA
    regen_conf(['ssl'], force=True)
    ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
    # (Update the serial so that it's specific to this very instance)
    os.system("openssl rand -hex 19 > %s/serial" % ssl_dir)
    commands = [
        'rm %s/index.txt' % ssl_dir,
        'touch %s/index.txt' % ssl_dir,
        'cp %s/openssl.cnf %s/openssl.ca.cnf' % (ssl_dir, ssl_dir),
        'sed -i s/yunohost.org/%s/g %s/openssl.ca.cnf ' % (domain, ssl_dir),
        'openssl req -x509 -new -config %s/openssl.ca.cnf -days 3650 -out %s/ca/cacert.pem -keyout %s/ca/cakey.pem -nodes -batch' % (ssl_dir, ssl_dir, ssl_dir),
        'cp %s/ca/cacert.pem /etc/ssl/certs/ca-yunohost_crt.pem' % ssl_dir,
        'update-ca-certificates'
    ]

    for command in commands:
        p = subprocess.Popen(
            command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        out, _ = p.communicate()

        if p.returncode != 0:
            logger.warning(out)
            raise YunohostError('yunohost_ca_creation_failed')
        else:
            logger.debug(out)

    logger.success(m18n.n('yunohost_ca_creation_success'))

    # New domain config
    regen_conf(['nsswitch'], force=True)
    domain_add(domain, dyndns)
    tools_maindomain(domain)

    # Change LDAP admin password
    tools_adminpw(password, check_strength=not force_password)

    # Enable UPnP silently and reload firewall
    firewall_upnp('enable', no_refresh=True)

    # Setup the default apps list with cron job
    try:
        app_fetchlist(name="yunohost",
                      url="https://app.yunohost.org/apps.json")
    except Exception as e:
        logger.warning(str(e))

    _install_appslist_fetch_cron()

    # Init migrations (skip them, no need to run them on a fresh system)
    _skip_all_migrations()

    os.system('touch /etc/yunohost/installed')

    # Enable and start YunoHost firewall at boot time
    service_enable("yunohost-firewall")
    service_start("yunohost-firewall")

    regen_conf(force=True)

    # Restore original ssh conf, as chosen by the
    # admin during the initial install
    #
    # c.f. the install script and in particular
    # https://github.com/YunoHost/install_script/pull/50
    # The user can now choose during the install to keep
    # the initial, existing sshd configuration
    # instead of YunoHost's recommended conf
    #
    original_sshd_conf = '/etc/ssh/sshd_config.before_yunohost'
    if os.path.exists(original_sshd_conf):
        os.rename(original_sshd_conf, '/etc/ssh/sshd_config')
    else:
        # We need to explicitly ask the regen conf to regen ssh
        # (by default, i.e. first argument = None, it won't because it's too touchy)
        regen_conf(names=["ssh"], force=True)

    logger.success(m18n.n('yunohost_configured'))

    logger.warning(m18n.n('recommend_to_add_first_user'))


def tools_regen_conf(names=[], with_diff=False, force=False, dry_run=False,
                     list_pending=False):
    return regen_conf(names, with_diff, force, dry_run, list_pending)


def tools_update(apps=False, system=False):
    """
    Update apps & system package cache

    Keyword arguments:
        system -- Fetch available system packages upgrades (equivalent to apt update)
        apps -- Fetch the application list to check which apps can be upgraded
    """

    # If neither --apps nor --system specified, do both
    if not apps and not system:
        apps = True
        system = True

    upgradable_system_packages = []
    if system:

        # Update APT cache
        # LC_ALL=C is here to make sure the results are in english
        command = "LC_ALL=C apt update"

        # Filter boring message about "apt not having a stable CLI interface"
        # Also keep track of wether or not we encountered a warning...
        warnings = []

        def is_legit_warning(m):
            legit_warning = m.rstrip() and "apt does not have a stable CLI interface" not in m.rstrip()
            if legit_warning:
                warnings.append(m)
            return legit_warning

        callbacks = (
            # stdout goes to debug
            lambda l: logger.debug(l.rstrip()),
            # stderr goes to warning except for the boring apt messages
            lambda l: logger.warning(l.rstrip()) if is_legit_warning(l) else logger.debug(l.rstrip())
        )

        logger.info(m18n.n('updating_apt_cache'))

        returncode = call_async_output(command, callbacks, shell=True)

        if returncode != 0:
            raise YunohostError('update_apt_cache_failed', sourceslist='\n'.join(_dump_sources_list()))
        elif warnings:
            logger.error(m18n.n('update_apt_cache_warning', sourceslist='\n'.join(_dump_sources_list())))

        upgradable_system_packages = list(_list_upgradable_apt_packages())
        logger.debug(m18n.n('done'))

    upgradable_apps = []
    if apps:
        logger.info(m18n.n('updating_app_lists'))
        try:
            app_fetchlist()
        except YunohostError:
            # FIXME : silent exception !?
            pass

        upgradable_apps = list(_list_upgradable_apps())

    if len(upgradable_apps) == 0 and len(upgradable_system_packages) == 0:
        logger.info(m18n.n('already_up_to_date'))

    return {'system': upgradable_system_packages, 'apps': upgradable_apps}


def _list_upgradable_apps():

    app_list_installed = os.listdir(APPS_SETTING_PATH)
    for app_id in app_list_installed:

        app_dict = app_info(app_id, raw=True)

        if app_dict["upgradable"] == "yes":

            current_version = app_dict.get("version", "?")
            current_commit = app_dict.get("status", {}).get("remote", {}).get("revision", "?")[:7]
            new_version = app_dict.get("manifest",{}).get("version","?")
            new_commit = app_dict.get("git", {}).get("revision", "?")[:7]

            if current_version == new_version:
                current_version += " (" + current_commit + ")"
                new_version += " (" + new_commit + ")"

            yield {
                'id': app_id,
                'label': app_dict['settings']['label'],
                'current_version': current_version,
                'new_version': new_version
            }


@is_unit_operation()
def tools_upgrade(operation_logger, apps=None, system=False):
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
       apps -- List of apps to upgrade (or [] to update all apps)
       system -- True to upgrade system
    """
    from yunohost.utils import packages
    if packages.dpkg_is_broken():
        raise YunohostError("dpkg_is_broken")

    # Check for obvious conflict with other dpkg/apt commands already running in parallel
    if not packages.dpkg_lock_available():
        raise YunohostError("dpkg_lock_not_available")

    if system is not False and apps is not None:
        raise YunohostError("tools_upgrade_cant_both")

    if system is False and apps is None:
        raise YunohostError("tools_upgrade_at_least_one")

    #
    # Apps
    # This is basically just an alias to yunohost app upgrade ...
    #

    if apps is not None:

        # Make sure there's actually something to upgrade

        upgradable_apps = [app["id"] for app in _list_upgradable_apps()]

        if not upgradable_apps:
            logger.info(m18n.n("app_no_upgrade"))
            return
        elif len(apps) and all(app not in upgradable_apps for app in apps):
            logger.info(m18n.n("apps_already_up_to_date"))
            return

        # Actually start the upgrades

        try:
            app_upgrade(app=apps)
        except Exception as e:
            logger.warning('unable to upgrade apps: %s' % str(e))
            logger.error(m18n.n('app_upgrade_some_app_failed'))

        return

    #
    # System
    #

    if system is True:

        # Check that there's indeed some packages to upgrade
        upgradables = list(_list_upgradable_apt_packages())
        if not upgradables:
            logger.info(m18n.n('already_up_to_date'))

        logger.info(m18n.n('upgrading_packages'))
        operation_logger.start()

        # Critical packages are packages that we can't just upgrade
        # randomly from yunohost itself... upgrading them is likely to
        critical_packages = ("moulinette", "yunohost", "yunohost-admin", "ssowat", "python")

        critical_packages_upgradable = [p for p in upgradables if p["name"] in critical_packages]
        noncritical_packages_upgradable = [p for p in upgradables if p["name"] not in critical_packages]

        # Prepare dist-upgrade command
        dist_upgrade = "DEBIAN_FRONTEND=noninteractive"
        dist_upgrade += " APT_LISTCHANGES_FRONTEND=none"
        dist_upgrade += " apt-get"
        dist_upgrade += " --fix-broken --show-upgraded --assume-yes"
        for conf_flag in ["old", "miss", "def"]:
            dist_upgrade += ' -o Dpkg::Options::="--force-conf{}"'.format(conf_flag)
        dist_upgrade += " dist-upgrade"

        #
        # "Regular" packages upgrade
        #
        if noncritical_packages_upgradable:

            logger.info(m18n.n("tools_upgrade_regular_packages"))

            # Mark all critical packages as held
            for package in critical_packages:
                check_output("apt-mark hold %s" % package)

            # Doublecheck with apt-mark showhold that packages are indeed held ...
            held_packages = check_output("apt-mark showhold").split("\n")
            if any(p not in held_packages for p in critical_packages):
                logger.warning(m18n.n("tools_upgrade_cant_hold_critical_packages"))
                operation_logger.error(m18n.n('packages_upgrade_failed'))
                raise YunohostError(m18n.n('packages_upgrade_failed'))

            logger.debug("Running apt command :\n{}".format(dist_upgrade))

            callbacks = (
                lambda l: logger.info("+" + l.rstrip() + "\r"),
                lambda l: logger.warning(l.rstrip()),
            )
            returncode = call_async_output(dist_upgrade, callbacks, shell=True)
            if returncode != 0:
                logger.warning('tools_upgrade_regular_packages_failed',
                               packages_list=', '.join(noncritical_packages_upgradable))
                operation_logger.error(m18n.n('packages_upgrade_failed'))
                raise YunohostError(m18n.n('packages_upgrade_failed'))

        #
        # Critical packages upgrade
        #
        if critical_packages_upgradable:

            logger.info(m18n.n("tools_upgrade_special_packages"))

            # Mark all critical packages as unheld
            for package in critical_packages:
                check_output("apt-mark unhold %s" % package)

            # Doublecheck with apt-mark showhold that packages are indeed unheld ...
            held_packages = check_output("apt-mark showhold").split("\n")
            if any(p in held_packages for p in critical_packages):
                logger.warning(m18n.n("tools_upgrade_cant_unhold_critical_packages"))
                operation_logger.error(m18n.n('packages_upgrade_failed'))
                raise YunohostError(m18n.n('packages_upgrade_failed'))

            #
            # Here we use a dirty hack to run a command after the current
            # "yunohost tools upgrade", because the upgrade of yunohost
            # will also trigger other yunohost commands (e.g. "yunohost tools migrations migrate")
            # (also the upgrade of the package, if executed from the webadmin, is
            # likely to kill/restart the api which is in turn likely to kill this
            # command before it ends...)
            #
            logfile = operation_logger.log_path
            dist_upgrade = dist_upgrade + " 2>&1 | tee -a {}".format(logfile)

            MOULINETTE_LOCK = "/var/run/moulinette_yunohost.lock"
            wait_until_end_of_yunohost_command = "(while [ -f {} ]; do sleep 2; done)".format(MOULINETTE_LOCK)
            mark_success = "(echo 'Done!' | tee -a {} && echo 'success: true' >> {})".format(logfile, operation_logger.md_path)
            mark_failure = "(echo 'Failed :(' | tee -a {} && echo 'success: false' >> {})".format(logfile, operation_logger.md_path)
            update_log_metadata = "sed -i \"s/ended_at: .*$/ended_at: $(date -u +'%Y-%m-%d %H:%M:%S.%N')/\" {}"
            update_log_metadata = update_log_metadata.format(operation_logger.md_path)

            # Dirty hack such that the operation_logger does not add ended_at
            # and success keys in the log metadata.  (c.f. the code of the
            # is_unit_operation + operation_logger.close()) We take care of
            # this ourselves (c.f. the mark_success and updated_log_metadata in
            # the huge command launched by os.system)
            operation_logger.ended_at = "notyet"

            upgrade_completed = "\n" + m18n.n("tools_upgrade_special_packages_completed")
            command = "({wait} && {dist_upgrade}) && {mark_success} || {mark_failure}; {update_metadata}; echo '{done}'".format(
                      wait=wait_until_end_of_yunohost_command,
                      dist_upgrade=dist_upgrade,
                      mark_success=mark_success,
                      mark_failure=mark_failure,
                      update_metadata=update_log_metadata,
                      done=upgrade_completed)

            logger.warning(m18n.n("tools_upgrade_special_packages_explanation"))
            logger.debug("Running command :\n{}".format(command))
            open("/tmp/yunohost-selfupgrade", "w").write("rm /tmp/yunohost-selfupgrade; " + command)
            # Using systemd-run --scope is like nohup/disown and &, but more robust somehow
            # (despite using nohup/disown and &, the self-upgrade process was still getting killed...)
            # ref: https://unix.stackexchange.com/questions/420594/why-process-killed-with-nohup
            # (though I still don't understand it 100%...)
            os.system("systemd-run --scope bash /tmp/yunohost-selfupgrade &")
            return

        else:
            logger.success(m18n.n('system_upgraded'))
            operation_logger.success()


def tools_diagnosis(private=False):
    """
    Return global info about current yunohost instance to help debugging

    """
    diagnosis = OrderedDict()

    # Debian release
    try:
        with open('/etc/debian_version', 'r') as f:
            debian_version = f.read().rstrip()
    except IOError as e:
        logger.warning(m18n.n('diagnosis_debian_version_error', error=format(e)), exc_info=1)
    else:
        diagnosis['host'] = "Debian %s" % debian_version

    # Kernel version
    try:
        with open('/proc/sys/kernel/osrelease', 'r') as f:
            kernel_version = f.read().rstrip()
    except IOError as e:
        logger.warning(m18n.n('diagnosis_kernel_version_error', error=format(e)), exc_info=1)
    else:
        diagnosis['kernel'] = kernel_version

    # Packages version
    diagnosis['packages'] = ynh_packages_version()

    diagnosis["backports"] = check_output("dpkg -l |awk '/^ii/ && $3 ~ /bpo[6-8]/ {print $2}'").split()

    # Server basic monitoring
    diagnosis['system'] = OrderedDict()
    try:
        disks = monitor_disk(units=['filesystem'], human_readable=True)
    except (YunohostError, Fault) as e:
        logger.warning(m18n.n('diagnosis_monitor_disk_error', error=format(e)), exc_info=1)
    else:
        diagnosis['system']['disks'] = {}
        for disk in disks:
            if isinstance(disks[disk], str):
                diagnosis['system']['disks'][disk] = disks[disk]
            else:
                diagnosis['system']['disks'][disk] = 'Mounted on %s, %s (%s free)' % (
                    disks[disk]['mnt_point'],
                    disks[disk]['size'],
                    disks[disk]['avail']
                )

    try:
        system = monitor_system(units=['cpu', 'memory'], human_readable=True)
    except YunohostError as e:
        logger.warning(m18n.n('diagnosis_monitor_system_error', error=format(e)), exc_info=1)
    else:
        diagnosis['system']['memory'] = {
            'ram': '%s (%s free)' % (system['memory']['ram']['total'], system['memory']['ram']['free']),
            'swap': '%s (%s free)' % (system['memory']['swap']['total'], system['memory']['swap']['free']),
        }

    # nginx -t
    p = subprocess.Popen("nginx -t".split(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    out, _ = p.communicate()
    diagnosis["nginx"] = out.strip().split("\n")
    if p.returncode != 0:
        logger.error(out)

    # Services status
    services = service_status()
    diagnosis['services'] = {}

    for service in services:
        diagnosis['services'][service] = "%s (%s)" % (services[service]['status'], services[service]['loaded'])

    # YNH Applications
    try:
        applications = app_list()['apps']
    except YunohostError as e:
        diagnosis['applications'] = m18n.n('diagnosis_no_apps')
    else:
        diagnosis['applications'] = {}
        for application in applications:
            if application['installed']:
                diagnosis['applications'][application['id']] = application['label'] if application['label'] else application['name']

    # Private data
    if private:
        diagnosis['private'] = OrderedDict()

        # Public IP
        diagnosis['private']['public_ip'] = {}
        diagnosis['private']['public_ip']['IPv4'] = get_public_ip(4)
        diagnosis['private']['public_ip']['IPv6'] = get_public_ip(6)

        # Domains
        diagnosis['private']['domains'] = domain_list()['domains']

        diagnosis['private']['regen_conf'] = regen_conf(with_diff=True, dry_run=True)

    try:
        diagnosis['security'] = {
            "CVE-2017-5754": {
                "name": "meltdown",
                "vulnerable": _check_if_vulnerable_to_meltdown(),
            }
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.warning("Unable to check for meltdown vulnerability: %s" % e)

    return diagnosis


def _check_if_vulnerable_to_meltdown():
    # meltdown CVE: https://security-tracker.debian.org/tracker/CVE-2017-5754

    # We use a cache file to avoid re-running the script so many times,
    # which can be expensive (up to around 5 seconds on ARM)
    # and make the admin appear to be slow (c.f. the calls to diagnosis
    # from the webadmin)
    #
    # The cache is in /tmp and shall disappear upon reboot
    # *or* we compare it to dpkg.log modification time
    # such that it's re-ran if there was package upgrades
    # (e.g. from yunohost)
    cache_file = "/tmp/yunohost-meltdown-diagnosis"
    dpkg_log = "/var/log/dpkg.log"
    if os.path.exists(cache_file):
        if not os.path.exists(dpkg_log) or os.path.getmtime(cache_file) > os.path.getmtime(dpkg_log):
            logger.debug("Using cached results for meltdown checker, from %s" % cache_file)
            return read_json(cache_file)[0]["VULNERABLE"]

    # script taken from https://github.com/speed47/spectre-meltdown-checker
    # script commit id is store directly in the script
    file_dir = os.path.split(__file__)[0]
    SCRIPT_PATH = os.path.join(file_dir, "./vendor/spectre-meltdown-checker/spectre-meltdown-checker.sh")

    # '--variant 3' corresponds to Meltdown
    # example output from the script:
    # [{"NAME":"MELTDOWN","CVE":"CVE-2017-5754","VULNERABLE":false,"INFOS":"PTI mitigates the vulnerability"}]
    try:
        logger.debug("Running meltdown vulnerability checker")
        call = subprocess.Popen("bash %s --batch json --variant 3" %
                                SCRIPT_PATH, shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        # TODO / FIXME : here we are ignoring error messages ...
        # in particular on RPi2 and other hardware, the script complains about
        # "missing some kernel info (see -v), accuracy might be reduced"
        # Dunno what to do about that but we probably don't want to harass
        # users with this warning ...
        output, err = call.communicate()
        assert call.returncode in (0, 2, 3), "Return code: %s" % call.returncode

        # If there are multiple lines, sounds like there was some messages
        # in stdout that are not json >.> ... Try to get the actual json
        # stuff which should be the last line
        output = output.strip()
        if "\n" in output:
            logger.debug("Original meltdown checker output : %s" % output)
            output = output.split("\n")[-1]

        CVEs = json.loads(output)
        assert len(CVEs) == 1
        assert CVEs[0]["NAME"] == "MELTDOWN"
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.warning("Something wrong happened when trying to diagnose Meltdown vunerability, exception: %s" % e)
        raise Exception("Command output for failed meltdown check: '%s'" % output)

    logger.debug("Writing results from meltdown checker to cache file, %s" % cache_file)
    write_to_json(cache_file, CVEs)
    return CVEs[0]["VULNERABLE"]


def tools_port_available(port):
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
        return True
    else:
        return False


@is_unit_operation()
def tools_shutdown(operation_logger, force=False):
    shutdown = force
    if not shutdown:
        try:
            # Ask confirmation for server shutdown
            i = msignals.prompt(m18n.n('server_shutdown_confirm', answers='y/N'))
        except NotImplemented:
            pass
        else:
            if i.lower() == 'y' or i.lower() == 'yes':
                shutdown = True

    if shutdown:
        operation_logger.start()
        logger.warn(m18n.n('server_shutdown'))
        subprocess.check_call(['systemctl', 'poweroff'])


@is_unit_operation()
def tools_reboot(operation_logger, force=False):
    reboot = force
    if not reboot:
        try:
            # Ask confirmation for restoring
            i = msignals.prompt(m18n.n('server_reboot_confirm', answers='y/N'))
        except NotImplemented:
            pass
        else:
            if i.lower() == 'y' or i.lower() == 'yes':
                reboot = True
    if reboot:
        operation_logger.start()
        logger.warn(m18n.n('server_reboot'))
        subprocess.check_call(['systemctl', 'reboot'])


def tools_migrations_list(pending=False, done=False):
    """
    List existing migrations
    """

    # Check for option conflict
    if pending and done:
        raise YunohostError("migrations_list_conflict_pending_done")

    # Get all migrations
    migrations = _get_migrations_list()

    # If asked, filter pending or done migrations
    if pending or done:
        last_migration = tools_migrations_state()["last_run_migration"]
        last_migration = last_migration["number"] if last_migration else -1
        if done:
            migrations = [m for m in migrations if m.number <= last_migration]
        if pending:
            migrations = [m for m in migrations if m.number > last_migration]

    # Reduce to dictionnaries
    migrations = [{"id": migration.id,
                   "number": migration.number,
                   "name": migration.name,
                   "mode": migration.mode,
                   "description": migration.description,
                   "disclaimer": migration.disclaimer} for migration in migrations]

    return {"migrations": migrations}


def tools_migrations_migrate(target=None, skip=False, auto=False, accept_disclaimer=False):
    """
    Perform migrations
    """

    # state is a datastructure that represents the last run migration
    # it has this form:
    # {
    #     "last_run_migration": {
    #             "number": "00xx",
    #             "name": "some name",
    #         }
    # }
    state = tools_migrations_state()

    last_run_migration_number = state["last_run_migration"]["number"] if state["last_run_migration"] else 0

    # load all migrations
    migrations = _get_migrations_list()
    migrations = sorted(migrations, key=lambda x: x.number)

    if not migrations:
        logger.info(m18n.n('migrations_no_migrations_to_run'))
        return

    all_migration_numbers = [x.number for x in migrations]

    if target is None:
        target = migrations[-1].number

    # validate input, target must be "0" or a valid number
    elif target != 0 and target not in all_migration_numbers:
        raise YunohostError('migrations_bad_value_for_target', ", ".join(map(str, all_migration_numbers)))

    logger.debug(m18n.n('migrations_current_target', target))

    # no new migrations to run
    if target == last_run_migration_number:
        logger.info(m18n.n('migrations_no_migrations_to_run'))
        return

    logger.debug(m18n.n('migrations_show_last_migration', last_run_migration_number))

    # we need to run missing migrations
    if last_run_migration_number < target:
        logger.debug(m18n.n('migrations_forward'))
        # drop all already run migrations
        migrations = filter(lambda x: target >= x.number > last_run_migration_number, migrations)
        mode = "forward"

    # we need to go backward on already run migrations
    elif last_run_migration_number > target:
        logger.debug(m18n.n('migrations_backward'))
        # drop all not already run migrations
        migrations = filter(lambda x: target < x.number <= last_run_migration_number, migrations)
        mode = "backward"

    else:  # can't happen, this case is handle before
        raise Exception()

    # effectively run selected migrations
    for migration in migrations:

        if not skip:
            # If we are migrating in "automatic mode" (i.e. from debian configure
            # during an upgrade of the package) but we are asked to run migrations
            # to be ran manually by the user, stop there and ask the user to
            # run the migration manually.
            if auto and migration.mode == "manual":
                logger.warn(m18n.n('migrations_to_be_ran_manually',
                                   number=migration.number,
                                   name=migration.name))
                break

            # If some migrations have disclaimers,
            if migration.disclaimer:
                # require the --accept-disclaimer option. Otherwise, stop everything
                # here and display the disclaimer
                if not accept_disclaimer:
                    logger.warn(m18n.n('migrations_need_to_accept_disclaimer',
                                       number=migration.number,
                                       name=migration.name,
                                       disclaimer=migration.disclaimer))
                    break
                # --accept-disclaimer will only work for the first migration
                else:
                    accept_disclaimer = False

        # Start register change on system
        operation_logger = OperationLogger('tools_migrations_migrate_' + mode)
        operation_logger.start()

        if not skip:

            logger.info(m18n.n('migrations_show_currently_running_migration',
                               number=migration.number, name=migration.name))

            try:
                migration.operation_logger = operation_logger
                if mode == "forward":
                    migration.migrate()
                elif mode == "backward":
                    migration.backward()
                else:  # can't happen
                    raise Exception("Illegal state for migration: '%s', should be either 'forward' or 'backward'" % mode)
            except Exception as e:
                # migration failed, let's stop here but still update state because
                # we managed to run the previous ones
                msg = m18n.n('migrations_migration_has_failed',
                             exception=e,
                             number=migration.number,
                             name=migration.name)
                logger.error(msg, exc_info=1)
                operation_logger.error(msg)
                break
            else:
                logger.success(m18n.n('migrations_success',
                                      number=migration.number, name=migration.name))

        else:  # if skip
            logger.warn(m18n.n('migrations_skip_migration',
                               number=migration.number,
                               name=migration.name))

        # update the state to include the latest run migration
        state["last_run_migration"] = {
            "number": migration.number,
            "name": migration.name
        }

        operation_logger.success()

        # Skip migrations one at a time
        if skip:
            break

    # special case where we want to go back from the start
    if target == 0:
        state["last_run_migration"] = None

    write_to_json(MIGRATIONS_STATE_PATH, state)


def tools_migrations_state():
    """
    Show current migration state
    """
    if not os.path.exists(MIGRATIONS_STATE_PATH):
        return {"last_run_migration": None}

    return read_json(MIGRATIONS_STATE_PATH)


def tools_shell(command=None):
    """
    Launch an (i)python shell in the YunoHost context.

    This is entirely aim for development.
    """

    from yunohost.utils.ldap import _get_ldap_interface
    ldap = _get_ldap_interface()

    if command:
        exec(command)
        return

    logger.warn("The \033[1;34mldap\033[0m interface is available in this context")
    try:
        from IPython import embed
        embed()
    except ImportError:
        logger.warn("You don't have IPython installed, consider installing it as it is way better than the standard shell.")
        logger.warn("Falling back on the standard shell.")

        import readline  # will allow Up/Down/History in the console
        readline  # to please pyflakes
        import code
        vars = globals().copy()
        vars.update(locals())
        shell = code.InteractiveConsole(vars)
        shell.interact()


def _get_migrations_list():
    migrations = []

    try:
        from . import data_migrations
    except ImportError:
        # not data migrations present, return empty list
        return migrations

    migrations_path = data_migrations.__path__[0]

    if not os.path.exists(migrations_path):
        logger.warn(m18n.n('migrations_cant_reach_migration_file', migrations_path))
        return migrations

    for migration_file in filter(lambda x: re.match("^\d+_[a-zA-Z0-9_]+\.py$", x), os.listdir(migrations_path)):
        migrations.append(_load_migration(migration_file))

    return sorted(migrations, key=lambda m: m.id)


def _get_migration_by_name(migration_name):
    """
    Low-level / "private" function to find a migration by its name
    """

    try:
        from . import data_migrations
    except ImportError:
        raise AssertionError("Unable to find migration with name %s" % migration_name)

    migrations_path = data_migrations.__path__[0]
    migrations_found = filter(lambda x: re.match("^\d+_%s\.py$" % migration_name, x), os.listdir(migrations_path))

    assert len(migrations_found) == 1, "Unable to find migration with name %s" % migration_name

    return _load_migration(migrations_found[0])


def _load_migration(migration_file):

    migration_id = migration_file[:-len(".py")]

    number, name = migration_id.split("_", 1)

    logger.debug(m18n.n('migrations_loading_migration',
                        number=number, name=name))

    try:
        # this is python builtin method to import a module using a name, we
        # use that to import the migration as a python object so we'll be
        # able to run it in the next loop
        module = import_module("yunohost.data_migrations.{}".format(migration_id))
        return module.MyMigration(migration_id)
    except Exception:
        import traceback
        traceback.print_exc()

        raise YunohostError('migrations_error_failed_to_load_migration',
                            number=number, name=name)


def _skip_all_migrations():
    """
    Skip all pending migrations.
    This is meant to be used during postinstall to
    initialize the migration system.
    """
    state = tools_migrations_state()

    # load all migrations
    migrations = _get_migrations_list()
    migrations = sorted(migrations, key=lambda x: x.number)
    last_migration = migrations[-1]

    state["last_run_migration"] = {
        "number": last_migration.number,
        "name": last_migration.name
    }
    write_to_json(MIGRATIONS_STATE_PATH, state)


class Migration(object):

    # Those are to be implemented by daughter classes

    mode = "auto"

    def forward(self):
        raise NotImplementedError()

    def backward(self):
        pass

    @property
    def disclaimer(self):
        return None

    # The followings shouldn't be overriden

    def migrate(self):
        self.forward()

    def __init__(self, id_):
        self.id = id_
        self.number = int(self.id.split("_", 1)[0])
        self.name = self.id.split("_", 1)[1]

    @property
    def description(self):
        return m18n.n("migration_description_%s" % self.id)
