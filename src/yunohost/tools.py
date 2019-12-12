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
from importlib import import_module

from moulinette import msignals, m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output, call_async_output
from moulinette.utils.filesystem import read_json, write_to_json, read_yaml, write_to_yaml

from yunohost.app import _update_apps_catalog, app_info, app_upgrade, app_ssowatconf, app_list, _initialize_apps_catalog_system
from yunohost.domain import domain_add, domain_list
from yunohost.dyndns import _dyndns_available, _dyndns_provides
from yunohost.firewall import firewall_upnp
from yunohost.service import service_start, service_enable
from yunohost.regenconf import regen_conf
from yunohost.utils.packages import _dump_sources_list, _list_upgradable_apt_packages
from yunohost.utils.error import YunohostError
from yunohost.log import is_unit_operation, OperationLogger

# FIXME this is a duplicate from apps.py
APPS_SETTING_PATH = '/etc/yunohost/apps/'
MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations.yaml"

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


def tools_maindomain(new_main_domain=None):
    from yunohost.domain import domain_main_domain
    logger.warning(m18n.g("deprecated_command_alias", prog="yunohost", old="tools maindomain", new="domain main-domain"))
    return domain_main_domain(new_main_domain=new_main_domain)


def _set_hostname(hostname, pretty_hostname=None):
    """
    Change the machine hostname using hostnamectl
    """

    if not pretty_hostname:
        pretty_hostname = "(YunoHost/%s)" % hostname

    # First clear nsswitch cache for hosts to make sure hostname is resolved...
    subprocess.call(['nscd', '-i', 'hosts'])

    # Then call hostnamectl
    commands = [
        "hostnamectl --static    set-hostname".split() + [hostname],
        "hostnamectl --transient set-hostname".split() + [hostname],
        "hostnamectl --pretty    set-hostname".split() + [pretty_hostname]
    ]

    for command in commands:
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        out, _ = p.communicate()

        if p.returncode != 0:
            logger.warning(command)
            logger.warning(out)
            logger.error(m18n.n('domain_hostname_failed'))
        else:
            logger.debug(out)


def _detect_virt():
    """
    Returns the output of systemd-detect-virt (so e.g. 'none' or 'lxc' or ...)
    You can check the man of the command to have a list of possible outputs...
    """

    p = subprocess.Popen("systemd-detect-virt".split(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    out, _ = p.communicate()
    return out.split()[0]


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
    from yunohost.domain import domain_main_domain

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
    if not os.path.exists('/etc/ssowat/conf.json.persistent'):
        ssowat_conf = {}
    else:
        ssowat_conf = read_json('/etc/ssowat/conf.json.persistent')

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls']['/'] = domain + '/yunohost/admin'

    write_to_json('/etc/ssowat/conf.json.persistent', ssowat_conf)
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
    domain_main_domain(domain)

    # Change LDAP admin password
    tools_adminpw(password, check_strength=not force_password)

    # Enable UPnP silently and reload firewall
    firewall_upnp('enable', no_refresh=True)

    # Initialize the apps catalog system
    _initialize_apps_catalog_system()

    # Try to update the apps catalog ...
    # we don't fail miserably if this fails,
    # because that could be for example an offline installation...
    try:
        _update_apps_catalog()
    except Exception as e:
        logger.warning(str(e))

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

    logger.warning(m18n.n('yunohost_postinstall_end_tip'))


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
        try:
            _update_apps_catalog()
        except YunohostError as e:
            logger.error(str(e))

        upgradable_apps = list(_list_upgradable_apps())

    if len(upgradable_apps) == 0 and len(upgradable_system_packages) == 0:
        logger.info(m18n.n('already_up_to_date'))

    return {'system': upgradable_system_packages, 'apps': upgradable_apps}


def _list_upgradable_apps():

    app_list_installed = os.listdir(APPS_SETTING_PATH)
    for app_id in app_list_installed:

        app_dict = app_info(app_id, full=True)

        if app_dict["upgradable"] == "yes":

            # FIXME : would make more sense for these infos to be computed
            # directly in app_info and used to check the upgradability of
            # the app...
            current_version = app_dict.get("manifest", {}).get("version", "?")
            current_commit = app_dict.get("settings", {}).get("current_revision", "?")[:7]
            new_version = app_dict.get("from_catalog", {}).get("manifest", {}).get("version", "?")
            new_commit = app_dict.get("from_catalog", {}).get("git", {}).get("revision", "?")[:7]

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

        if not upgradable_apps or (len(apps) and all(app not in upgradable_apps for app in apps)):
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

        critical_packages_upgradable = [p["name"] for p in upgradables if p["name"] in critical_packages]
        noncritical_packages_upgradable = [p["name"] for p in upgradables if p["name"] not in critical_packages]

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

            def is_relevant(l):
                return "Reading database ..." not in l.rstrip()

            callbacks = (
                lambda l: logger.info("+ " + l.rstrip() + "\r") if is_relevant(l) else logger.debug(l.rstrip() + "\r"),
                lambda l: logger.warning(l.rstrip()),
            )
            returncode = call_async_output(dist_upgrade, callbacks, shell=True)
            if returncode != 0:
                logger.warning(m18n.n('tools_upgrade_regular_packages_failed'),
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


# ############################################ #
#                                              #
#            Migrations management             #
#                                              #
# ############################################ #

def tools_migrations_list(pending=False, done=False):
    """
    List existing migrations
    """

    # Check for option conflict
    if pending and done:
        raise YunohostError("migrations_list_conflict_pending_done")

    # Get all migrations
    migrations = _get_migrations_list()

    # Reduce to dictionnaries
    migrations = [{"id": migration.id,
                   "number": migration.number,
                   "name": migration.name,
                   "mode": migration.mode,
                   "state": migration.state,
                   "description": migration.description,
                   "disclaimer": migration.disclaimer} for migration in migrations]

    # If asked, filter pending or done migrations
    if pending or done:
        if done:
            migrations = [m for m in migrations if m["state"] != "pending"]
        if pending:
            migrations = [m for m in migrations if m["state"] == "pending"]

    return {"migrations": migrations}


def tools_migrations_migrate(targets=[], skip=False, auto=False, force_rerun=False, accept_disclaimer=False):
    """
    Perform migrations

    targets        A list migrations to run (all pendings by default)
    --skip         Skip specified migrations (to be used only if you know what you are doing) (must explicit which migrations)
    --auto         Automatic mode, won't run manual migrations (to be used only if you know what you are doing)
    --force-rerun  Re-run already-ran migrations (to be used only if you know what you are doing)(must explicit which migrations)
    --accept-disclaimer  Accept disclaimers of migrations (please read them before using this option) (only valid for one migration)
    """

    all_migrations = _get_migrations_list()

    # Small utility that allows up to get a migration given a name, id or number later
    def get_matching_migration(target):
        for m in all_migrations:
            if m.id == target or m.name == target or m.id.split("_")[0] == target:
                return m

        raise YunohostError("migrations_no_such_migration", id=target)

    # auto, skip and force are exclusive options
    if auto + skip + force_rerun > 1:
        raise YunohostError("migrations_exclusive_options")

    # If no target specified
    if not targets:
        # skip, revert or force require explicit targets
        if (skip or force_rerun):
            raise YunohostError("migrations_must_provide_explicit_targets")

        # Otherwise, targets are all pending migrations
        targets = [m for m in all_migrations if m.state == "pending"]

    # If explicit targets are provided, we shall validate them
    else:
        targets = [get_matching_migration(t) for t in targets]
        done = [t.id for t in targets if t.state != "pending"]
        pending = [t.id for t in targets if t.state == "pending"]

        if skip and done:
            raise YunohostError("migrations_not_pending_cant_skip", ids=', '.join(done))
        if force_rerun and pending:
            raise YunohostError("migrations_pending_cant_rerun", ids=', '.join(pending))
        if not (skip or force_rerun) and done:
            raise YunohostError("migrations_already_ran", ids=', '.join(done))

    # So, is there actually something to do ?
    if not targets:
        logger.info(m18n.n('migrations_no_migrations_to_run'))
        return

    # Actually run selected migrations
    for migration in targets:

        # If we are migrating in "automatic mode" (i.e. from debian configure
        # during an upgrade of the package) but we are asked for running
        # migrations to be ran manually by the user, stop there and ask the
        # user to run the migration manually.
        if auto and migration.mode == "manual":
            logger.warn(m18n.n('migrations_to_be_ran_manually', id=migration.id))

            # We go to the next migration
            continue

        # Check for migration dependencies
        if not skip:
            dependencies = [get_matching_migration(dep) for dep in migration.dependencies]
            pending_dependencies = [dep.id for dep in dependencies if dep.state == "pending"]
            if pending_dependencies:
                logger.error(m18n.n('migrations_dependencies_not_satisfied',
                                    id=migration.id,
                                    dependencies_id=', '.join(pending_dependencies)))
                continue

        # If some migrations have disclaimers (and we're not trying to skip them)
        if migration.disclaimer and not skip:
            # require the --accept-disclaimer option.
            # Otherwise, go to the next migration
            if not accept_disclaimer:
                logger.warn(m18n.n('migrations_need_to_accept_disclaimer',
                                   id=migration.id,
                                   disclaimer=migration.disclaimer))
                continue
            # --accept-disclaimer will only work for the first migration
            else:
                accept_disclaimer = False

        # Start register change on system
        operation_logger = OperationLogger('tools_migrations_migrate_forward')
        operation_logger.start()

        if skip:
            logger.warn(m18n.n('migrations_skip_migration', id=migration.id))
            migration.state = "skipped"
            _write_migration_state(migration.id, "skipped")
            operation_logger.success()
        else:

            try:
                migration.operation_logger = operation_logger
                logger.info(m18n.n('migrations_running_forward', id=migration.id))
                migration.run()
            except Exception as e:
                # migration failed, let's stop here but still update state because
                # we managed to run the previous ones
                msg = m18n.n('migrations_migration_has_failed',
                             exception=e, id=migration.id)
                logger.error(msg, exc_info=1)
                operation_logger.error(msg)
            else:
                logger.success(m18n.n('migrations_success_forward', id=migration.id))
                migration.state = "done"
                _write_migration_state(migration.id, "done")

                operation_logger.success()


def tools_migrations_state():
    """
    Show current migration state
    """
    if os.path.exists("/etc/yunohost/migrations_state.json"):
        _migrate_legacy_migration_json()

    if not os.path.exists(MIGRATIONS_STATE_PATH):
        return {"migrations": {}}

    return read_yaml(MIGRATIONS_STATE_PATH)


def _migrate_legacy_migration_json():

    from moulinette.utils.filesystem import read_json

    logger.debug("Migrating legacy migration state json to yaml...")

    # We fetch the old state containing the last run migration
    old_state = read_json("/etc/yunohost/migrations_state.json")["last_run_migration"]
    last_run_migration_id = str(old_state["number"]) + "_" + old_state["name"]

    # Extract the list of migration ids
    from . import data_migrations
    migrations_path = data_migrations.__path__[0]
    migration_files = filter(lambda x: re.match("^\d+_[a-zA-Z0-9_]+\.py$", x), os.listdir(migrations_path))
    # (here we remove the .py extension and make sure the ids are sorted)
    migration_ids = sorted([f.rsplit(".", 1)[0] for f in migration_files])

    # So now build the new dict for every id up to the last run migration
    migrations = {}
    for migration_id in migration_ids:
        migrations[migration_id] = "done"
        if last_run_migration_id in migration_id:
            break

    # Write the new file and rename the old one
    write_to_yaml(MIGRATIONS_STATE_PATH, {"migrations": migrations})
    os.rename("/etc/yunohost/migrations_state.json", "/etc/yunohost/migrations_state.json.old")


def _write_migration_state(migration_id, state):

    current_states = tools_migrations_state()
    current_states["migrations"][migration_id] = state
    write_to_yaml(MIGRATIONS_STATE_PATH, current_states)


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

    # states is a datastructure that represents the last run migration
    # it has this form:
    # {
    #     "0001_foo": "skipped",
    #     "0004_baz": "done",
    #     "0002_bar": "skipped",
    #     "0005_zblerg": "done",
    # }
    # (in particular, pending migrations / not already ran are not listed
    states = tools_migrations_state()["migrations"]

    for migration_file in filter(lambda x: re.match("^\d+_[a-zA-Z0-9_]+\.py$", x), os.listdir(migrations_path)):
        m = _load_migration(migration_file)
        m.state = states.get(m.id, "pending")
        migrations.append(m)

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

    logger.debug(m18n.n('migrations_loading_migration', id=migration_id))

    try:
        # this is python builtin method to import a module using a name, we
        # use that to import the migration as a python object so we'll be
        # able to run it in the next loop
        module = import_module("yunohost.data_migrations.{}".format(migration_id))
        return module.MyMigration(migration_id)
    except Exception as e:
        import traceback
        traceback.print_exc()

        raise YunohostError('migrations_failed_to_load_migration', id=migration_id, error=e)


def _skip_all_migrations():
    """
    Skip all pending migrations.
    This is meant to be used during postinstall to
    initialize the migration system.
    """
    all_migrations = _get_migrations_list()
    new_states = {"migrations": {}}
    for migration in all_migrations:
        new_states["migrations"][migration.id] = "skipped"
    write_to_yaml(MIGRATIONS_STATE_PATH, new_states)


class Migration(object):

    # Those are to be implemented by daughter classes

    mode = "auto"
    dependencies = [] # List of migration ids required before running this migration

    @property
    def disclaimer(self):
        return None

    def run(self):
        raise NotImplementedError()

    # The followings shouldn't be overriden

    def __init__(self, id_):
        self.id = id_
        self.number = int(self.id.split("_", 1)[0])
        self.name = self.id.split("_", 1)[1]

    @property
    def description(self):
        return m18n.n("migration_description_%s" % self.id)
