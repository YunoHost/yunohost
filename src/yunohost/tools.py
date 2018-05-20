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
import errno
import logging
import subprocess
import pwd
import socket
from xmlrpclib import Fault
from importlib import import_module
from collections import OrderedDict

import apt
import apt.progress

from moulinette import msettings, msignals, m18n
from moulinette.core import MoulinetteError, init_authenticator
from moulinette.utils.log import getActionLogger
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_json, write_to_json
from yunohost.app import app_fetchlist, app_info, app_upgrade, app_ssowatconf, app_list, _install_appslist_fetch_cron
from yunohost.domain import domain_add, domain_list, _get_maindomain, _set_maindomain
from yunohost.dyndns import _dyndns_available, _dyndns_provides
from yunohost.firewall import firewall_upnp
from yunohost.service import service_status, service_regen_conf, service_log, service_start, service_enable
from yunohost.monitor import monitor_disk, monitor_system
from yunohost.utils.packages import ynh_packages_version
from yunohost.utils.network import get_public_ip

# FIXME this is a duplicate from apps.py
APPS_SETTING_PATH = '/etc/yunohost/apps/'
MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations_state.json"

logger = getActionLogger('yunohost.tools')


def tools_ldapinit():
    """
    YunoHost LDAP initialization


    """

    # Instantiate LDAP Authenticator
    auth = init_authenticator(('ldap', 'default'),
                              {'uri': "ldap://localhost:389",
                               'base_dn': "dc=yunohost,dc=org",
                               'user_rdn': "cn=admin"})
    auth.authenticate('yunohost')

    with open('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml') as f:
        ldap_map = yaml.load(f)

    for rdn, attr_dict in ldap_map['parents'].items():
        try:
            auth.add(rdn, attr_dict)
        except Exception as e:
            logger.warn("Error when trying to inject '%s' -> '%s' into ldap: %s" % (rdn, attr_dict, e))

    for rdn, attr_dict in ldap_map['children'].items():
        try:
            auth.add(rdn, attr_dict)
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

    auth.update('cn=admin', admin_dict)

    # Force nscd to refresh cache to take admin creation into account
    subprocess.call(['nscd', '-i', 'passwd'])

    # Check admin actually exists now
    try:
        pwd.getpwnam("admin")
    except KeyError:
        logger.error(m18n.n('ldap_init_failed_to_create_admin'))
        raise MoulinetteError(errno.EINVAL, m18n.n('installation_failed'))

    logger.success(m18n.n('ldap_initialized'))
    return auth


def tools_adminpw(auth, new_password):
    """
    Change admin password

    Keyword argument:
        new_password

    """
    from yunohost.user import _hash_user_password
    try:
        auth.update("cn=admin", {
            "userPassword": _hash_user_password(new_password),
        })
    except:
        logger.exception('unable to change admin password')
        raise MoulinetteError(errno.EPERM,
                              m18n.n('admin_password_change_failed'))
    else:
        logger.success(m18n.n('admin_password_changed'))


def tools_maindomain(auth, new_domain=None):
    """
    Check the current main domain, or change it

    Keyword argument:
        new_domain -- The new domain to be set as the main domain

    """

    # If no new domain specified, we return the current main domain
    if not new_domain:
        return {'current_main_domain': _get_maindomain()}

    # Check domain exists
    if new_domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

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
        raise MoulinetteError(errno.EPERM, m18n.n('maindomain_change_failed'))

    _set_hostname(new_domain)

    # Generate SSOwat configuration file
    app_ssowatconf(auth)

    # Regen configurations
    try:
        with open('/etc/yunohost/installed', 'r') as f:
            service_regen_conf()
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
            raise MoulinetteError(errno.EIO, m18n.n('domain_hostname_failed'))
        else:
            logger.info(out)


def _is_inside_container():
    """
    Check if we're inside a container (i.e. LXC)

    Returns True or False
    """

    # See https://stackoverflow.com/a/37016302
    p = subprocess.Popen("sudo cat /proc/1/sched".split(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    out, _ = p.communicate()

    return out.split()[1] != "(1,"


def tools_postinstall(domain, password, ignore_dyndns=False):
    """
    YunoHost post-install

    Keyword argument:
        domain -- YunoHost main domain
        ignore_dyndns -- Do not subscribe domain to a DynDNS service (only
        needed for nohost.me, noho.st domains)
        password -- YunoHost admin password

    """
    dyndns_provider = "dyndns.yunohost.org"

    # Do some checks at first
    if os.path.isfile('/etc/yunohost/installed'):
        raise MoulinetteError(errno.EPERM,
                              m18n.n('yunohost_already_installed'))

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
                raise MoulinetteError(errno.EEXIST,
                                      m18n.n('dyndns_unavailable',
                                             domain=domain))
        else:
            dyndns = False
    else:
        dyndns = False

    logger.info(m18n.n('yunohost_installing'))

    service_regen_conf(['nslcd', 'nsswitch'], force=True)

    # Initialize LDAP for YunoHost
    # TODO: Improve this part by integrate ldapinit into conf_regen hook
    auth = tools_ldapinit()

    # Create required folders
    folders_to_create = [
        '/etc/yunohost/apps',
        '/etc/yunohost/certs',
        '/var/cache/yunohost/repo',
        '/home/yunohost.backup',
        '/home/yunohost.app'
    ]

    for folder in folders_to_create:
        try:
            os.listdir(folder)
        except OSError:
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
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('ssowat_persistent_conf_read_error', error=e.strerror))
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls']['/'] = domain + '/yunohost/admin'

    try:
        with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
            json.dump(ssowat_conf, f, sort_keys=True, indent=4)
    except IOError as e:
        raise MoulinetteError(errno.EPERM,
                              m18n.n('ssowat_persistent_conf_write_error', error=e.strerror))

    os.system('chmod 644 /etc/ssowat/conf.json.persistent')

    # Create SSL CA
    service_regen_conf(['ssl'], force=True)
    ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
    commands = [
        'echo "01" > %s/serial' % ssl_dir,
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
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('yunohost_ca_creation_failed'))
        else:
            logger.debug(out)

    logger.success(m18n.n('yunohost_ca_creation_success'))

    # New domain config
    service_regen_conf(['nsswitch'], force=True)
    domain_add(auth, domain, dyndns)
    tools_maindomain(auth, domain)

    # Change LDAP admin password
    tools_adminpw(auth, password)

    # Enable UPnP silently and reload firewall
    firewall_upnp('enable', no_refresh=True)

    # Setup the default official app list with cron job
    try:
        app_fetchlist(name="yunohost",
                      url="https://app.yunohost.org/official.json")
    except Exception as e:
        logger.warning(str(e))

    _install_appslist_fetch_cron()

    # Init migrations (skip them, no need to run them on a fresh system)
    tools_migrations_migrate(skip=True, auto=True)

    os.system('touch /etc/yunohost/installed')

    # Enable and start YunoHost firewall at boot time
    service_enable("yunohost-firewall")
    service_start("yunohost-firewall")

    service_regen_conf(force=True)
    logger.success(m18n.n('yunohost_configured'))


def tools_update(ignore_apps=False, ignore_packages=False):
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
        ignore_apps -- Ignore app list update and changelog
        ignore_packages -- Ignore apt cache update and changelog

    """
    # "packages" will list upgradable packages
    packages = []
    if not ignore_packages:
        cache = apt.Cache()

        # Update APT cache
        logger.info(m18n.n('updating_apt_cache'))
        if not cache.update():
            raise MoulinetteError(errno.EPERM, m18n.n('update_cache_failed'))

        cache.open(None)
        cache.upgrade(True)

        # Add changelogs to the result
        for pkg in cache.get_changes():
            packages.append({
                'name': pkg.name,
                'fullname': pkg.fullname,
                'changelog': pkg.get_changelog()
            })
        logger.info(m18n.n('done'))

    # "apps" will list upgradable packages
    apps = []
    if not ignore_apps:
        try:
            app_fetchlist()
        except MoulinetteError:
            # FIXME : silent exception !?
            pass

        app_list_installed = os.listdir(APPS_SETTING_PATH)
        for app_id in app_list_installed:

            app_dict = app_info(app_id, raw=True)

            if app_dict["upgradable"] == "yes":
                apps.append({
                    'id': app_id,
                    'label': app_dict['settings']['label']
                })

    if len(apps) == 0 and len(packages) == 0:
        logger.info(m18n.n('packages_no_upgrade'))

    return {'packages': packages, 'apps': apps}


def tools_upgrade(auth, ignore_apps=False, ignore_packages=False):
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
        ignore_apps -- Ignore apps upgrade
        ignore_packages -- Ignore APT packages upgrade

    """
    failure = False

    # Retrieve interface
    is_api = True if msettings.get('interface') == 'api' else False

    if not ignore_packages:
        cache = apt.Cache()
        cache.open(None)
        cache.upgrade(True)

        # If API call
        if is_api:
            critical_packages = ("moulinette", "yunohost",
                "yunohost-admin", "ssowat", "python")
            critical_upgrades = set()

            for pkg in cache.get_changes():
                if pkg.name in critical_packages:
                    critical_upgrades.add(pkg.name)
                    # Temporarily keep package ...
                    pkg.mark_keep()

            # ... and set a hourly cron up to upgrade critical packages
            if critical_upgrades:
                logger.info(m18n.n('packages_upgrade_critical_later',
                                   packages=', '.join(critical_upgrades)))
                with open('/etc/cron.d/yunohost-upgrade', 'w+') as f:
                    f.write('00 * * * * root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin apt-get install %s -y && rm -f /etc/cron.d/yunohost-upgrade\n' % ' '.join(critical_upgrades))

        if cache.get_changes():
            logger.info(m18n.n('upgrading_packages'))

            try:
                # Apply APT changes
                # TODO: Logs output for the API
                cache.commit(apt.progress.text.AcquireProgress(),
                             apt.progress.base.InstallProgress())
            except Exception as e:
                failure = True
                logger.warning('unable to upgrade packages: %s' % str(e))
                logger.error(m18n.n('packages_upgrade_failed'))
            else:
                logger.info(m18n.n('done'))
        else:
            logger.info(m18n.n('packages_no_upgrade'))

    if not ignore_apps:
        try:
            app_upgrade(auth)
        except Exception as e:
            failure = True
            logger.warning('unable to upgrade apps: %s' % str(e))
            logger.error(m18n.n('app_upgrade_some_app_failed'))

    if not failure:
        logger.success(m18n.n('system_upgraded'))

    # Return API logs if it is an API call
    if is_api:
        return {"log": service_log('yunohost-api', number="100").values()[0]}


def tools_diagnosis(auth, private=False):
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
    except (MoulinetteError, Fault) as e:
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
    except MoulinetteError as e:
        logger.warning(m18n.n('diagnosis_monitor_system_error', error=format(e)), exc_info=1)
    else:
        diagnosis['system']['memory'] = {
            'ram': '%s (%s free)' % (system['memory']['ram']['total'], system['memory']['ram']['free']),
            'swap': '%s (%s free)' % (system['memory']['swap']['total'], system['memory']['swap']['free']),
        }

    # nginx -t
    try:
        diagnosis['nginx'] = check_output("nginx -t").strip().split("\n")
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.warning("Unable to check 'nginx -t', exception: %s" % e)

    # Services status
    services = service_status()
    diagnosis['services'] = {}

    for service in services:
        diagnosis['services'][service] = "%s (%s)" % (services[service]['status'], services[service]['loaded'])

    # YNH Applications
    try:
        applications = app_list()['apps']
    except MoulinetteError as e:
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
        diagnosis['private']['domains'] = domain_list(auth)['domains']

        diagnosis['private']['regen_conf'] = service_regen_conf(with_diff=True, dry_run=True)

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

    # script taken from https://github.com/speed47/spectre-meltdown-checker
    # script commit id is store directly in the script
    file_dir = os.path.split(__file__)[0]
    SCRIPT_PATH = os.path.join(file_dir, "./vendor/spectre-meltdown-checker/spectre-meltdown-checker.sh")

    # '--variant 3' corresponds to Meltdown
    # example output from the script:
    # [{"NAME":"MELTDOWN","CVE":"CVE-2017-5754","VULNERABLE":false,"INFOS":"PTI mitigates the vulnerability"}]
    try:
        call = subprocess.Popen("bash %s --batch json --variant 3" %
                                SCRIPT_PATH, shell=True,
                                  stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)

        output, _ = call.communicate()
        assert call.returncode in (0, 2, 3), "Return code: %s" % call.returncode

        CVEs = json.loads(output)
        assert len(CVEs) == 1
        assert CVEs[0]["NAME"] == "MELTDOWN"
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.warning("Something wrong happened when trying to diagnose Meltdown vunerability, exception: %s" % e)
        raise Exception("Command output for failed meltdown check: '%s'" % output)

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


def tools_shutdown(force=False):
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
        logger.warn(m18n.n('server_shutdown'))
        subprocess.check_call(['systemctl', 'poweroff'])


def tools_reboot(force=False):
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
        logger.warn(m18n.n('server_reboot'))
        subprocess.check_call(['systemctl', 'reboot'])


def tools_migrations_list(pending=False, done=False):
    """
    List existing migrations
    """

    # Check for option conflict
    if pending and done:
        raise MoulinetteError(errno.EINVAL, m18n.n("migrations_list_conflict_pending_done"))

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
    migrations = [{ "id": migration.id,
                    "number": migration.number,
                    "name": migration.name,
                    "mode": migration.mode,
                    "description": migration.description,
                    "disclaimer": migration.disclaimer } for migration in migrations ]

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
        raise MoulinetteError(errno.EINVAL, m18n.n('migrations_bad_value_for_target', ", ".join(map(str, all_migration_numbers))))

    logger.debug(m18n.n('migrations_current_target', target))

    # no new migrations to run
    if target == last_run_migration_number:
        logger.warn(m18n.n('migrations_no_migrations_to_run'))
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

    # If we are migrating in "automatic mode" (i.e. from debian
    # configure during an upgrade of the package) but we are asked to run
    # migrations is to be ran manually by the user
    manual_migrations = [m for m in migrations if m.mode == "manual"]
    if not skip and auto and manual_migrations:
        for m in manual_migrations:
            logger.warn(m18n.n('migrations_to_be_ran_manually',
                               number=m.number,
                               name=m.name))
        return

    # If some migrations have disclaimers, require the --accept-disclaimer
    # option
    migrations_with_disclaimer = [m for m in migrations if m.disclaimer]
    if not skip and not accept_disclaimer and migrations_with_disclaimer:
        for m in migrations_with_disclaimer:
            logger.warn(m18n.n('migrations_need_to_accept_disclaimer',
                               number=m.number,
                               name=m.name,
                               disclaimer=m.disclaimer))
        return

    # effectively run selected migrations
    for migration in migrations:
        if not skip:

            logger.warn(m18n.n('migrations_show_currently_running_migration',
                               number=migration.number, name=migration.name))

            try:
                if mode == "forward":
                    migration.migrate()
                elif mode == "backward":
                    migration.backward()
                else:  # can't happen
                    raise Exception("Illegal state for migration: '%s', should be either 'forward' or 'backward'" % mode)
            except Exception as e:
                # migration failed, let's stop here but still update state because
                # we managed to run the previous ones
                logger.error(m18n.n('migrations_migration_has_failed',
                                    exception=e,
                                    number=migration.number,
                                    name=migration.name),
                                    exc_info=1)
                break

        else:  # if skip
            logger.warn(m18n.n('migrations_skip_migration',
                               number=migration.number,
                               name=migration.name))

        # update the state to include the latest run migration
        state["last_run_migration"] = {
            "number": migration.number,
            "name": migration.name
        }

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


def tools_shell(auth, command=None):
    """
    Launch an (i)python shell in the YunoHost context.

    This is entirely aim for development.
    """

    if command:
        exec(command)
        return

    logger.warn("The \033[1;34mauth\033[0m is available in this context")
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
        import data_migrations
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
        import data_migrations
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

        raise MoulinetteError(errno.EINVAL, m18n.n('migrations_error_failed_to_load_migration',
            number=number, name=name))


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
