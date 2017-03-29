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
import os
import yaml
import requests
import json
import errno
import logging
import subprocess
import pwd
from collections import OrderedDict

import apt
import apt.progress

from moulinette.core import MoulinetteError, init_authenticator
from moulinette.utils.log import getActionLogger
from yunohost.app import app_fetchlist, app_info, app_upgrade, app_ssowatconf, app_list
from yunohost.domain import domain_add, domain_list, get_public_ip, _get_maindomain, _set_maindomain
from yunohost.dyndns import dyndns_subscribe
from yunohost.firewall import firewall_upnp
from yunohost.service import service_status, service_regen_conf, service_log
from yunohost.monitor import monitor_disk, monitor_system
from yunohost.utils.packages import ynh_packages_version

# FIXME this is a duplicate from apps.py
APPS_SETTING_PATH= '/etc/yunohost/apps/'

logger = getActionLogger('yunohost.tools')


def tools_ldapinit():
    """
    YunoHost LDAP initialization


    """

    # Instantiate LDAP Authenticator
    auth = init_authenticator(('ldap', 'default'),
                              {'uri': "ldap://localhost:389",
                               'base_dn': "dc=yunohost,dc=org",
                               'user_rdn': "cn=admin" })
    auth.authenticate('yunohost')

    with open('/usr/share/yunohost/yunohost-config/moulinette/ldap_scheme.yml') as f:
        ldap_map = yaml.load(f)

    for rdn, attr_dict in ldap_map['parents'].items():
        try:
            auth.add(rdn, attr_dict)
        except:
            pass

    for rdn, attr_dict in ldap_map['children'].items():
        try:
            auth.add(rdn, attr_dict)
        except:
            pass

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
    try:
        auth.con.passwd_s('cn=admin,dc=yunohost,dc=org', None, new_password)
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

    # Set hostname
    pretty_hostname = "(YunoHost/%s)" % new_domain
    commands = [
        "sudo hostnamectl --static    set-hostname".split() + [new_domain],
        "sudo hostnamectl --transient set-hostname".split() + [new_domain],
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

    # Generate SSOwat configuration file
    app_ssowatconf(auth)

    # Regen configurations
    try:
        with open('/etc/yunohost/installed', 'r') as f:
            service_regen_conf()
    except IOError:
        pass

    logger.success(m18n.n('maindomain_changed'))


def tools_postinstall(domain, password, ignore_dyndns=False):
    """
    YunoHost post-install

    Keyword argument:
        domain -- YunoHost main domain
        ignore_dyndns -- Do not subscribe domain to a DynDNS service (only
        needed for nohost.me, noho.st domains)
        password -- YunoHost admin password

    """
    dyndns = not ignore_dyndns

    # Do some checks at first
    if os.path.isfile('/etc/yunohost/installed'):
        raise MoulinetteError(errno.EPERM,
                              m18n.n('yunohost_already_installed'))
    if len(domain.split('.')) >= 3 and not ignore_dyndns:
        try:
            r = requests.get('https://dyndns.yunohost.org/domains')
        except requests.ConnectionError:
            pass
        else:
            dyndomains = json.loads(r.text)
            dyndomain  = '.'.join(domain.split('.')[1:])

            if dyndomain in dyndomains:
                if requests.get('https://dyndns.yunohost.org/test/%s' % domain).status_code == 200:
                    dyndns = True
                else:
                    raise MoulinetteError(errno.EEXIST,
                                          m18n.n('dyndns_unavailable'))
            else:
                dyndns = False
    else:
        dyndns = False

    logger.info(m18n.n('yunohost_installing'))

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
    if os.system('hostname -d') != 0:
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

    ssowat_conf['redirected_urls']['/'] = domain +'/yunohost/admin'

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
        'rm %s/index.txt'       % ssl_dir,
        'touch %s/index.txt'    % ssl_dir,
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
    domain_add(auth, domain, dyndns)
    tools_maindomain(auth, domain)

    # Change LDAP admin password
    tools_adminpw(auth, password)

    # Enable UPnP silently and reload firewall
    firewall_upnp('enable', no_refresh=True)

    os.system('touch /etc/yunohost/installed')

    # Enable and start YunoHost firewall at boot time
    os.system('update-rc.d yunohost-firewall enable')
    os.system('service yunohost-firewall start')

    service_regen_conf(force=True)
    logger.success(m18n.n('yunohost_configured'))


def tools_update(ignore_apps=False, ignore_packages=False):
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
        ignore_apps -- Ignore app list update and changelog
        ignore_packages -- Ignore apt cache update and changelog

    """
    packages = []
    if not ignore_packages:
        cache = apt.Cache()

        # Update APT cache
        logger.info(m18n.n('updating_apt_cache'))
        if not cache.update():
            raise MoulinetteError(errno.EPERM, m18n.n('update_cache_failed'))

        logger.info(m18n.n('done'))

        cache.open(None)
        cache.upgrade(True)

        # Add changelogs to the result
        for pkg in cache.get_changes():
            packages.append({
                'name': pkg.name,
                'fullname': pkg.fullname,
                'changelog': pkg.get_changelog()
            })

    apps = []
    if not ignore_apps:
        try:
            app_fetchlist()
        except MoulinetteError:
            pass
        app_list = os.listdir(APPS_SETTING_PATH)
        if len(app_list) > 0:
            for app_id in app_list:
                if '__' in app_id:
                    original_app_id = app_id[:app_id.index('__')]
                else:
                    original_app_id = app_id

                current_app_dict = app_info(app_id,  raw=True)
                new_app_dict     = app_info(original_app_id, raw=True)

                # Custom app
                if new_app_dict is None or 'lastUpdate' not in new_app_dict or 'git' not in new_app_dict:
                    continue

                if (new_app_dict['lastUpdate'] > current_app_dict['lastUpdate']) \
                      or ('update_time' not in current_app_dict['settings'] \
                           and (new_app_dict['lastUpdate'] > current_app_dict['settings']['install_time'])) \
                      or ('update_time' in current_app_dict['settings'] \
                           and (new_app_dict['lastUpdate'] > current_app_dict['settings']['update_time'])):
                    apps.append({
                        'id': app_id,
                        'label': current_app_dict['settings']['label']
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
            logger.error(m18n.n('app_upgrade_failed'))

    if not failure:
        logger.success(m18n.n('system_upgraded'))

    # Return API logs if it is an API call
    if is_api:
        return {"log": service_log('yunohost-api', number="100").values()[0]}


def tools_diagnosis(auth, private=False):
    """
    Return global info about current yunohost instance to help debugging

    """
    diagnosis = OrderedDict();

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

    # Server basic monitoring
    diagnosis['system'] = OrderedDict()
    try:
        disks = monitor_disk(units=['filesystem'], human_readable=True)
    except MoulinetteError as e:
        logger.warning(m18n.n('diagnosis_monitor_disk_error', error=format(e)), exc_info=1)
    else:
        diagnosis['system']['disks'] = {}
        for disk in disks:
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
            'ram' : '%s (%s free)' % (system['memory']['ram']['total'], system['memory']['ram']['free']),
            'swap' : '%s (%s free)' % (system['memory']['swap']['total'], system['memory']['swap']['free']),
        }

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
        try:
            diagnosis['private']['public_ip']['IPv4'] = get_public_ip(4)
        except MoulinetteError as e:
            pass
        try:
            diagnosis['private']['public_ip']['IPv6'] = get_public_ip(6)
        except MoulinetteError as e:
            pass

        # Domains
        diagnosis['private']['domains'] = domain_list(auth)['domains']

    return diagnosis
