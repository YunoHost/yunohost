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

""" yunohost_firewall.py

    Manage firewall rules
"""
import os
import sys
import yaml
import errno
try:
    import miniupnpc
except ImportError:
    sys.stderr.write('Error: Yunohost CLI Require miniupnpc lib\n')
    sys.exit(1)

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils import process
from moulinette.utils.log import getActionLogger
from moulinette.utils.text import prependlines

FIREWALL_FILE = '/etc/yunohost/firewall.yml'
UPNP_CRON_JOB = '/etc/cron.d/yunohost-firewall-upnp'

logger = getActionLogger('yunohost.firewall')


def firewall_allow(protocol, port, ipv4_only=False, ipv6_only=False,
                   no_upnp=False, no_reload=False):
    """
    Allow connections on a port

    Keyword arguments:
        protocol -- Protocol type to allow (TCP/UDP/Both)
        port -- Port or range of ports to open
        ipv4_only -- Only add a rule for IPv4 connections
        ipv6_only -- Only add a rule for IPv6 connections
        no_upnp -- Do not add forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules

    """
    firewall = firewall_list(raw=True)

    # Validate port
    if not isinstance(port, int) and ':' not in port:
        port = int(port)

    # Validate protocols
    protocols = ['TCP', 'UDP']
    if protocol != 'Both' and protocol in protocols:
        protocols = [protocol, ]

    # Validate IP versions
    ipvs = ['ipv4', 'ipv6']
    if ipv4_only and not ipv6_only:
        ipvs = ['ipv4', ]
    elif ipv6_only and not ipv4_only:
        ipvs = ['ipv6', ]

    for p in protocols:
        # Iterate over IP versions to add port
        for i in ipvs:
            if port not in firewall[i][p]:
                firewall[i][p].append(port)
            else:
                ipv = "IPv%s" % i[3]
                logger.warning(m18n.n('port_already_opened', port=port, ip_version=ipv))
        # Add port forwarding with UPnP
        if not no_upnp and port not in firewall['uPnP'][p]:
            firewall['uPnP'][p].append(port)

    # Update and reload firewall
    _update_firewall_file(firewall)
    if not no_reload:
        return firewall_reload()


def firewall_disallow(protocol, port, ipv4_only=False, ipv6_only=False,
                      upnp_only=False, no_reload=False):
    """
    Disallow connections on a port

    Keyword arguments:
        protocol -- Protocol type to disallow (TCP/UDP/Both)
        port -- Port or range of ports to close
        ipv4_only -- Only remove the rule for IPv4 connections
        ipv6_only -- Only remove the rule for IPv6 connections
        upnp_only -- Only remove forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules

    """
    firewall = firewall_list(raw=True)

    # Validate port
    if not isinstance(port, int) and ':' not in port:
        port = int(port)

    # Validate protocols
    protocols = ['TCP', 'UDP']
    if protocol != 'Both' and protocol in protocols:
        protocols = [protocol, ]

    # Validate IP versions and UPnP
    ipvs = ['ipv4', 'ipv6']
    upnp = True
    if ipv4_only and ipv6_only:
        upnp = True  # automatically disallow UPnP
    elif ipv4_only:
        ipvs = ['ipv4', ]
        upnp = upnp_only
    elif ipv6_only:
        ipvs = ['ipv6', ]
        upnp = upnp_only
    elif upnp_only:
        ipvs = []

    for p in protocols:
        # Iterate over IP versions to remove port
        for i in ipvs:
            if port in firewall[i][p]:
                firewall[i][p].remove(port)
            else:
                ipv = "IPv%s" % i[3]
                logger.warning(m18n.n('port_already_closed', port=port, ip_version=ipv))
        # Remove port forwarding with UPnP
        if upnp and port in firewall['uPnP'][p]:
            firewall['uPnP'][p].remove(port)

    # Update and reload firewall
    _update_firewall_file(firewall)
    if not no_reload:
        return firewall_reload()


def firewall_list(raw=False, by_ip_version=False, list_forwarded=False):
    """
    List all firewall rules

    Keyword arguments:
        raw -- Return the complete YAML dict
        by_ip_version -- List rules by IP version
        list_forwarded -- List forwarded ports with UPnP

    """
    with open(FIREWALL_FILE) as f:
        firewall = yaml.load(f)
    if raw:
        return firewall

    # Retrieve all ports for IPv4 and IPv6
    ports = {}
    for i in ['ipv4', 'ipv6']:
        f = firewall[i]
        # Combine TCP and UDP ports
        ports[i] = sorted(set(f['TCP']) | set(f['UDP']))

    if not by_ip_version:
        # Combine IPv4 and IPv6 ports
        ports = sorted(set(ports['ipv4']) | set(ports['ipv6']))

    # Format returned dict
    ret = {"opened_ports": ports}
    if list_forwarded:
        # Combine TCP and UDP forwarded ports
        ret['forwarded_ports'] = sorted(
            set(firewall['uPnP']['TCP']) | set(firewall['uPnP']['UDP']))
    return ret


def firewall_reload(skip_upnp=False):
    """
    Reload all firewall rules

    Keyword arguments:
        skip_upnp -- Do not refresh port forwarding using UPnP

    """
    from yunohost.hook import hook_callback

    reloaded = False
    errors = False

    # Check if SSH port is allowed
    ssh_port = _get_ssh_port()
    if ssh_port not in firewall_list()['opened_ports']:
        firewall_allow('TCP', ssh_port, no_reload=True)

    # Retrieve firewall rules and UPnP status
    firewall = firewall_list(raw=True)
    upnp = firewall_upnp()['enabled'] if not skip_upnp else False

    # IPv4
    try:
        process.check_output("iptables -w -L")
    except process.CalledProcessError as e:
        logger.debug('iptables seems to be not available, it outputs:\n%s',
                     prependlines(e.output.rstrip(), '> '))
        logger.warning(m18n.n('iptables_unavailable'))
    else:
        rules = [
            "iptables -w -F",
            "iptables -w -X",
            "iptables -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
        # Iterate over ports and add rule
        for protocol in ['TCP', 'UDP']:
            for port in firewall['ipv4'][protocol]:
                rules.append("iptables -w -A INPUT -p %s --dport %s -j ACCEPT"
                             % (protocol, process.quote(str(port))))
        rules += [
            "iptables -w -A INPUT -i lo -j ACCEPT",
            "iptables -w -A INPUT -p icmp -j ACCEPT",
            "iptables -w -P INPUT DROP",
        ]

        # Execute each rule
        if process.run_commands(rules, callback=_on_rule_command_error):
            errors = True
        reloaded = True

    # IPv6
    try:
        process.check_output("ip6tables -L")
    except process.CalledProcessError as e:
        logger.debug('ip6tables seems to be not available, it outputs:\n%s',
                     prependlines(e.output.rstrip(), '> '))
        logger.warning(m18n.n('ip6tables_unavailable'))
    else:
        rules = [
            "ip6tables -w -F",
            "ip6tables -w -X",
            "ip6tables -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
        # Iterate over ports and add rule
        for protocol in ['TCP', 'UDP']:
            for port in firewall['ipv6'][protocol]:
                rules.append("ip6tables -w -A INPUT -p %s --dport %s -j ACCEPT"
                             % (protocol, process.quote(str(port))))
        rules += [
            "ip6tables -w -A INPUT -i lo -j ACCEPT",
            "ip6tables -w -A INPUT -p icmpv6 -j ACCEPT",
            "ip6tables -w -P INPUT DROP",
        ]

        # Execute each rule
        if process.run_commands(rules, callback=_on_rule_command_error):
            errors = True
        reloaded = True

    if not reloaded:
        raise MoulinetteError(errno.ESRCH, m18n.n('firewall_reload_failed'))

    hook_callback('post_iptable_rules',
                  args=[upnp, os.path.exists("/proc/net/if_inet6")])

    if upnp:
        # Refresh port forwarding with UPnP
        firewall_upnp(no_refresh=False)

    # TODO: Use service_restart
    os.system("service fail2ban restart")

    if errors:
        logger.warning(m18n.n('firewall_rules_cmd_failed'))
    else:
        logger.success(m18n.n('firewall_reloaded'))
    return firewall_list()


def firewall_upnp(action='status', no_refresh=False):
    """
    Manage port forwarding using UPnP

    Note: 'reload' action is deprecated and will be removed in the near
    future. You should use 'status' instead - which retrieve UPnP status
    and automatically refresh port forwarding if 'no_refresh' is False.

    Keyword argument:
        action -- Action to perform
        no_refresh -- Do not refresh port forwarding

    """
    firewall = firewall_list(raw=True)
    enabled = firewall['uPnP']['enabled']

    # Compatibility with previous version
    if action == 'reload':
        logger.info("'reload' action is deprecated and will be removed")
        try:
            # Remove old cron job
            os.remove('/etc/cron.d/yunohost-firewall')
        except:
            pass
        action = 'status'
        no_refresh = False

    if action == 'status' and no_refresh:
        # Only return current state
        return {'enabled': enabled}
    elif action == 'enable' or (enabled and action == 'status'):
        # Add cron job
        with open(UPNP_CRON_JOB, 'w+') as f:
            f.write('*/50 * * * * root '
                    '/usr/bin/yunohost firewall upnp status >>/dev/null\n')
        # Open port 1900 to receive discovery message
        if 1900 not in firewall['ipv4']['UDP']:
            firewall_allow('UDP', 1900, no_upnp=True, no_reload=True)
            if not enabled:
                firewall_reload(skip_upnp=True)
        enabled = True
    elif action == 'disable' or (not enabled and action == 'status'):
        try:
            # Remove cron job
            os.remove(UPNP_CRON_JOB)
        except:
            pass
        enabled = False
        if action == 'status':
            no_refresh = True
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('action_invalid', action=action))

    # Refresh port mapping using UPnP
    if not no_refresh:
        upnpc = miniupnpc.UPnP()
        upnpc.discoverdelay = 3000

        # Discover UPnP device(s)
        logger.debug('discovering UPnP devices...')
        nb_dev = upnpc.discover()
        logger.debug('found %d UPnP device(s)', int(nb_dev))
        if nb_dev < 1:
            logger.error(m18n.n('upnp_dev_not_found'))
            enabled = False
        else:
            try:
                # Select UPnP device
                upnpc.selectigd()
            except:
                logger.info('unable to select UPnP device', exc_info=1)
                enabled = False
            else:
                # Iterate over ports
                for protocol in ['TCP', 'UDP']:
                    for port in firewall['uPnP'][protocol]:
                        # Clean the mapping of this port
                        if upnpc.getspecificportmapping(port, protocol):
                            try:
                                upnpc.deleteportmapping(port, protocol)
                            except:
                                pass
                        if not enabled:
                            continue
                        try:
                            # Add new port mapping
                            upnpc.addportmapping(port, protocol, upnpc.lanaddr,
                                port, 'yunohost firewall: port %d' % port, '')
                        except:
                            logger.info('unable to add port %d using UPnP',
                                        port, exc_info=1)
                            enabled = False

    if enabled != firewall['uPnP']['enabled']:
        firewall = firewall_list(raw=True)
        firewall['uPnP']['enabled'] = enabled

        # Make a backup and update firewall file
        os.system("cp {0} {0}.old".format(FIREWALL_FILE))
        with open(FIREWALL_FILE, 'w') as f:
            yaml.safe_dump(firewall, f, default_flow_style=False)

        if not no_refresh:
            # Display success message if needed
            if action == 'enable' and enabled:
                logger.success(m18n.n('upnp_enabled'))
            elif action == 'disable' and not enabled:
                logger.success(m18n.n('upnp_disabled'))
            # Make sure to disable UPnP
            elif action != 'disable' and not enabled:
                firewall_upnp('disable', no_refresh=True)

    if not enabled and (action == 'enable' or 1900 in firewall['ipv4']['UDP']):
        # Close unused port 1900
        firewall_disallow('UDP', 1900, no_reload=True)
        if not no_refresh:
            firewall_reload(skip_upnp=True)

    if action == 'enable' and not enabled:
        raise MoulinetteError(errno.ENXIO, m18n.n('upnp_port_open_failed'))
    return {'enabled': enabled}


def firewall_stop():
    """
    Stop iptables and ip6tables


    """

    if os.system("iptables -w -P INPUT ACCEPT") != 0:
        raise MoulinetteError(errno.ESRCH, m18n.n('iptables_unavailable'))

    os.system("iptables -w -F")
    os.system("iptables -w -X")

    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")

    if os.path.exists(UPNP_CRON_JOB):
        firewall_upnp('disable')


def _get_ssh_port(default=22):
    """Return the SSH port to use

    Retrieve the SSH port from the sshd_config file or used the default
    one if it's not defined.
    """
    from moulinette.utils.text import searchf
    try:
        m = searchf(r'^Port[ \t]+([0-9]+)$',
                    '/etc/ssh/sshd_config', count=-1)
        if m:
            return int(m)
    except:
        pass
    return default


def _update_firewall_file(rules):
    """Make a backup and write new rules to firewall file"""
    os.system("cp {0} {0}.old".format(FIREWALL_FILE))
    with open(FIREWALL_FILE, 'w') as f:
        yaml.safe_dump(rules, f, default_flow_style=False)


def _on_rule_command_error(returncode, cmd, output):
    """Callback for rules commands error"""
    # Log error and continue commands execution
    logger.info('"%s" returned non-zero exit status %d:\n%s',
                cmd, returncode, prependlines(output.rstrip(), '> '))
    return True
