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

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

""" Search the ssh port in ssh config file
    If we don't find the ssh port we define 22"""

try:
  with open('/etc/ssh/sshd_config') as ssh_config_file:
    for line in ssh_config_file:
      line0 = line.split(" ")[0]

      if line0 == 'Port':
        ssh_port = line.split(' ')[1]
        ssh_port = ssh_port.rstrip('\n\r')

  ssh_config_file.close()

  if ssh_port == '':
    ssh_port = '22'

except:
  ssh_port = '22'

ssh_port = int(ssh_port)
firewall_file = '/etc/yunohost/firewall.yml'
upnp_cron_job = '/etc/cron.d/yunohost-firewall-upnp'

logger = getActionLogger('yunohost.firewall')


def firewall_allow(port=None, protocol=['TCP'], ipv6=False, no_upnp=False):
    """
    Allow connection port/protocol

    Keyword argument:
        port -- Port to open
        protocol -- Protocol associated with port
        ipv6 -- ipv6
        no_upnp -- Do not request for uPnP

    """
    port = int(port)
    ipv  = "ipv4"
    if isinstance(protocol, list):
        protocols = protocol
    else:
        protocols = [protocol]
    protocol  = protocols[0]

    firewall = firewall_list(raw=True)

    upnp = not no_upnp and firewall['uPnP']['enabled']

    if ipv6:
        ipv = "ipv6"

    if protocol == "Both":
        protocols = ['UDP', 'TCP']

    for protocol in protocols:
        if upnp and port not in firewall['uPnP'][protocol]:
            firewall['uPnP'][protocol].append(port)
        if port not in firewall[ipv][protocol]:
            firewall[ipv][protocol].append(port)
        else:
            msignals.display(m18n.n('port_already_opened', port), 'warning')

    with open(firewall_file, 'w') as f:
        yaml.safe_dump(firewall, f, default_flow_style=False)

    return firewall_reload()


def firewall_disallow(port=None, protocol=['TCP'], ipv6=False):
    """
    Allow connection port/protocol

    Keyword argument:
        port -- Port to open
        protocol -- Protocol associated with port
        ipv6 -- ipv6

    """
    port = int(port)
    ipv  = "ipv4"
    if isinstance(protocol, list):
        protocols = protocol
    else:
        protocols = [protocol]
    protocol  = protocols[0]

    firewall = firewall_list(raw=True)

    if ipv6:
        ipv = "ipv6"

    if protocol == "Both":
        protocols = ['UDP', 'TCP']

    for protocol in protocols:
        if port in firewall['uPnP'][protocol]:
            firewall['uPnP'][protocol].remove(port)
        if port in firewall[ipv][protocol]:
            firewall[ipv][protocol].remove(port)
        else:
            msignals.display(m18n.n('port_already_closed', port), 'warning')

    with open(firewall_file, 'w') as f:
        yaml.safe_dump(firewall, f, default_flow_style=False)

    return firewall_reload()


def firewall_list(raw=False):
    """
    List all firewall rules

    Keyword argument:
        raw -- Return the complete YAML dict

    """
    with open(firewall_file) as f:
        firewall = yaml.load(f)

    if raw:
        return firewall
    else:
        return { "openned_ports": firewall['ipv4']['TCP'] }


def firewall_reload():
    """
    Reload all firewall rules


    """
    from yunohost.hook import hook_callback

    firewall = firewall_list(raw=True)
    upnp = firewall['uPnP']['enabled']

    # IPv4
    if os.system("iptables -P INPUT ACCEPT") != 0:
        raise MoulinetteError(errno.ESRCH, m18n.n('iptables_unavailable'))
    if upnp:
        firewall_upnp(no_refresh=False)

    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT")

    if ssh_port not in firewall['ipv4']['TCP']:
        firewall_allow(ssh_port)

    # Loop
    for protocol in ['TCP', 'UDP']:
        for port in firewall['ipv4'][protocol]:
            os.system("iptables -A INPUT -p %s --dport %d -j ACCEPT" % (protocol, port))

    hook_callback('post_iptable_rules',
                  args=[upnp, os.path.exists("/proc/net/if_inet6")])

    os.system("iptables -A INPUT -i lo -j ACCEPT")
    os.system("iptables -A INPUT -p icmp -j ACCEPT")
    os.system("iptables -P INPUT DROP")

    # IPv6
    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")
        os.system("ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT")

        if ssh_port not in firewall['ipv6']['TCP']:
            firewall_allow(ssh_port, ipv6=True)

        # Loop v6
        for protocol in ['TCP', 'UDP']:
            for port in firewall['ipv6'][protocol]:
                os.system("ip6tables -A INPUT -p %s --dport %d -j ACCEPT" % (protocol, port))

        os.system("ip6tables -A INPUT -i lo -j ACCEPT")
        os.system("ip6tables -A INPUT -p icmpv6 -j ACCEPT")
        os.system("ip6tables -P INPUT DROP")

    os.system("service fail2ban restart")
    msignals.display(m18n.n('firewall_reloaded'), 'success')

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
        logger.warning("'reload' action is deprecated and will be removed")
        try:
            # Remove old cron job
            os.remove('/etc/cron.d/yunohost-firewall')
        except: pass
        action = 'status'
        no_refresh = False

    if action == 'status' and no_refresh:
        # Only return current state
        return { 'enabled': enabled }
    elif action == 'enable' or (enabled and action == 'status'):
        # Add cron job
        with open(upnp_cron_job, 'w+') as f:
            f.write('*/50 * * * * root '
                    '/usr/bin/yunohost firewall upnp status >>/dev/null\n')
        enabled = True
    elif action == 'disable' or (not enabled and action == 'status'):
        try:
            # Remove cron job
            os.remove(upnp_cron_job)
        except: pass
        enabled = False
        if action == 'status':
            no_refresh = True
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('action_invalid', action))

    # Refresh port mapping using UPnP
    if not no_refresh:
        upnpc = miniupnpc.UPnP()
        upnpc.discoverdelay = 3000

        # Discover UPnP device(s)
        logger.debug('discovering UPnP devices...')
        nb_dev = upnpc.discover()
        logger.debug('found %d UPnP device(s)', int(nb_dev))
        if nb_dev < 1:
            msignals.display(m18n.n('upnp_dev_not_found'), 'error')
            enabled = False
        else:
            try:
                # Select UPnP device
                upnpc.selectigd()
            except:
                logger.exception('unable to select UPnP device')
                enabled = False
            else:
                # Iterate over ports
                for protocol in ['TCP', 'UDP']:
                    for port in firewall['uPnP'][protocol]:
                        # Clean the mapping of this port
                        if upnpc.getspecificportmapping(port, protocol):
                            try:
                                upnpc.deleteportmapping(port, protocol)
                            except: pass
                        if not enabled:
                            continue
                        try:
                            # Add new port mapping
                            upnpc.addportmapping(port, protocol, upnpc.lanaddr,
                                port, 'yunohost firewall: port %d' % port, '')
                        except:
                            logger.exception('unable to add port %d using UPnP',
                                             port)
                            enabled = False

    if enabled != firewall['uPnP']['enabled']:
        firewall['uPnP']['enabled'] = enabled

        # Make a backup and update firewall file
        os.system("cp {0} {0}.old".format(firewall_file))
        with open(firewall_file, 'w') as f:
            yaml.safe_dump(firewall, f, default_flow_style=False)

        if not no_refresh:
            # Display success message if needed
            if action == 'enable' and enabled:
                msignals.display(m18n.n('upnp_enabled'), 'success')
            elif action == 'disable' and not enabled:
                msignals.display(m18n.n('upnp_disabled'), 'success')
            # Make sure to disable UPnP
            elif action != 'disable' and not enabled:
                firewall_upnp('disable', no_refresh=True)

    if action == 'enable' and not enabled:
        raise MoulinetteError(errno.ENXIO, m18n.n('upnp_port_open_failed'))
    return { 'enabled': enabled }


def firewall_stop():
    """
    Stop iptables and ip6tables


    """

    if os.system("iptables -P INPUT ACCEPT") != 0:
        raise MoulinetteError(errno.ESRCH, m18n.n('iptables_unavailable'))

    os.system("iptables -F")
    os.system("iptables -X")

    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")

    if os.path.exists(upnp_cron_job):
        firewall_upnp('disable')
