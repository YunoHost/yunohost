#!/usr/bin/env python

import re
import os
import random

from moulinette.utils.network import download_text
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file

from yunohost.diagnosis import Diagnoser
from yunohost.utils.network import get_network_interfaces


class IPDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies = []

    def run(self):

        # ############################################################ #
        # PING : Check that we can ping outside at least in ipv4 or v6 #
        # ############################################################ #

        can_ping_ipv4 = self.can_ping_outside(4)
        can_ping_ipv6 = self.can_ping_outside(6)

        if not can_ping_ipv4 and not can_ping_ipv6:
            yield dict(
                meta={"test": "ping"},
                status="ERROR",
                summary="diagnosis_ip_not_connected_at_all",
            )
            # Not much else we can do if there's no internet at all
            return

        # ###################################################### #
        # DNS RESOLUTION : Check that we can resolve domain name #
        # (later needed to talk to ip. and ip6.yunohost.org)     #
        # ###################################################### #

        can_resolve_dns = self.can_resolve_dns()

        # In every case, we can check that resolvconf seems to be okay
        # (symlink managed by resolvconf service + pointing to dnsmasq)
        good_resolvconf = self.good_resolvconf()

        # If we can't resolve domain names at all, that's a pretty big issue ...
        # If it turns out that at the same time, resolvconf is bad, that's probably
        # the cause of this, so we use a different message in that case
        if not can_resolve_dns:
            yield dict(
                meta={"test": "dnsresolv"},
                status="ERROR",
                summary="diagnosis_ip_broken_dnsresolution"
                if good_resolvconf
                else "diagnosis_ip_broken_resolvconf",
            )
            return
        # Otherwise, if the resolv conf is bad but we were able to resolve domain name,
        # still warn that we're using a weird resolv conf ...
        elif not good_resolvconf:
            yield dict(
                meta={"test": "dnsresolv"},
                status="WARNING",
                summary="diagnosis_ip_weird_resolvconf",
                details=["diagnosis_ip_weird_resolvconf_details"],
            )
        else:
            yield dict(
                meta={"test": "dnsresolv"},
                status="SUCCESS",
                summary="diagnosis_ip_dnsresolution_working",
            )

        # ##################################################### #
        # IP DIAGNOSIS : Check that we're actually able to talk #
        # to a web server to fetch current IPv4 and v6          #
        # ##################################################### #

        ipv4 = self.get_public_ip(4) if can_ping_ipv4 else None
        ipv6 = self.get_public_ip(6) if can_ping_ipv6 else None

        network_interfaces = get_network_interfaces()

        def get_local_ip(version):
            local_ip = {
                iface: addr[version].split("/")[0]
                for iface, addr in network_interfaces.items()
                if version in addr
            }
            if not local_ip:
                return None
            elif len(local_ip):
                return next(iter(local_ip.values()))
            else:
                return local_ip

        yield dict(
            meta={"test": "ipv4"},
            data={"global": ipv4, "local": get_local_ip("ipv4")},
            status="SUCCESS" if ipv4 else "ERROR",
            summary="diagnosis_ip_connected_ipv4" if ipv4 else "diagnosis_ip_no_ipv4",
            details=["diagnosis_ip_global", "diagnosis_ip_local"] if ipv4 else None,
        )

        yield dict(
            meta={"test": "ipv6"},
            data={"global": ipv6, "local": get_local_ip("ipv6")},
            status="SUCCESS" if ipv6 else "WARNING",
            summary="diagnosis_ip_connected_ipv6" if ipv6 else "diagnosis_ip_no_ipv6",
            details=["diagnosis_ip_global", "diagnosis_ip_local"]
            if ipv6
            else ["diagnosis_ip_no_ipv6_tip"],
        )

        # TODO / FIXME : add some attempt to detect ISP (using whois ?) ?

    def can_ping_outside(self, protocol=4):

        assert protocol in [
            4,
            6,
        ], "Invalid protocol version, it should be either 4 or 6 and was '%s'" % repr(
            protocol
        )

        # We can know that ipv6 is not available directly if this file does not exists
        if protocol == 6 and not os.path.exists("/proc/net/if_inet6"):
            return False

        # If we are indeed connected in ipv4 or ipv6, we should find a default route
        routes = check_output("ip -%s route show table all" % protocol).split("\n")

        def is_default_route(r):
            # Typically the default route starts with "default"
            # But of course IPv6 is more complex ... e.g. on internet cube there's
            # no default route but a /3 which acts as a default-like route...
            # e.g. 2000:/3 dev tun0 ...
            return r.startswith("default") or (
                ":" in r and re.match(r".*/[0-3]$", r.split()[0])
            )

        if not any(is_default_route(r) for r in routes):
            self.logger_debug(
                "No default route for IPv%s, so assuming there's no IP address for that version"
                % protocol
            )
            return None

        # We use the resolver file as a list of well-known, trustable (ie not google ;)) IPs that we can ping
        resolver_file = (
            "/usr/share/yunohost/templates/dnsmasq/plain/resolv.dnsmasq.conf"
        )
        resolvers = [
            r.split(" ")[1]
            for r in read_file(resolver_file).split("\n")
            if r.startswith("nameserver")
        ]

        if protocol == 4:
            resolvers = [r for r in resolvers if ":" not in r]
        if protocol == 6:
            resolvers = [r for r in resolvers if ":" in r]

        assert (
            resolvers != []
        ), "Uhoh, need at least one IPv{} DNS resolver in {} ...".format(
            protocol,
            resolver_file,
        )

        # So let's try to ping the first 4~5 resolvers (shuffled)
        # If we succesfully ping any of them, we conclude that we are indeed connected
        def ping(protocol, target):
            return (
                os.system(
                    "ping%s -c1 -W 3 %s >/dev/null 2>/dev/null"
                    % ("" if protocol == 4 else "6", target)
                )
                == 0
            )

        random.shuffle(resolvers)
        return any(ping(protocol, resolver) for resolver in resolvers[:5])

    def can_resolve_dns(self):
        return os.system("dig +short ip.yunohost.org >/dev/null 2>/dev/null") == 0

    def good_resolvconf(self):
        content = read_file("/etc/resolv.conf").strip().split("\n")
        # Ignore comments and empty lines
        content = [
            line.strip()
            for line in content
            if line.strip()
            and not line.strip().startswith("#")
            and not line.strip().startswith("search")
        ]
        # We should only find a "nameserver 127.0.0.1"
        return len(content) == 1 and content[0].split() == ["nameserver", "127.0.0.1"]

    def get_public_ip(self, protocol=4):

        # FIXME - TODO : here we assume that DNS resolution for ip.yunohost.org is working
        # but if we want to be able to diagnose DNS resolution issues independently from
        # internet connectivity, we gotta rely on fixed IPs first....

        assert protocol in [
            4,
            6,
        ], "Invalid protocol version, it should be either 4 or 6 and was '%s'" % repr(
            protocol
        )

        url = "https://ip%s.yunohost.org" % ("6" if protocol == 6 else "")

        try:
            return download_text(url, timeout=30).strip()
        except Exception as e:
            self.logger_debug(
                "Could not get public IPv{} : {}".format(str(protocol), str(e))
            )
            return None


def main(args, env, loggers):
    return IPDiagnoser(args, env, loggers).diagnose()
