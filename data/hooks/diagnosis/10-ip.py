#!/usr/bin/env python

import os
import random

from moulinette.utils.network import download_text
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file

from yunohost.diagnosis import Diagnoser


class IPDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 60
    dependencies = []

    def run(self):

        # ############################################################ #
        # PING : Check that we can ping outside at least in ipv4 or v6 #
        # ############################################################ #

        can_ping_ipv4 = self.can_ping_outside(4)
        can_ping_ipv6 = self.can_ping_outside(6)

        if not can_ping_ipv4 and not can_ping_ipv6:
            yield dict(meta={"test": "ping"},
                       status="ERROR",
                       summary=("diagnosis_ip_not_connected_at_all", {}))
            # Not much else we can do if there's no internet at all
            return

        # ###################################################### #
        # DNS RESOLUTION : Check that we can resolve domain name #
        # (later needed to talk to ip. and ip6.yunohost.org)     #
        # ###################################################### #

        can_resolve_dns = self.can_resolve_dns()

        # In every case, we can check that resolvconf seems to be okay
        # (symlink managed by resolvconf service + pointing to dnsmasq)
        good_resolvconf = self.resolvconf_is_symlink() and self.resolvconf_points_to_localhost()

        # If we can't resolve domain names at all, that's a pretty big issue ...
        # If it turns out that at the same time, resolvconf is bad, that's probably
        # the cause of this, so we use a different message in that case
        if not can_resolve_dns:
            yield dict(meta={"test": "dnsresolv"},
                       status="ERROR",
                       summary=("diagnosis_ip_broken_dnsresolution", {}) if good_resolvconf
                          else ("diagnosis_ip_broken_resolvconf", {}))
            return
        # Otherwise, if the resolv conf is bad but we were able to resolve domain name,
        # still warn that we're using a weird resolv conf ...
        elif not good_resolvconf:
            yield dict(meta={"test": "dnsresolv"},
                       status="WARNING",
                       summary=("diagnosis_ip_weird_resolvconf", {}),
                       details=[("diagnosis_ip_weird_resolvconf_details", ())])
        else:
            yield dict(meta={"test": "dnsresolv"},
                       status="SUCCESS",
                       summary=("diagnosis_ip_dnsresolution_working", {}))

        # ##################################################### #
        # IP DIAGNOSIS : Check that we're actually able to talk #
        # to a web server to fetch current IPv4 and v6          #
        # ##################################################### #

        ipv4 = self.get_public_ip(4) if can_ping_ipv4 else None
        ipv6 = self.get_public_ip(6) if can_ping_ipv6 else None

        yield dict(meta={"test": "ip", "version": 4},
                   data=ipv4,
                   status="SUCCESS" if ipv4 else "ERROR",
                   summary=("diagnosis_ip_connected_ipv4", {}) if ipv4
                      else ("diagnosis_ip_no_ipv4", {}))

        yield dict(meta={"test": "ip", "version": 6},
                   data=ipv6,
                   status="SUCCESS" if ipv6 else "WARNING",
                   summary=("diagnosis_ip_connected_ipv6", {}) if ipv6
                      else ("diagnosis_ip_no_ipv6", {}))

        # TODO / FIXME : add some attempt to detect ISP (using whois ?) ?

    def can_ping_outside(self, protocol=4):

        assert protocol in [4, 6], "Invalid protocol version, it should be either 4 or 6 and was '%s'" % repr(protocol)

        # We can know that ipv6 is not available directly if this file does not exists
        if protocol == 6 and not os.path.exists("/proc/net/if_inet6"):
            return False

        # If we are indeed connected in ipv4 or ipv6, we should find a default route
        routes = check_output("ip -%s route" % protocol).split("\n")
        if not [r for r in routes if r.startswith("default")]:
            return False

        # We use the resolver file as a list of well-known, trustable (ie not google ;)) IPs that we can ping
        resolver_file = "/usr/share/yunohost/templates/dnsmasq/plain/resolv.dnsmasq.conf"
        resolvers = [r.split(" ")[1] for r in read_file(resolver_file).split("\n") if r.startswith("nameserver")]

        if protocol == 4:
            resolvers = [r for r in resolvers if ":" not in r]
        if protocol == 6:
            resolvers = [r for r in resolvers if ":" in r]

        assert resolvers != [], "Uhoh, need at least one IPv%s DNS resolver in %s ..." % (protocol, resolver_file)

        # So let's try to ping the first 4~5 resolvers (shuffled)
        # If we succesfully ping any of them, we conclude that we are indeed connected
        def ping(protocol, target):
            return os.system("ping%s -c1 -W 3 %s >/dev/null 2>/dev/null" % ("" if protocol == 4 else "6", target)) == 0

        random.shuffle(resolvers)
        return any(ping(protocol, resolver) for resolver in resolvers[:5])

    def can_resolve_dns(self):
        return os.system("dig +short ip.yunohost.org >/dev/null 2>/dev/null") == 0

    def resolvconf_is_symlink(self):
        return os.path.realpath("/etc/resolv.conf") == "/run/resolvconf/resolv.conf"

    def resolvconf_points_to_localhost(self):
        file_ = "/etc/resolv.conf"
        resolvers = [r.split(" ")[1] for r in read_file(file_).split("\n") if r.startswith("nameserver")]
        return resolvers == ["127.0.0.1"]

    def get_public_ip(self, protocol=4):

        # FIXME - TODO : here we assume that DNS resolution for ip.yunohost.org is working
        # but if we want to be able to diagnose DNS resolution issues independently from
        # internet connectivity, we gotta rely on fixed IPs first....

        assert protocol in [4, 6], "Invalid protocol version, it should be either 4 or 6 and was '%s'" % repr(protocol)

        url = 'https://ip%s.yunohost.org' % ('6' if protocol == 6 else '')

        try:
            return download_text(url, timeout=30).strip()
        except Exception as e:
            self.logger_debug("Could not get public IPv%s : %s" % (str(protocol), str(e)))
            return None


def main(args, env, loggers):
    return IPDiagnoser(args, env, loggers).diagnose()
