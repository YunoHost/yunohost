#!/usr/bin/env python

import os
import random

from moulinette import m18n
from moulinette.utils.network import download_text
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file

from yunohost.diagnosis import Diagnoser

class IPDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 60

    def validate_args(self, args):
        if "version" not in args.keys():
            return { "versions" : [4, 6] }
        else:
            assert str(args["version"]) in ["4", "6"], "Invalid version, should be 4 or 6."
            return { "versions" : [int(args["version"])] }

    def run(self):

        versions = self.args["versions"]

        if 4 in versions:

            if not self.can_ping_outside(4):
                ipv4 = None
            else:
                ipv4 = self.get_public_ip(4)

            yield dict(meta = {"version": 4},
                       data = ipv4,
                       status = "SUCCESS" if ipv4 else "ERROR",
                       summary = ("diagnosis_network_connected_ipv4", {}) if ipv4 \
                            else ("diagnosis_network_no_ipv4", {}))

        if 6 in versions:

            if not self.can_ping_outside(4):
                ipv6 = None
            else:
                ipv6 = self.get_public_ip(6)

            yield dict(meta = {"version": 6},
                       data = ipv6,
                       status = "SUCCESS" if ipv6 else "WARNING",
                       summary = ("diagnosis_network_connected_ipv6", {}) if ipv6 \
                            else ("diagnosis_network_no_ipv6", {}))


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
            return os.system("ping -c1 -%s -W 3 %s >/dev/null 2>/dev/null" % (protocol, target)) == 0

        random.shuffle(resolvers)
        return any(ping(protocol, resolver) for resolver in resolvers[:5])

    def get_public_ip(self, protocol=4):

        # FIXME - TODO : here we assume that DNS resolution for ip.yunohost.org is working
        # but if we want to be able to diagnose DNS resolution issues independently from
        # internet connectivity, we gotta rely on fixed IPs first....

        if protocol == 4:
            url = 'https://ip.yunohost.org'
        elif protocol == 6:
            url = 'https://ip6.yunohost.org'
        else:
            raise ValueError("invalid protocol version, it should be either 4 or 6 and was '%s'" % repr(protocol))

        try:
            return download_text(url, timeout=30).strip()
        except Exception as e:
            self.logger_debug("Could not get public IPv%s : %s" % (str(protocol), str(e)))
            return None


def main(args, env, loggers):
    return IPDiagnoser(args, env, loggers).diagnose()

