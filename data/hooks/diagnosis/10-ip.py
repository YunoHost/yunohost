#!/usr/bin/env python

import os

from moulinette import m18n
from moulinette.utils.network import download_text
from yunohost.diagnosis import Diagnoser

class IPDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0]
    description = m18n.n("internet_connectivity")
    cache_duration = 60

    def validate_args(self, args):
        if "version" not in args.keys():
            return { "versions" : [4, 6] }
        else:
            if str(args["version"]) not in ["4", "6"]:
                raise MoulinetteError(1, "Invalid version, should be 4 or 6.")
            return { "versions" : [int(args["version"])] }

    def run(self):

        versions = self.args["versions"]

        if 4 in versions:
            ipv4 = self.get_public_ip(4)
            yield dict(meta = {"version": "4"},
                       result = ipv4,
                       report = ("SUCCESS", m18n.n("diagnosis_network_connected_ipv4")) if ipv4 \
                           else ("ERROR",   m18n.n("diagnosis_network_no_ipv4")))
       
        if 6 in versions:
            ipv6 = self.get_public_ip(6)
            yield dict(meta = {"version": "6"},
                       result = ipv6,
                       report = ("SUCCESS", m18n.n("diagnosis_network_connected_ipv6")) if ipv6 \
                           else ("WARNING", m18n.n("diagnosis_network_no_ipv6")))


    def get_public_ip(self, protocol=4):

        if protocol == 4:
            url = 'https://ip.yunohost.org'
        elif protocol == 6:
            url = 'https://ip6.yunohost.org'
        else:
            raise ValueError("invalid protocol version")

        try:
            return download_text(url, timeout=30).strip()
        except Exception as e:
            self.logger_debug("Could not get public IPv%s : %s" % (str(protocol), str(e)))
            return None


def main(args, env, loggers):

    return IPDiagnoser(args, env, loggers).report()

