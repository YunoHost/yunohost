#!/usr/bin/env python

import os
import requests

from yunohost.diagnosis import Diagnoser
from yunohost.utils.error import YunohostError


class PortsDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600

    def run(self):

        # FIXME / TODO : in the future, maybe we want to report different
        # things per port depending on how important they are
        # (e.g. XMPP sounds to me much less important than other ports)
        # Ideally, a port could be related to a service...
        # FIXME / TODO : for now this list of port is hardcoded, might want
        # to fetch this from the firewall.yml in /etc/yunohost/
        ports = [22, 25, 53, 80, 443, 587, 993, 5222, 5269]

        try:
            r = requests.post('https://ynhdiagnoser.netlib.re/check-ports', json={'ports': ports}, timeout=30).json()
            if "status" not in r.keys():
                raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
            elif r["status"] == "error":
                if "content" in r.keys():
                    raise Exception(r["content"])
                else:
                    raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
            elif r["status"] != "ok" or "ports" not in r.keys() or not isinstance(r["ports"], dict):
                raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
        except Exception as e:
            raise YunohostError("diagnosis_ports_could_not_diagnose", error=e)

        found_issues = False
        for port in ports:
            if r["ports"].get(str(port), None) is not True:
                found_issues = True
                yield dict(meta={"port": port},
                           status="ERROR",
                           summary=("diagnosis_ports_unreachable", {"port": port}))

        if not found_issues:
            yield dict(meta={},
                       status="SUCCESS",
                       summary=("diagnosis_ports_ok", {}))


def main(args, env, loggers):
    return PortsDiagnoser(args, env, loggers).diagnose()
