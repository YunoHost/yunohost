#!/usr/bin/env python

import os
import requests

from yunohost.diagnosis import Diagnoser
from yunohost.utils.error import YunohostError
from yunohost.service import _get_services

class PortsDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = ["ip"]

    def run(self):

        # This dict is something like :
        #   {   80: "nginx",
        #       25: "postfix",
        #       443: "nginx"
        #       ... }
        ports = {}
        services = _get_services()
        for service, infos in services.items():
            for port in infos.get("needs_exposed_ports", []):
                ports[port] = service

        try:
            r = requests.post('https://diagnosis.yunohost.org/check-ports', json={'ports': ports.keys()}, timeout=30)
            if r.status_code not in [200, 400, 418]:
                raise Exception("Bad response from the server https://diagnosis.yunohost.org/check-ports : %s - %s" % (str(r.status_code), r.content))
            r = r.json()
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

        for port, service in sorted(ports.items()):
            category = services[service].get("category", "[?]")
            if r["ports"].get(str(port), None) is not True:
                yield dict(meta={"port": port, "needed_by": service},
                           status="ERROR",
                           summary=("diagnosis_ports_unreachable", {"port": port}),
                           details=[("diagnosis_ports_needed_by", (service, category)), ("diagnosis_ports_forwarding_tip", ())])
            else:
                yield dict(meta={"port": port, "needed_by": service},
                           status="SUCCESS",
                           summary=("diagnosis_ports_ok", {"port": port}),
                           details=[("diagnosis_ports_needed_by", (service, category))])


def main(args, env, loggers):
    return PortsDiagnoser(args, env, loggers).diagnose()
