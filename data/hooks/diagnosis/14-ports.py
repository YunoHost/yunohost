#!/usr/bin/env python

import os

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
            r = Diagnoser.remote_diagnosis('check-ports',
                                           data={'ports': ports.keys()},
                                           ipversion=4)
            results = r["ports"]
        except Exception as e:
            raise YunohostError("diagnosis_ports_could_not_diagnose", error=e)

        for port, service in sorted(ports.items()):
            category = services[service].get("category", "[?]")
            if results.get(str(port), None) is not True:
                yield dict(meta={"port": str(port)},
                           data={"service": service, "category": category},
                           status="ERROR",
                           summary="diagnosis_ports_unreachable",
                           details=["diagnosis_ports_needed_by", "diagnosis_ports_forwarding_tip"])
            else:
                yield dict(meta={"port": str(port)},
                           data={"service": service, "category": category},
                           status="SUCCESS",
                           summary="diagnosis_ports_ok",
                           details=["diagnosis_ports_needed_by"])


def main(args, env, loggers):
    return PortsDiagnoser(args, env, loggers).diagnose()
