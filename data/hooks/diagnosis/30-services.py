#!/usr/bin/env python

import os

from yunohost.diagnosis import Diagnoser
from yunohost.service import service_status

class ServicesDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies = []

    def run(self):

        all_result = service_status()

        for service, result in sorted(all_result.items()):

            item = dict(meta={"service": service})

            if result["status"] != "running":
                item["status"] = "ERROR"
                item["summary"] = ("diagnosis_services_bad_status", {"service": service, "status": result["status"]})
                item["details"] = [("diagnosis_services_bad_status_tip", (service,))]

            elif result["configuration"] == "broken":
                item["status"] = "WARNING"
                item["summary"] = ("diagnosis_services_conf_broken", {"service": service})
                item["details"] = [(d, tuple()) for d in result["configuration-details"]]

            else:
                item["status"] = "SUCCESS"
                item["summary"] = ("diagnosis_services_running", {"service": service, "status": result["status"]})

            yield item

def main(args, env, loggers):
    return ServicesDiagnoser(args, env, loggers).diagnose()
