#!/usr/bin/env python

import os
from typing import List

from yunohost.diagnosis import Diagnoser
from yunohost.service import service_status


class MyDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies: List[str] = []

    def run(self):

        all_result = service_status()

        for service, result in sorted(all_result.items()):

            item = dict(
                meta={"service": service},
                data={
                    "status": result["status"],
                    "configuration": result["configuration"],
                },
            )

            if result["status"] != "running":
                item["status"] = "ERROR" if result["status"] != "unknown" else "WARNING"
                item["summary"] = "diagnosis_services_bad_status"
                item["details"] = ["diagnosis_services_bad_status_tip"]

            elif result["configuration"] == "broken":
                item["status"] = "WARNING"
                item["summary"] = "diagnosis_services_conf_broken"
                item["details"] = result["configuration-details"]

            else:
                item["status"] = "SUCCESS"
                item["summary"] = "diagnosis_services_running"

            yield item
