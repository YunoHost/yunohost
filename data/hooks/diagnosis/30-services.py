#!/usr/bin/env python

import os

from yunohost.diagnosis import Diagnoser
from yunohost.service import service_status

# TODO : all these are arbitrary, should be collectively validated
services_ignored = {"glances"}
services_critical = {"dnsmasq", "fail2ban", "yunohost-firewall", "nginx", "slapd", "ssh"}
# TODO / FIXME : we should do something about this postfix thing
# The nominal value is to be "exited" ... some daemon is actually running
# in a different thread that the thing started by systemd, which is fine
# but somehow sometimes it gets killed and there's no easy way to detect it
# Just randomly restarting it will fix ths issue. We should find some trick
# to identify the PID of the process and check it's still up or idk
services_expected_to_be_exited = {"postfix", "yunohost-firewall"}

class ServicesDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300

    def validate_args(self, args):
        # TODO / FIXME Ugh do we really need this arg system
        return {}

    def run(self):

        all_result = service_status()

        for service, result in all_result.items():

            if service in services_ignored:
                continue

            item = dict(meta={"service": service})
            expected_status = "running" if service not in services_expected_to_be_exited else "exited"

            # TODO / FIXME : might also want to check that services are enabled

            if result["active"] != "active" or result["status"] != expected_status:
                item["status"] = "WARNING" if service not in services_critical else "ERROR"
                item["summary"] = ("diagnosis_services_bad_status", {"service": service, "status": result["active"] + "/" + result["status"]})

                # TODO : could try to append the tail of the service log to the "details" key ...
            else:
                item["status"] = "SUCCESS"
                item["summary"] = ("diagnosis_services_good_status", {"service": service, "status": result["active"] + "/" + result["status"]})

            yield item

def main(args, env, loggers):
    return ServicesDiagnoser(args, env, loggers).diagnose()
