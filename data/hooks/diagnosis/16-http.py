#!/usr/bin/env python

import os
import random
import requests

from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list
from yunohost.utils.error import YunohostError


class HttpDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = ["ip"]

    def run(self):

        nonce_digits = "0123456789abcedf"

        all_domains = domain_list()["domains"]
        for domain in all_domains:

            nonce = ''.join(random.choice(nonce_digits) for i in range(16))
            os.system("rm -rf /tmp/.well-known/ynh-diagnosis/")
            os.system("mkdir -p /tmp/.well-known/ynh-diagnosis/")
            os.system("touch /tmp/.well-known/ynh-diagnosis/%s" % nonce)

            try:
                r = requests.post('https://ynhdiagnoser.netlib.re/check-http', json={'domain': domain, "nonce": nonce}, timeout=30).json()
                if "status" not in r.keys():
                    raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
                elif r["status"] == "error" and ("code" not in r.keys() or r["code"] not in ["error_http_check_connection_error", "error_http_check_unknown_error"]):
                    if "content" in r.keys():
                        raise Exception(r["content"])
                    else:
                        raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
            except Exception as e:
                raise YunohostError("diagnosis_http_could_not_diagnose", error=e)

            if r["status"] == "ok":
                yield dict(meta={"domain": domain},
                           status="SUCCESS",
                           summary=("diagnosis_http_ok", {"domain": domain}))
            else:
                yield dict(meta={"domain": domain},
                           status="ERROR",
                           summary=("diagnosis_http_unreachable", {"domain": domain}))


def main(args, env, loggers):
    return HttpDiagnoser(args, env, loggers).diagnose()
