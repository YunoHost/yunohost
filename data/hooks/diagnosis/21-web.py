#!/usr/bin/env python

import os
import random
import requests

from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list
from yunohost.utils.error import YunohostError


class WebDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = ["ip"]

    def run(self):

        nonce_digits = "0123456789abcedf"

        at_least_one_domain_ok = False
        all_domains = domain_list()["domains"]
        for domain in all_domains:

            # If the diagnosis location ain't defined, can't do diagnosis,
            # probably because nginx conf manually modified...
            nginx_conf = "/etc/nginx/conf.d/%s.conf" % domain
            if os.system("grep -q '^.*location .*/.well-known/ynh-diagnosis/' %s" % nginx_conf) != 0:
                yield dict(meta={"domain": domain},
                           status="WARNING",
                           summary="diagnosis_http_nginx_conf_not_up_to_date",
                           details=["diagnosis_http_nginx_conf_not_up_to_date_details"])

            nonce = ''.join(random.choice(nonce_digits) for i in range(16))
            os.system("rm -rf /tmp/.well-known/ynh-diagnosis/")
            os.system("mkdir -p /tmp/.well-known/ynh-diagnosis/")
            os.system("touch /tmp/.well-known/ynh-diagnosis/%s" % nonce)

            try:
                r = requests.post('https://diagnosis.yunohost.org/check-http', json={'domain': domain, "nonce": nonce}, timeout=30)
                if r.status_code not in [200, 400, 418]:
                    raise Exception("Bad response from the server https://diagnosis.yunohost.org/check-http : %s - %s" % (str(r.status_code), r.content))
                r = r.json()
                if "status" not in r.keys():
                    raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
                elif r["status"] == "error" and ("code" not in r.keys() or not r["code"].startswith("error_http_check_")):
                    if "content" in r.keys():
                        raise Exception(r["content"])
                    else:
                        raise Exception("Bad syntax for response ? Raw json: %s" % str(r))
            except Exception as e:
                raise YunohostError("diagnosis_http_could_not_diagnose", error=e)

            if r["status"] == "ok":
                at_least_one_domain_ok = True
                yield dict(meta={"domain": domain},
                           status="SUCCESS",
                           summary="diagnosis_http_ok")
            else:
                detail = r["code"].replace("error_http_check", "diagnosis_http") if "code" in r else "diagnosis_http_unknown_error"
                yield dict(meta={"domain": domain},
                           status="ERROR",
                           summary="diagnosis_http_unreachable",
                           details=[detail])

        # If at least one domain is correctly exposed to the outside,
        # attempt to diagnose hairpinning situations. On network with
        # hairpinning issues, the server may be correctly exposed on the
        # outside, but from the outside, it will be as if the port forwarding
        # was not configured... Hence, calling for example
        # "curl --head the.global.ip" will simply timeout...
        if at_least_one_domain_ok:
            ipv4 = Diagnoser.get_cached_report_item("ip", {"test": "ipv4"})
            global_ipv4 = ipv4.get("data", {}).get("global", {})
            if global_ipv4:
                try:
                    requests.head("http://" + ipv4, timeout=5)
                except requests.exceptions.Timeout as e:
                    yield dict(meta={"test": "hairpinning"},
                               status="WARNING",
                               summary="diagnosis_http_hairpinning_issue",
                               details=["diagnosis_http_hairpinning_issue_details"])
                except:
                    # Well I dunno what to do if that's another exception
                    # type... That'll most probably *not* be an hairpinning
                    # issue but something else super weird ...
                    pass


def main(args, env, loggers):
    return WebDiagnoser(args, env, loggers).diagnose()
