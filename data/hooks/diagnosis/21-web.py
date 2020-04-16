#!/usr/bin/env python

import os
import random
import requests

from moulinette.utils.filesystem import read_file

from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list
from yunohost.utils.error import YunohostError

DIAGNOSIS_SERVER = "diagnosis.yunohost.org"


class WebDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = ["ip"]

    def run(self):

        all_domains = domain_list()["domains"]
        domains_to_check = []
        for domain in all_domains:

            # If the diagnosis location ain't defined, can't do diagnosis,
            # probably because nginx conf manually modified...
            nginx_conf = "/etc/nginx/conf.d/%s.conf" % domain
            if ".well-known/ynh-diagnosis/" not in read_file(nginx_conf):
                yield dict(meta={"domain": domain},
                           status="WARNING",
                           summary="diagnosis_http_nginx_conf_not_up_to_date",
                           details=["diagnosis_http_nginx_conf_not_up_to_date_details"])
            else:
                domains_to_check.append(domain)

        self.nonce = ''.join(random.choice("0123456789abcedf") for i in range(16))
        os.system("rm -rf /tmp/.well-known/ynh-diagnosis/")
        os.system("mkdir -p /tmp/.well-known/ynh-diagnosis/")
        os.system("touch /tmp/.well-known/ynh-diagnosis/%s" % self.nonce)

        if not domains_to_check:
            return

        # To perform hairpinning test, we gotta make sure that port forwarding
        # is working and therefore we'll do it only if at least one ipv4 domain
        # works.
        self.do_hairpinning_test = False
        ipv4 = Diagnoser.get_cached_report("ip", item={"test": "ipv4"}) or {}
        if ipv4.get("status") == "SUCCESS":
            for item in self.test_http(domains_to_check, ipversion=4):
                yield item

        ipv6 = Diagnoser.get_cached_report("ip", item={"test": "ipv6"}) or {}
        if ipv6.get("status") == "SUCCESS":
            for item in self.test_http(domains_to_check, ipversion=6):
                yield item

        # If at least one domain is correctly exposed to the outside,
        # attempt to diagnose hairpinning situations. On network with
        # hairpinning issues, the server may be correctly exposed on the
        # outside, but from the outside, it will be as if the port forwarding
        # was not configured... Hence, calling for example
        # "curl --head the.global.ip" will simply timeout...
        if self.do_hairpinning_test:
            global_ipv4 = ipv4.get("data", {}).get("global", None)
            if global_ipv4:
                try:
                    requests.head("http://" + global_ipv4, timeout=5)
                except requests.exceptions.Timeout:
                    yield dict(meta={"test": "hairpinning"},
                               status="WARNING",
                               summary="diagnosis_http_hairpinning_issue",
                               details=["diagnosis_http_hairpinning_issue_details"])
                except:
                    # Well I dunno what to do if that's another exception
                    # type... That'll most probably *not* be an hairpinning
                    # issue but something else super weird ...
                    pass

    def test_http(self, domains, ipversion):

        try:
            r = Diagnoser.remote_diagnosis('check-http',
                                           data={'domains': domains,
                                                 "nonce": self.nonce},
                                           ipversion=ipversion)
            results = r["http"]
        except Exception as e:
            raise YunohostError("diagnosis_http_could_not_diagnose", error=e)

        assert set(results.keys()) == set(domains)

        for domain, result in results.items():

            if result["status"] == "ok":
                if ipversion == 4:
                    self.do_hairpinning_test = True
                yield dict(meta={"domain": domain},
                           status="SUCCESS",
                           summary="diagnosis_http_ok")
            else:
                yield dict(meta={"domain": domain},
                           status="ERROR",
                           summary="diagnosis_http_unreachable",
                           details=[result["status"].replace("error_http_check", "diagnosis_http")])


def main(args, env, loggers):
    return WebDiagnoser(args, env, loggers).diagnose()
