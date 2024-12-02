#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
import random
from typing import List

import requests
from moulinette.utils.filesystem import mkdir, read_file, rm

from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list
from yunohost.settings import settings_get
from yunohost.utils.dns import is_special_use_tld

DIAGNOSIS_SERVER = "diagnosis.yunohost.org"


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies: List[str] = ["ip"]

    def run(self):
        all_domains = domain_list()["domains"]
        domains_to_check = []
        for domain in all_domains:
            # If the diagnosis location ain't defined, can't do diagnosis,
            # probably because nginx conf manually modified...
            nginx_conf = "/etc/nginx/conf.d/%s.conf" % domain
            if ".well-known/ynh-diagnosis/" not in read_file(nginx_conf):
                yield dict(
                    meta={"domain": domain},
                    status="WARNING",
                    summary="diagnosis_http_nginx_conf_not_up_to_date",
                    details=["diagnosis_http_nginx_conf_not_up_to_date_details"],
                )
            elif is_special_use_tld(domain):
                yield dict(
                    meta={"domain": domain},
                    status="INFO",
                    summary="diagnosis_http_special_use_tld",
                )
            else:
                domains_to_check.append(domain)

        self.nonce = "".join(random.choice("0123456789abcedf") for i in range(16))
        rm("/var/www/.well-known/ynh-diagnosis/", recursive=True, force=True)
        mkdir("/var/www/.well-known/ynh-diagnosis/", parents=True, mode=0o0775)
        os.system("touch /var/www/.well-known/ynh-diagnosis/%s" % self.nonce)

        if not domains_to_check:
            return

        # To perform hairpinning test, we gotta make sure that port forwarding
        # is working and therefore we'll do it only if at least one ipv4 domain
        # works.
        self.do_hairpinning_test = False

        ipversions = []
        ipv4 = Diagnoser.get_cached_report("ip", item={"test": "ipv4"}) or {}
        if ipv4.get("status") == "SUCCESS" and settings_get(
            "misc.network.dns_exposure"
        ) in ["both", "ipv4"]:
            ipversions.append(4)

        # To be discussed: we could also make this check dependent on the
        # existence of an AAAA record...
        ipv6 = Diagnoser.get_cached_report("ip", item={"test": "ipv6"}) or {}
        if ipv6.get("status") == "SUCCESS":
            ipversions.append(6)

        for item in self.test_http(domains_to_check, ipversions):
            yield item

        # If at least one domain is correctly exposed to the outside,
        # attempt to diagnose hairpinning situations. On network with
        # hairpinning issues, the server may be correctly exposed on the
        # outside, but from the outside, it will be as if the port forwarding
        # was not configured... Hence, calling for example
        # "curl --head the.global.ip" will simply timeout...
        if self.do_hairpinning_test:
            global_ipv4 = ipv4.get("data", {}).get("global", None)
            if global_ipv4 and settings_get("misc.network.dns_exposure") in [
                "both",
                "ipv4",
            ]:
                try:
                    requests.head("http://" + global_ipv4, timeout=5)
                except requests.exceptions.Timeout:
                    yield dict(
                        meta={"test": "hairpinning"},
                        status="WARNING",
                        summary="diagnosis_http_hairpinning_issue",
                        details=["diagnosis_http_hairpinning_issue_details"],
                    )
                except Exception:
                    # Well I dunno what to do if that's another exception
                    # type... That'll most probably *not* be an hairpinning
                    # issue but something else super weird ...
                    pass

    def test_http(self, domains, ipversions):
        results = {}
        for ipversion in ipversions:
            try:
                r = Diagnoser.remote_diagnosis(
                    "check-http",
                    data={"domains": domains, "nonce": self.nonce},
                    ipversion=ipversion,
                )
                results[ipversion] = r["http"]
            except Exception as e:
                yield dict(
                    meta={"reason": "remote_diagnosis_failed", "ipversion": ipversion},
                    data={"error": str(e)},
                    status="WARNING",
                    summary="diagnosis_http_could_not_diagnose",
                    details=["diagnosis_http_could_not_diagnose_details"],
                )
                continue

        ipversions = results.keys()
        if not ipversions:
            return

        for domain in domains:
            # i18n: diagnosis_http_bad_status_code
            # i18n: diagnosis_http_connection_error
            # i18n: diagnosis_http_timeout

            # If both IPv4 and IPv6 (if applicable) are good
            if all(
                results[ipversion][domain]["status"] == "ok" for ipversion in ipversions
            ):
                if 4 in ipversions and settings_get("misc.network.dns_exposure") in [
                    "both",
                    "ipv4",
                ]:
                    self.do_hairpinning_test = True
                yield dict(
                    meta={"domain": domain},
                    status="SUCCESS",
                    summary="diagnosis_http_ok",
                )
            # If both IPv4 and IPv6 (if applicable) are failed
            elif all(
                results[ipversion][domain]["status"] != "ok" for ipversion in ipversions
            ):
                detail = results[4 if 4 in ipversions else 6][domain]["status"]
                yield dict(
                    meta={"domain": domain},
                    status="ERROR",
                    summary="diagnosis_http_unreachable",
                    details=[detail.replace("error_http_check", "diagnosis_http")],
                )
            # If only IPv4 is failed or only IPv6 is failed (if applicable)
            else:
                passed, failed = (
                    (4, 6) if results[4][domain]["status"] == "ok" else (6, 4)
                )
                detail = results[failed][domain]["status"]

                # Failing in ipv4 is critical.
                # If we failed in IPv6 but there's in fact no AAAA record
                # It's an acceptable situation and we shall not report an
                # error
                def ipv6_is_important_for_this_domain():
                    dnsrecords = (
                        Diagnoser.get_cached_report(
                            "dnsrecords", item={"domain": domain, "category": "basic"}
                        )
                        or {}
                    )
                    AAAA_status = dnsrecords.get("data", {}).get("AAAA:@")

                    return AAAA_status in ["OK", "WRONG"] or settings_get(
                        "misc.network.dns_exposure"
                    ) in ["both", "ipv6"]

                if failed == 4 or ipv6_is_important_for_this_domain():
                    yield dict(
                        meta={"domain": domain},
                        data={"passed": passed, "failed": failed},
                        status="ERROR",
                        summary="diagnosis_http_partially_unreachable",
                        details=[detail.replace("error_http_check", "diagnosis_http")],
                    )
                # So otherwise we report a success (note that this info is
                # later used to know that ACME challenge is doable)
                #
                # And in addition we report an info about the failure in IPv6
                # *with a different meta* (important to avoid conflicts when
                # fetching the other info...)
                else:
                    self.do_hairpinning_test = True
                    yield dict(
                        meta={"domain": domain},
                        status="SUCCESS",
                        summary="diagnosis_http_ok",
                    )
                    yield dict(
                        meta={"test": "ipv6", "domain": domain},
                        data={"passed": passed, "failed": failed},
                        status="INFO",
                        summary="diagnosis_http_partially_unreachable",
                        details=[detail.replace("error_http_check", "diagnosis_http")],
                    )
