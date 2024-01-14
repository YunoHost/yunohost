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
import dns.resolver
import re
import logging
from typing import List

from subprocess import CalledProcessError

from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_yaml

from yunohost.diagnosis import Diagnoser
from yunohost.domain import _get_maindomain, domain_list
from yunohost.settings import settings_get
from yunohost.utils.dns import dig

DEFAULT_DNS_BLACKLIST = "/usr/share/yunohost/dnsbl_list.yml"

logger = logging.getLogger("yunohost.diagnosis")


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies: List[str] = ["ip"]

    def run(self):
        self.ehlo_domain = _get_maindomain().lower()
        self.mail_domains = domain_list()["domains"]
        self.ipversions, self.ips = self.get_ips_checked()

        # TODO Is a A/AAAA and MX Record ?
        # TODO Are outgoing public IPs authorized to send mail by SPF ?
        # TODO Validate DKIM and dmarc ?
        # TODO check that the recent mail logs are not filled with thousand of email sending (unusual number of mail sent)
        # TODO check for unusual failed sending attempt being refused in the logs ?
        checks = [
            "check_outgoing_port_25",  # i18n: diagnosis_mail_outgoing_port_25_ok
            "check_ehlo",  # i18n: diagnosis_mail_ehlo_ok
            "check_fcrdns",  # i18n: diagnosis_mail_fcrdns_ok
            "check_blacklist",  # i18n: diagnosis_mail_blacklist_ok
            "check_queue",  # i18n: diagnosis_mail_queue_ok
        ]
        for check in checks:
            logger.debug("Running " + check)
            reports = list(getattr(self, check)())
            for report in reports:
                yield report
            if not reports:
                name = check[6:]
                yield dict(
                    meta={"test": "mail_" + name},
                    status="SUCCESS",
                    summary="diagnosis_mail_" + name + "_ok",
                )

    def check_outgoing_port_25(self):
        """
        Check outgoing port 25 is open and not blocked by router
        This check is ran on IPs we could used to send mail.
        """

        for ipversion in self.ipversions:
            cmd = "/bin/nc -{ipversion} -z -w2 yunohost.org 25".format(
                ipversion=ipversion
            )
            if os.system(cmd) != 0:
                yield dict(
                    meta={"test": "outgoing_port_25", "ipversion": ipversion},
                    data={},
                    status="ERROR",
                    summary="diagnosis_mail_outgoing_port_25_blocked",
                    details=[
                        "diagnosis_mail_outgoing_port_25_blocked_details",
                        "diagnosis_mail_outgoing_port_25_blocked_relay_vpn",
                    ],
                )

    def check_ehlo(self):
        """
        Check the server is reachable from outside and it's the good one
        This check is ran on IPs we could used to send mail.
        """

        for ipversion in self.ipversions:
            try:
                r = Diagnoser.remote_diagnosis(
                    "check-smtp", data={}, ipversion=ipversion
                )
            except Exception as e:
                yield dict(
                    meta={
                        "test": "mail_ehlo",
                        "reason": "remote_server_failed",
                        "ipversion": ipversion,
                    },
                    data={"error": str(e)},
                    status="WARNING",
                    summary="diagnosis_mail_ehlo_could_not_diagnose",
                    details=["diagnosis_mail_ehlo_could_not_diagnose_details"],
                )
                continue

            if r["status"] != "ok":
                # i18n: diagnosis_mail_ehlo_bad_answer
                # i18n: diagnosis_mail_ehlo_bad_answer_details
                # i18n: diagnosis_mail_ehlo_unreachable
                # i18n: diagnosis_mail_ehlo_unreachable_details
                summary = r["status"].replace("error_smtp_", "diagnosis_mail_ehlo_")
                yield dict(
                    meta={"test": "mail_ehlo", "ipversion": ipversion},
                    data={},
                    status="ERROR",
                    summary=summary,
                    details=[summary + "_details"],
                )
            elif r["helo"].lower() != self.ehlo_domain:
                yield dict(
                    meta={"test": "mail_ehlo", "ipversion": ipversion},
                    data={"wrong_ehlo": r["helo"], "right_ehlo": self.ehlo_domain},
                    status="ERROR",
                    summary="diagnosis_mail_ehlo_wrong",
                    details=["diagnosis_mail_ehlo_wrong_details"],
                )

    def check_fcrdns(self):
        """
        Check the reverse DNS is well defined by doing a Forward-confirmed
        reverse DNS check
        This check is ran on IPs we could used to send mail.
        """

        for ip in self.ips:
            if ":" in ip:
                ipversion = 6
                details = [
                    "diagnosis_mail_fcrdns_nok_details",
                    "diagnosis_mail_fcrdns_nok_alternatives_6",
                ]
            else:
                ipversion = 4
                details = [
                    "diagnosis_mail_fcrdns_nok_details",
                    "diagnosis_mail_fcrdns_nok_alternatives_4",
                ]

            rev = dns.reversename.from_address(ip)
            subdomain = str(rev.split(3)[0])
            query = subdomain
            if ipversion == 4:
                query += ".in-addr.arpa"
            else:
                query += ".ip6.arpa"

            # Do the DNS Query
            status, value = dig(query, "PTR", resolvers="force_external")
            if status == "nok":
                yield dict(
                    meta={"test": "mail_fcrdns", "ipversion": ipversion},
                    data={"ip": ip, "ehlo_domain": self.ehlo_domain},
                    status="ERROR",
                    summary="diagnosis_mail_fcrdns_dns_missing",
                    details=details,
                )
                continue

            rdns_domain = ""
            if len(value) > 0:
                rdns_domain = value[0][:-1] if value[0].endswith(".") else value[0]
            if rdns_domain.lower() != self.ehlo_domain:
                details = [
                    "diagnosis_mail_fcrdns_different_from_ehlo_domain_details"
                ] + details
                yield dict(
                    meta={"test": "mail_fcrdns", "ipversion": ipversion},
                    data={
                        "ip": ip,
                        "ehlo_domain": self.ehlo_domain,
                        "rdns_domain": rdns_domain.lower(),
                    },
                    status="ERROR",
                    summary="diagnosis_mail_fcrdns_different_from_ehlo_domain",
                    details=details,
                )

    def check_blacklist(self):
        """
        Check with dig onto blacklist DNS server
        This check is ran on IPs and domains we could used to send mail.
        """

        dns_blacklists = read_yaml(DEFAULT_DNS_BLACKLIST)
        for item in self.ips + self.mail_domains:
            for blacklist in dns_blacklists:
                item_type = "domain"
                if ":" in item:
                    item_type = "ipv6"
                elif re.match(r"^\d+\.\d+\.\d+\.\d+$", item):
                    item_type = "ipv4"

                if not blacklist[item_type]:
                    continue

                # Build the query for DNSBL
                subdomain = item
                if item_type != "domain":
                    rev = dns.reversename.from_address(item)
                    subdomain = str(rev.split(3)[0])
                query = subdomain + "." + blacklist["dns_server"]

                # Do the DNS Query
                status, answers = dig(query, "A")
                if status != "ok" or (
                    answers
                    and set(answers) <= set(blacklist["non_blacklisted_return_code"])
                ):
                    continue

                # Try to get the reason
                details = []
                status, answers = dig(query, "TXT")
                reason = "-"
                if status == "ok":
                    reason = ", ".join(answers)
                    details.append("diagnosis_mail_blacklist_reason")

                details.append("diagnosis_mail_blacklist_website")

                yield dict(
                    meta={
                        "test": "mail_blacklist",
                        "item": item,
                        "blacklist": blacklist["dns_server"],
                    },
                    data={
                        "blacklist_name": blacklist["name"],
                        "blacklist_website": blacklist["website"],
                        "reason": reason,
                    },
                    status="ERROR",
                    summary="diagnosis_mail_blacklist_listed_by",
                    details=details,
                )

    def check_queue(self):
        """
        Check mail queue is not filled with hundreds of email pending
        """

        command = (
            'postqueue -p | grep -v "Mail queue is empty" | grep -c "^[A-Z0-9]" || true'
        )
        try:
            output = check_output(command)
            pending_emails = int(output)
        except (ValueError, CalledProcessError) as e:
            yield dict(
                meta={"test": "mail_queue"},
                data={"error": str(e)},
                status="ERROR",
                summary="diagnosis_mail_queue_unavailable",
                details=["diagnosis_mail_queue_unavailable_details"],
            )
        else:
            if pending_emails > 100:
                yield dict(
                    meta={"test": "mail_queue"},
                    data={"nb_pending": pending_emails},
                    status="WARNING",
                    summary="diagnosis_mail_queue_too_big",
                )
            else:
                yield dict(
                    meta={"test": "mail_queue"},
                    data={"nb_pending": pending_emails},
                    status="SUCCESS",
                    summary="diagnosis_mail_queue_ok",
                )

    def get_ips_checked(self):
        outgoing_ipversions = []
        outgoing_ips = []
        ipv4 = Diagnoser.get_cached_report("ip", {"test": "ipv4"}) or {}
        if ipv4.get("status") == "SUCCESS" and settings_get(
            "misc.network.dns_exposure"
        ) in ["both", "ipv4"]:
            outgoing_ipversions.append(4)
            global_ipv4 = ipv4.get("data", {}).get("global", {})
            if global_ipv4:
                outgoing_ips.append(global_ipv4)

        if settings_get("email.smtp.smtp_allow_ipv6") or settings_get(
            "misc.network.dns_exposure"
        ) in ["both", "ipv6"]:
            ipv6 = Diagnoser.get_cached_report("ip", {"test": "ipv6"}) or {}
            if ipv6.get("status") == "SUCCESS":
                outgoing_ipversions.append(6)
                global_ipv6 = ipv6.get("data", {}).get("global", {})
                if global_ipv6:
                    outgoing_ips.append(global_ipv6)
        return (outgoing_ipversions, outgoing_ips)
