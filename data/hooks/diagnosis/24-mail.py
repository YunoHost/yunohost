#!/usr/bin/env python

import os
import dns.resolver
import socket
import re

from subprocess import CalledProcessError

from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_yaml

from yunohost.diagnosis import Diagnoser
from yunohost.domain import _get_maindomain, domain_list

DEFAULT_DNS_BLACKLIST = "/usr/share/yunohost/other/dnsbl_list.yml"


class MailDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 0
    dependencies = ["ip"]

    def run(self):

        self.ehlo_domain = _get_maindomain()
        self.mail_domains = domain_list()["domains"]
        self.ipversions, self.ips = self.get_ips_checked()

        # TODO Is a A/AAAA and MX Record ?
        # TODO Are outgoing public IPs authorized to send mail by SPF ?
        # TODO Validate DKIM and dmarc ?
        # TODO check that the recent mail logs are not filled with thousand of email sending (unusual number of mail sent)
        # TODO check for unusual failed sending attempt being refused in the logs ?
        checks = ["check_outgoing_port_25", "check_ehlo", "check_fcrdns",
                  "check_blacklist", "check_queue"]
        for check in checks:
            self.logger_debug("Running " + check)
            reports = list(getattr(self, check)())
            for report in reports:
                yield report
            if not reports:
                name = check[6:]
                yield dict(meta={"test": "mail_" + name},
                        status="SUCCESS",
                        summary="diagnosis_mail_" + name + "_ok")


    def check_outgoing_port_25(self):
        """
        Check outgoing port 25 is open and not blocked by router
        This check is ran on IPs we could used to send mail.
        """

        for ipversion in self.ipversions:
            cmd = '/bin/nc -{ipversion} -z -w2 yunohost.org 25'.format(ipversion=ipversion)
            if os.system(cmd) != 0:
                yield dict(meta={"test": "outgoing_port_25", "ipversion": ipversion},
                           data={},
                           status="ERROR",
                           summary="diagnosis_mail_outgoing_port_25_blocked",
                           details=["diagnosis_mail_outgoing_port_25_blocked_details",
                                    "diagnosis_mail_outgoing_port_25_blocked_relay_vpn"])


    def check_ehlo(self):
        """
        Check the server is reachable from outside and it's the good one
        This check is ran on IPs we could used to send mail.
        """

        for ipversion in self.ipversions:
            try:
                r = Diagnoser.remote_diagnosis('check-smtp',
                                               data={},
                                               ipversion=ipversion)
            except Exception as e:
                yield dict(meta={"test": "mail_ehlo", "reason": "remote_server_failed",
                                 "ipversion": ipversion},
                           data={"error": str(e)},
                           status="WARNING",
                           summary="diagnosis_mail_ehlo_could_not_diagnose",
                           details=["diagnosis_mail_ehlo_could_not_diagnose_details"])
                continue

            if r["status"] != "ok":
                summary = r["status"].replace("error_smtp_", "diagnosis_mail_ehlo_")
                yield dict(meta={"test": "mail_ehlo", "ipversion": ipversion},
                           data={},
                           status="ERROR",
                           summary=summary,
                           details=[summary + "_details"])
            elif r["helo"] != self.ehlo_domain:
                yield dict(meta={"test": "mail_ehlo", "ipversion": ipversion},
                           data={"wrong_ehlo": r["helo"], "right_ehlo": self.ehlo_domain},
                           status="ERROR",
                           summary="diagnosis_mail_ehlo_wrong")


    def check_fcrdns(self):
        """
        Check the reverse DNS is well defined by doing a Forward-confirmed
        reverse DNS check
        This check is ran on IPs we could used to send mail.
        """

        for ip in self.ips:
            try:
                rdns_domain, _, _ = socket.gethostbyaddr(ip)
            except socket.herror:
                yield dict(meta={"test": "mail_fcrdns", "ip": ip},
                           data={"ehlo_domain": self.ehlo_domain},
                           status="ERROR",
                           summary="diagnosis_mail_fcrdns_dns_missing")
                continue
            if rdns_domain != self.ehlo_domain:
                yield dict(meta={"test": "mail_fcrdns", "ip": ip},
                           data={"ehlo_domain": self.ehlo_domain,
                                 "rdns_domain": rdns_domain},
                           status="ERROR",
                           summary="diagnosis_mail_fcrdns_different_from_ehlo_domain")


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
                    item_type = 'ipv6'
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', item):
                    item_type = 'ipv4'

                if not blacklist[item_type]:
                    continue

                # Determine if we are listed on this RBL
                try:
                    subdomain = item
                    if item_type != "domain":
                        rev = dns.reversename.from_address(item)
                        subdomain = str(rev.split(3)[0])
                    query = subdomain + '.' + blacklist['dns_server']
                    # TODO add timeout lifetime
                    dns.resolver.query(query, "A")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer,
                dns.exception.Timeout):
                    continue

                # Try to get the reason
                details = []
                try:
                    reason = str(dns.resolver.query(query, "TXT")[0])
                    details.append("diagnosis_mail_blacklist_reason")
                except Exception:
                    reason = "-"

                details.append("diagnosis_mail_blacklist_website")

                yield dict(meta={"test": "mail_blacklist", "item": item,
                                 "blacklist": blacklist["dns_server"]},
                           data={'blacklist_name': blacklist['name'],
                                 'blacklist_website': blacklist['website'],
                                 'reason': reason},
                           status="ERROR",
                           summary='diagnosis_mail_blacklist_listed_by',
                           details=details)

    def check_queue(self):
        """
        Check mail queue is not filled with hundreds of email pending
        """

        command = 'postqueue -p | grep -v "Mail queue is empty" | grep -c "^[A-Z0-9]" || true'
        try:
            output = check_output(command).strip()
            pending_emails = int(output)
        except (ValueError, CalledProcessError) as e:
            yield dict(meta={"test": "mail_queue"},
                       data={"error": str(e)},
                       status="ERROR",
                       summary="diagnosis_mail_queue_unavailable",
                       details="diagnosis_mail_queue_unavailable_details")
        else:
            if pending_emails > 100:
                yield dict(meta={"test": "mail_queue"},
                           data={'nb_pending': pending_emails},
                       status="WARNING",
                       summary="diagnosis_mail_queue_too_many_pending_emails")
            else:
                yield dict(meta={"test": "mail_queue"},
                           data={'nb_pending': pending_emails},
                           status="SUCCESS",
                           summary="diagnosis_mail_queue_ok")


    def get_ips_checked(self):
        outgoing_ipversions = []
        outgoing_ips = []
        ipv4 = Diagnoser.get_cached_report("ip", {"test": "ipv4"}) or {}
        if ipv4.get("status") == "SUCCESS":
            outgoing_ipversions.append(4)
            global_ipv4 = ipv4.get("data", {}).get("global", {})
            if global_ipv4:
                outgoing_ips.append(global_ipv4)

        ipv6 = Diagnoser.get_cached_report("ip", {"test": "ipv6"}) or {}
        if ipv6.get("status") == "SUCCESS":
            outgoing_ipversions.append(6)
            global_ipv6 = ipv6.get("data", {}).get("global", {})
            if global_ipv6:
                outgoing_ips.append(global_ipv6)
        return (outgoing_ipversions, outgoing_ips)

def main(args, env, loggers):
    return MailDiagnoser(args, env, loggers).diagnose()
