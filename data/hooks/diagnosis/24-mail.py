#!/usr/bin/env python

import os
import dns.resolver
import smtplib
import socket

from moulinette.utils.process import check_output
from moulinette.utils.network import download_text
from moulinette.utils.filesystem import read_yaml

from yunohost.diagnosis import Diagnoser
from yunohost.domain import _get_maindomain

DEFAULT_DNS_BLACKLIST = "/usr/share/yunohost/other/dnsbl_list.yml"


class MailDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies = ["ip"]

    def run(self):
        
        ips = self.get_public_ips()

        # Is outgoing port 25 filtered somehow ?
        self.logger_debug("Running outgoing 25 port check")
        if os.system('/bin/nc -z -w2 yunohost.org 25') == 0:
            yield dict(meta={"test": "ougoing_port_25"},
                       status="SUCCESS",
                       summary="diagnosis_mail_ougoing_port_25_ok")
        else:
            yield dict(meta={"test": "outgoing_port_25"},
                       status="ERROR",
                       summary="diagnosis_mail_ougoing_port_25_blocked")

        # Get HELO and be sure postfix is running
        # TODO SMTP reachability (c.f. check-smtp to be implemented on yunohost's remote diagnoser)
        server = None
        result = dict(meta={"test": "mail_ehlo"},
                      status="SUCCESS",
                      summary="diagnosis_mail_service_working")
        try:
            server = smtplib.SMTP("127.0.0.1", 25, timeout=10)
            ehlo = server.ehlo()
            ehlo_domain = ehlo[1].decode("utf-8").split("\n")[0]
        except OSError:
            result = dict(meta={"test": "mail_ehlo"},
                    status="ERROR",
                    summary="diagnosis_mail_service_not_working")
            ehlo_domain = _get_maindomain()
        if server:
            server.quit()
        yield result

        # Forward-confirmed reverse DNS (FCrDNS) verification
        self.logger_debug("Running Forward-confirmed reverse DNS check")
        for ip in ips:
            try:
                rdns_domain, _, _ = socket.gethostbyaddr(ip)
            except socket.herror as e:
                yield dict(meta={"test": "mail_fcrdns"},
                           data={"ip": ip, "ehlo_domain": ehlo_domain},
                           status="ERROR",
                           summary="diagnosis_mail_reverse_dns_missing")
                continue
            else:
                if rdns_domain != ehlo_domain:
                    yield dict(meta={"test": "mail_fcrdns"},
                               data={"ip": ip, "ehlo_domain": ehlo_domain,
                                     "rdns_domain": rdns_domain},
                               status="ERROR",
                               summary="diagnosis_mail_rdns_different_from_ehlo_domain")
                else:
                    yield dict(meta={"test": "mail_fcrdns"},
                               data={"ip": ip, "ehlo_domain": ehlo_domain},
                               status="SUCCESS",
                               summary="diagnosis_mail_rdns_equal_to_ehlo_domain")

        # TODO Is a A/AAAA and MX Record ?

        # Are IPs listed on a DNSBL ?
        self.logger_debug("Running DNS Blacklist detection")
        # TODO Test if domain are blacklisted too

        blacklisted_details = list(self.check_dnsbl(self.get_public_ips()))
        if blacklisted_details:
            yield dict(meta={"test": "mail_blacklist"},
                       status="ERROR",
                       summary="diagnosis_mail_blacklist_nok",
                       details=blacklisted_details)
        else:
            yield dict(meta={"test": "mail_blacklist"},
                       status="SUCCESS",
                       summary="diagnosis_mail_blacklist_ok")

        # TODO Are outgoing public IPs authorized to send mail by SPF ?
        
        # TODO Validate DKIM and dmarc ?


        # Is mail queue filled with hundreds of email pending ?
        command = 'postqueue -p | grep -c "^[A-Z0-9]"'
        output = check_output(command).strip()
        try:
            pending_emails = int(output)
        except ValueError:
            yield dict(meta={"test": "mail_queue"},
                       status="ERROR",
                       summary="diagnosis_mail_cannot_get_queue")
        else:
            if pending_emails > 300:
                yield dict(meta={"test": "mail_queue"},
                           data={'nb_pending': pending_emails},
                       status="WARNING",
                       summary="diagnosis_mail_queue_too_many_pending_emails")
            else:
                yield dict(meta={"test": "mail_queue"},
                           data={'nb_pending': pending_emails},
                       status="INFO",
                       summary="diagnosis_mail_queue_ok")

        # check that the recent mail logs are not filled with thousand of email sending (unusual number of mail sent)

        # check for unusual failed sending attempt being refused in the logs ?

    def check_dnsbl(self, ips):
        """ Check with dig onto blacklist DNS server
        """
        dns_blacklists = read_yaml(DEFAULT_DNS_BLACKLIST)
        for ip in ips:
            for blacklist in dns_blacklists:
                if "." in ip and not blacklist['ipv4']:
                    continue

                if ":" in ip and not blacklist['ipv6']:
                    continue
                
                # Determine if we are listed on this RBL
                try:
                    rev = dns.reversename.from_address(ip)
                    query = str(rev.split(3)[0]) + '.' + blacklist['dns_server']
                    # TODO add timeout lifetime
                    dns.resolver.query(query, "A")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer,
                dns.exception.Timeout):
                    continue

                # Try to get the reason
                reason = "not explained"
                try:
                    reason = str(dns.resolver.query(query, "TXT")[0])
                except Exception:
                    pass

                yield ('diagnosis_mail_blacklisted_by', {
                    'ip': ip,
                    'blacklist_name': blacklist['name'],
                    'blacklist_website': blacklist['website'],
                    'reason': reason})

    def get_public_ips(self):
        # Todo code a better way to access a data
        ipv4 = Diagnoser.get_cached_report("ip", {"test": "ipv4"})
        if ipv4:
            global_ipv4 = ipv4.get("data", {}).get("global", {})
            if global_ipv4:
                yield global_ipv4
        
        ipv6 = Diagnoser.get_cached_report("ip", {"test": "ipv6"})
        if ipv6:
            global_ipv6 = ipv6.get("data", {}).get("global", {})
            if global_ipv6:
                yield global_ipv6


def main(args, env, loggers):
    return MailDiagnoser(args, env, loggers).diagnose()
