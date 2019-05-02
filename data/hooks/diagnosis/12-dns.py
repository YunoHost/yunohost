#!/usr/bin/env python

import os

from moulinette.utils.network import download_text
from moulinette.core import init_authenticator
from moulinette.utils.process import check_output

from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list, _build_dns_conf, _get_maindomain

# Instantiate LDAP Authenticator
auth_identifier = ('ldap', 'ldap-anonymous')
auth_parameters = {'uri': 'ldap://localhost:389', 'base_dn': 'dc=yunohost,dc=org'}
auth = init_authenticator(auth_identifier, auth_parameters)

class DNSDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    description = "dns_configurations"
    cache_duration = 3600*24

    def validate_args(self, args):
        all_domains = domain_list(auth)["domains"]
        if "domain" not in args.keys():
            return { "domains" : all_domains }
        else:
            assert args["domain"] in all_domains, "Unknown domain"
            return { "domains" : [ args["domain"] ] }

    def run(self):

        self.resolver = check_output('grep "$nameserver" /etc/resolv.dnsmasq.conf').split("\n")[0].split(" ")[1]

        main_domain = _get_maindomain()

        for domain in self.args["domains"]:
            self.logger_info("Diagnosing DNS conf for %s" % domain)
            for report in self.check_domain(domain, domain==main_domain):
                yield report

    def check_domain(self, domain, is_main_domain):

        expected_configuration = _build_dns_conf(domain)

        # Here if there are no AAAA record, we should add something to expect "no" AAAA record
        # to properly diagnose situations where people have a AAAA record but no IPv6

	for category, records in expected_configuration.items():

            discrepancies = []

            for r in records:
                current_value = self.get_current_record(domain, r["name"], r["type"]) or "None"
                expected_value = r["value"] if r["value"] != "@" else domain+"."

                if current_value != expected_value:
                    discrepancies.append((r, expected_value, current_value))

            if discrepancies:
                if category == "basic" or is_main_domain:
                    level = "ERROR"
                else:
                    level = "WARNING"
                report = (level, "diagnosis_dns_bad_conf", {"domain": domain, "category": category})
            else:
                level = "SUCCESS"
                report = ("SUCCESS", "diagnosis_dns_good_conf", {"domain": domain, "category": category})

            # FIXME : add management of details of what's wrong if there are discrepancies
            yield dict(meta = {"domain": domain, "category": category},
                       result = level, report = report )



    def get_current_record(self, domain, name, type_):
        if name == "@":
            command = "dig +short @%s %s %s" % (self.resolver, type_, domain)
        else:
            command = "dig +short @%s %s %s.%s" % (self.resolver, type_, name, domain)
        output = check_output(command).strip()
        output = output.replace("\;",";")
        if output.startswith('"') and output.endswith('"'):
            output = '"' + ' '.join(output.replace('"',' ').split()) + '"'
        return output


def main(args, env, loggers):
    DNSDiagnoser(args, env, loggers).diagnose()
    return 0

