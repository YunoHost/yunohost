#!/usr/bin/env python

import os

from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file

from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list, _build_dns_conf, _get_maindomain


class DNSRecordsDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600 * 24
    dependencies = ["ip"]

    def run(self):

        resolvers = read_file("/etc/resolv.dnsmasq.conf").split("\n")
        ipv4_resolvers = [r.split(" ")[1] for r in resolvers if r.startswith("nameserver") and ":" not in r]
        # FIXME some day ... handle ipv4-only and ipv6-only servers. For now we assume we have at least ipv4
        assert ipv4_resolvers != [], "Uhoh, need at least one IPv4 DNS resolver ..."

        self.resolver = ipv4_resolvers[0]
        main_domain = _get_maindomain()

        all_domains = domain_list()["domains"]
        for domain in all_domains:
            self.logger_debug("Diagnosing DNS conf for %s" % domain)
            is_subdomain = domain.split(".",1)[1] in all_domains
            for report in self.check_domain(domain, domain == main_domain, is_subdomain=is_subdomain):
                yield report

        # FIXME : somewhere, should implement a check for reverse DNS ...

        # FIXME / TODO : somewhere, could also implement a check for domain expiring soon

    def check_domain(self, domain, is_main_domain, is_subdomain):

        expected_configuration = _build_dns_conf(domain)

        # FIXME: Here if there are no AAAA record, we should add something to expect "no" AAAA record
        # to properly diagnose situations where people have a AAAA record but no IPv6
        categories = ["basic", "mail", "xmpp", "extra"]
        if is_subdomain:
            categories = ["basic"]

        for category in categories:

            records = expected_configuration[category]
            discrepancies = []

            for r in records:
                current_value = self.get_current_record(domain, r["name"], r["type"]) or "None"
                expected_value = r["value"] if r["value"] != "@" else domain + "."

                if current_value == "None":
                    discrepancies.append(("diagnosis_dns_missing_record", (r["type"], r["name"], expected_value)))
                elif current_value != expected_value:
                    discrepancies.append(("diagnosis_dns_discrepancy", (r["type"], r["name"], expected_value, current_value)))

            if discrepancies:
                status = "ERROR" if (category == "basic" or (is_main_domain and category != "extra")) else "WARNING"
                summary = ("diagnosis_dns_bad_conf", {"domain": domain, "category": category})
            else:
                status = "SUCCESS"
                summary = ("diagnosis_dns_good_conf", {"domain": domain, "category": category})

            output = dict(meta={"domain": domain, "category": category},
                          status=status,
                          summary=summary)

            if discrepancies:
                output["details"] = discrepancies

            yield output

    def get_current_record(self, domain, name, type_):
        if name == "@":
            command = "dig +short @%s %s %s" % (self.resolver, type_, domain)
        else:
            command = "dig +short @%s %s %s.%s" % (self.resolver, type_, name, domain)
        # FIXME : gotta handle case where this command fails ...
        # e.g. no internet connectivity (dependency mechanism to good result from 'ip' diagosis ?)
        # or the resolver is unavailable for some reason
        output = check_output(command).strip()
        if output.startswith('"') and output.endswith('"'):
            output = '"' + ' '.join(output.replace('"', ' ').split()) + '"'
        return output


def main(args, env, loggers):
    return DNSRecordsDiagnoser(args, env, loggers).diagnose()
