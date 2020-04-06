#!/usr/bin/env python

import os
import dns.resolver

from moulinette.utils.network import download_text

from yunohost.diagnosis import Diagnoser

DEFAULT_BLACKLIST = [
    ('zen.spamhaus.org'             , 'Spamhaus SBL, XBL and PBL'        ),
    ('dnsbl.sorbs.net'              , 'SORBS aggregated'                 ),
    ('safe.dnsbl.sorbs.net'         , "'safe' subset of SORBS aggregated"),
    ('ix.dnsbl.manitu.net'          , 'Heise iX NiX Spam'                ),
    ('babl.rbl.webiron.net'         , 'Bad Abuse'                        ),
    ('cabl.rbl.webiron.net'         , 'Chronicly Bad Abuse'              ),
    ('truncate.gbudb.net'           , 'Exclusively Spam/Malware'         ),
    ('dnsbl-1.uceprotect.net'       , 'Trapserver Cluster'               ),
    ('cbl.abuseat.org'              , 'Net of traps'                     ),
    ('dnsbl.cobion.com'             , 'used in IBM products'             ),
    ('psbl.surriel.com'             , 'passive list, easy to unlist'     ),
    ('dnsrbl.org'                   , 'Real-time black list'             ),
    ('db.wpbl.info'                 , 'Weighted private'                 ),
    ('bl.spamcop.net'               , 'Based on spamcop users'           ),
    ('dyna.spamrats.com'            , 'Dynamic IP addresses'             ),
    ('spam.spamrats.com'            , 'Manual submissions'               ),
    ('auth.spamrats.com'            , 'Suspicious authentications'       ),
    ('dnsbl.inps.de'                , 'automated and reported'           ),
    ('bl.blocklist.de'              , 'fail2ban reports etc.'            ),
    ('srnblack.surgate.net'         , 'feeders'                          ),
    ('all.s5h.net'                  , 'traps'                            ),
    ('rbl.realtimeblacklist.com'    , 'lists ip ranges'                  ),
    ('b.barracudacentral.org'       , 'traps'                            ),
    ('hostkarma.junkemailfilter.com', 'Autotected Virus Senders'         ),
    ('rbl.megarbl.net'              , 'Curated Spamtraps'                ),
    ('ubl.unsubscore.com'           , 'Collected Opt-Out Addresses'      ),
    ('0spam.fusionzero.com'         , 'Spam Trap'                        ),
]


class MailDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies = ["ip"]

    def run(self):

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

        # Is Reverse DNS well configured ?


        # Are IPs blacklisted ?
        self.logger_debug("Running RBL detection")
        blacklisted_details = tuple(self.check_blacklisted(self.get_public_ip(4)))
        blacklisted_details += tuple(self.check_blacklisted(self.get_public_ip(6)))
        if blacklisted_details:
            yield dict(meta={},
                       status="ERROR",
                       summary=("diagnosis_mail_blacklist_nok", {}),
                       details=blacklisted_details)
        else:
            yield dict(meta={},
                       status="SUCCESS",
                       summary=("diagnosis_mail_blacklist_ok", {}))

        # SMTP reachability (c.f. check-smtp to be implemented on yunohost's remote diagnoser)

        # ideally, SPF / DMARC / DKIM validation ... (c.f. https://github.com/alexAubin/yunoScripts/blob/master/yunoDKIM.py possibly though that looks horrible)

        # check that the mail queue is not filled with hundreds of email pending

        # check that the recent mail logs are not filled with thousand of email sending (unusual number of mail sent)

        # check for unusual failed sending attempt being refused in the logs ?

    def check_blacklisted(self, ip):
        """ Check with dig onto blacklist DNS server
        """
        if ip is None:
            return

        for blacklist, description in DEFAULT_BLACKLIST:

            # Determine if we are listed on this RBL
            try:
                rev = dns.reversename.from_address(ip)
                query = str(rev.split(3)[0]) + '.' + blacklist
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

            yield ('diagnosis_mail_blacklisted_by',
                   (ip, blacklist, reason))

    def get_public_ip(self, protocol=4):
        # TODO we might call this function from another side
        assert protocol in [4, 6], "Invalid protocol version, it should be either 4 or 6 and was '%s'" % repr(protocol)

        url = 'https://ip%s.yunohost.org' % ('6' if protocol == 6 else '')

        try:
            return download_text(url, timeout=30).strip()
        except Exception as e:
            self.logger_debug("Could not get public IPv%s : %s" % (str(protocol), str(e)))
            return None


def main(args, env, loggers):
    return MailDiagnoser(args, env, loggers).diagnose()
