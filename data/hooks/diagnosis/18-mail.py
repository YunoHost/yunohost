#!/usr/bin/env python

import os

from yunohost.diagnosis import Diagnoser


class MailDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = ["ip"]

    def run(self):

        # Is outgoing port 25 filtered somehow ?
        if os.system('/bin/nc -z -w2 yunohost.org 25') == 0:
            yield dict(meta={"test": "ougoing_port_25"},
                       status="SUCCESS",
                       summary=("diagnosis_mail_ougoing_port_25_ok",{}))
        else:
            yield dict(meta={"test": "outgoing_port_25"},
                       status="ERROR",
                       summary=("diagnosis_mail_ougoing_port_25_blocked",{}))



        # Mail blacklist using dig requests (c.f. ljf's code)

        # SMTP reachability (c.f. check-smtp to be implemented on yunohost's remote diagnoser)

        # ideally, SPF / DMARC / DKIM validation ... (c.f. https://github.com/alexAubin/yunoScripts/blob/master/yunoDKIM.py possibly though that looks horrible)

        # check that the mail queue is not filled with hundreds of email pending

        # check that the recent mail logs are not filled with thousand of email sending (unusual number of mail sent)

        # check for unusual failed sending attempt being refused in the logs ?


def main(args, env, loggers):
    return MailDiagnoser(args, env, loggers).diagnose()
