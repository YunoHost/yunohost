#!/usr/bin/env python

import os

from yunohost.diagnosis import Diagnoser


class MailDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = ["ip"]

    def run(self):

        return  # TODO / FIXME TO BE IMPLEMETED in the future ...

        # Mail blacklist using dig requests (c.f. ljf's code)

        # Outgoing port 25 (c.f. code in monitor.py, a simple 'nc -zv yunohost.org 25' IIRC)

        # SMTP reachability (c.f. check-smtp to be implemented on yunohost's remote diagnoser)

        # ideally, SPF / DMARC / DKIM validation ... (c.f. https://github.com/alexAubin/yunoScripts/blob/master/yunoDKIM.py possibly though that looks horrible)

        # check that the mail queue is not filled with hundreds of email pending

        # check that the recent mail logs are not filled with thousand of email sending (unusual number of mail sent)

        # check for unusual failed sending attempt being refused in the logs ?


def main(args, env, loggers):
    return MailDiagnoser(args, env, loggers).diagnose()
