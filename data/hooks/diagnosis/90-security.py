#!/usr/bin/env python

import os
import json
import subprocess

from yunohost.diagnosis import Diagnoser
from moulinette.utils.filesystem import read_json, write_to_json


class SecurityDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600
    dependencies = []

    def run(self):

        "CVE-2017-5754"

        if self.is_vulnerable_to_meltdown():
            yield dict(meta={"test": "meltdown"},
                       status="ERROR",
                       summary=("diagnosis_security_vulnerable_to_meltdown", {}),
                       details=[("diagnosis_security_vulnerable_to_meltdown_details", ())]
                       )
        else:
            yield dict(meta={},
                       status="SUCCESS",
                       summary=("diagnosis_security_all_good", {})
                       )


    def is_vulnerable_to_meltdown(self):
        # meltdown CVE: https://security-tracker.debian.org/tracker/CVE-2017-5754

        # We use a cache file to avoid re-running the script so many times,
        # which can be expensive (up to around 5 seconds on ARM)
        # and make the admin appear to be slow (c.f. the calls to diagnosis
        # from the webadmin)
        #
        # The cache is in /tmp and shall disappear upon reboot
        # *or* we compare it to dpkg.log modification time
        # such that it's re-ran if there was package upgrades
        # (e.g. from yunohost)
        cache_file = "/tmp/yunohost-meltdown-diagnosis"
        dpkg_log = "/var/log/dpkg.log"
        if os.path.exists(cache_file):
            if not os.path.exists(dpkg_log) or os.path.getmtime(cache_file) > os.path.getmtime(dpkg_log):
                self.logger_debug("Using cached results for meltdown checker, from %s" % cache_file)
                return read_json(cache_file)[0]["VULNERABLE"]

        # script taken from https://github.com/speed47/spectre-meltdown-checker
        # script commit id is store directly in the script
        SCRIPT_PATH = "/usr/lib/moulinette/yunohost/vendor/spectre-meltdown-checker/spectre-meltdown-checker.sh"

        # '--variant 3' corresponds to Meltdown
        # example output from the script:
        # [{"NAME":"MELTDOWN","CVE":"CVE-2017-5754","VULNERABLE":false,"INFOS":"PTI mitigates the vulnerability"}]
        try:
            self.logger_debug("Running meltdown vulnerability checker")
            call = subprocess.Popen("bash %s --batch json --variant 3" %
                                    SCRIPT_PATH, shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            # TODO / FIXME : here we are ignoring error messages ...
            # in particular on RPi2 and other hardware, the script complains about
            # "missing some kernel info (see -v), accuracy might be reduced"
            # Dunno what to do about that but we probably don't want to harass
            # users with this warning ...
            output, err = call.communicate()
            assert call.returncode in (0, 2, 3), "Return code: %s" % call.returncode

            # If there are multiple lines, sounds like there was some messages
            # in stdout that are not json >.> ... Try to get the actual json
            # stuff which should be the last line
            output = output.strip()
            if "\n" in output:
                self.logger_debug("Original meltdown checker output : %s" % output)
                output = output.split("\n")[-1]

            CVEs = json.loads(output)
            assert len(CVEs) == 1
            assert CVEs[0]["NAME"] == "MELTDOWN"
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.logger_warning("Something wrong happened when trying to diagnose Meltdown vunerability, exception: %s" % e)
            raise Exception("Command output for failed meltdown check: '%s'" % output)

        self.logger_debug("Writing results from meltdown checker to cache file, %s" % cache_file)
        write_to_json(cache_file, CVEs)
        return CVEs[0]["VULNERABLE"]


def main(args, env, loggers):
    return SecurityDiagnoser(args, env, loggers).diagnose()
