#!/usr/bin/env python

import os

import subprocess
from yunohost.diagnosis import Diagnoser
from yunohost.regenconf import manually_modified_files
#from yunohost.regenconf import manually_modified_files, manually_modified_files_compared_to_debian_default


class RegenconfDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies = []

    def run(self):

        regenconf_modified_files = manually_modified_files()
        #debian_modified_files = manually_modified_files_compared_to_debian_default(ignore_handled_by_regenconf=True)

        if regenconf_modified_files == []:
            yield dict(meta={"test": "regenconf"},
                       status="SUCCESS",
                       summary=("diagnosis_regenconf_allgood", {})
                       )
        else:
            for f in regenconf_modified_files:
                yield dict(meta={"test": "regenconf", "file": f},
                           status="WARNING",
                           summary=("diagnosis_regenconf_manually_modified", {"file": f}),
                           details=[("diagnosis_regenconf_manually_modified_details", {})]
                           )

        #for f in debian_modified_files:
        #    yield dict(meta={"test": "debian", "file": f},
        #               status="WARNING",
        #               summary=("diagnosis_regenconf_manually_modified_debian", {"file": f}),
        #               details=[("diagnosis_regenconf_manually_modified_debian_details", {})]
        #               )


def main(args, env, loggers):
    return RegenconfDiagnoser(args, env, loggers).diagnose()
