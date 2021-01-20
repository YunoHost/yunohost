#!/usr/bin/env python

import os

from yunohost.diagnosis import Diagnoser
from yunohost.regenconf import _get_regenconf_infos, _calculate_hash


class RegenconfDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies = []

    def run(self):

        regenconf_modified_files = list(self.manually_modified_files())

        if not regenconf_modified_files:
            yield dict(
                meta={"test": "regenconf"},
                status="SUCCESS",
                summary="diagnosis_regenconf_allgood",
            )
        else:
            for f in regenconf_modified_files:
                yield dict(
                    meta={
                        "test": "regenconf",
                        "category": f["category"],
                        "file": f["path"],
                    },
                    status="WARNING",
                    summary="diagnosis_regenconf_manually_modified",
                    details=["diagnosis_regenconf_manually_modified_details"],
                )

    def manually_modified_files(self):

        for category, infos in _get_regenconf_infos().items():
            for path, hash_ in infos["conffiles"].items():
                if hash_ != _calculate_hash(path):
                    yield {"path": path, "category": category}


def main(args, env, loggers):
    return RegenconfDiagnoser(args, env, loggers).diagnose()
