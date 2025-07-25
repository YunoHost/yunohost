#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
import re
from typing import List

from moulinette.utils.filesystem import read_file

from ..diagnosis import Diagnoser
from ..regenconf import _calculate_hash, _get_regenconf_infos
from ..settings import settings_get


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies: List[str] = []

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

        if (
            any(f["path"] == "/etc/ssh/sshd_config" for f in regenconf_modified_files)
            and os.system(
                "grep -q '^ *AllowGroups\\|^ *AllowUsers' /etc/ssh/sshd_config"
            )
            != 0
        ):
            yield dict(
                meta={"test": "sshd_config_insecure"},
                status="ERROR",
                summary="diagnosis_sshd_config_insecure",
            )

        # Check consistency between actual ssh port in sshd_config vs. setting
        ssh_port_setting = settings_get("security.ssh.ssh_port")
        ssh_port_line = re.findall(
            r"\bPort *([0-9]{2,5})\b", read_file("/etc/ssh/sshd_config")
        )
        if len(ssh_port_line) == 1 and int(ssh_port_line[0]) != ssh_port_setting:
            yield dict(
                meta={"test": "sshd_config_port_inconsistency"},
                status="WARNING",
                summary="diagnosis_sshd_config_inconsistent",
                details=["diagnosis_sshd_config_inconsistent_details"],
            )

    def manually_modified_files(self):
        for category, infos in _get_regenconf_infos().items():
            for path, hash_ in infos["conffiles"].items():
                if hash_ != _calculate_hash(path):
                    yield {"path": path, "category": category}
