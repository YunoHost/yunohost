#
# Copyright (c) 2022 YunoHost Contributors
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
from typing import List

from yunohost.diagnosis import Diagnoser
from yunohost.service import service_status


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies: List[str] = []

    def run(self):
        all_result = service_status()

        for service, result in sorted(all_result.items()):
            item = dict(
                meta={"service": service},
                data={
                    "status": result["status"],
                    "configuration": result["configuration"],
                },
            )

            if result["status"] != "running":
                item["status"] = "ERROR" if result["status"] != "unknown" else "WARNING"
                item["summary"] = "diagnosis_services_bad_status"
                item["details"] = ["diagnosis_services_bad_status_tip"]

            elif result["configuration"] == "broken":
                item["status"] = "WARNING"
                item["summary"] = "diagnosis_services_conf_broken"
                item["details"] = result["configuration-details"]

            else:
                item["status"] = "SUCCESS"
                item["summary"] = "diagnosis_services_running"

            yield item
