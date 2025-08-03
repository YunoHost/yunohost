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

from ..app import app_list, APPS_SETTING_PATH
from ..diagnosis import Diagnoser


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies: list[str] = []

    def run(self):
        apps = app_list(full=True)["apps"]
        for app in apps:
            app["issues"] = list(self.issues(app))

        if not any(app["issues"] for app in apps):
            yield dict(
                meta={"test": "apps"},
                status="SUCCESS",
                summary="diagnosis_apps_allgood",
            )
        else:
            for app in apps:
                if not app["issues"]:
                    continue

                level = (
                    "ERROR"
                    if any(issue[0] == "error" for issue in app["issues"])
                    else "WARNING"
                )

                yield dict(
                    meta={"test": "apps", "app": app["name"]},
                    status=level,
                    summary="diagnosis_apps_issue",
                    details=[issue[1] for issue in app["issues"]],
                )

    def issues(self, app):
        # Check quality level in catalog

        if not app.get("from_catalog") or app["from_catalog"].get("state") != "working":
            yield ("warning", "diagnosis_apps_not_in_app_catalog")
        elif (
            not isinstance(app["from_catalog"].get("level"), int)
            or app["from_catalog"]["level"] == 0
        ):
            yield ("warning", "diagnosis_apps_broken")
        elif app["from_catalog"]["level"] <= 4:
            yield ("warning", "diagnosis_apps_bad_quality")

        # Check for super old, deprecated practices

        if app["manifest"].get("packaging_format", 0) < 2:
            yield ("error", "diagnosis_apps_outdated_packaging_format")

        yunohost_version_req = (
            app["manifest"].get("requirements", {}).get("yunohost", "").strip(">= ")
        )
        if (
            yunohost_version_req.startswith("2.")
            or yunohost_version_req.startswith("3.")
            or yunohost_version_req.startswith("4.")
        ):
            yield ("error", "diagnosis_apps_outdated_ynh_requirement")

        app_setting_path = os.path.join(APPS_SETTING_PATH, app["id"])
        deprecated_helpers = [
            "yunohost app setting",
            "yunohost app checkurl",
            "yunohost app checkport",
            "yunohost app initdb",
            "yunohost tools port-available",
        ]
        for deprecated_helper in deprecated_helpers:
            if (
                os.system(
                    f"grep -hr '{deprecated_helper}' {app_setting_path}/scripts/ | grep -v -q '^\\s*#'"
                )
                == 0
            ):
                yield ("error", "diagnosis_apps_deprecated_practices")

        old_arg_regex = r"^domain=\${?[0-9]"
        if (
            os.system(f"grep -q '{old_arg_regex}' {app_setting_path}/scripts/install")
            == 0
        ):
            yield ("error", "diagnosis_apps_deprecated_practices")
