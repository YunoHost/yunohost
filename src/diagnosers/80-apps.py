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

import logging
import os

from packaging import version

from ..app import APPS_SETTING_PATH, AppInfo, app_list
from ..app_catalog import SecurityIssueInfos, _load_security_issues_list
from ..diagnosis import Diagnoser
from ..utils.system import debian_version

logger = logging.getLogger("yunohost.diagnosis")


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies: list[str] = []

    def run(self):
        self.security_issues_list_per_app = _load_security_issues_list()["apps"]

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
                    meta={
                        "test": "apps",
                        "app": app["name"],
                        "installed_version": app["version"],
                    },
                    status=level,
                    summary="diagnosis_apps_issue",
                    details=[issue[1] for issue in app["issues"]],
                )

    def issues(self, app: AppInfo):
        def app_version_parse(v: str) -> tuple:
            if "~" in v:
                raw_upstream_version, raw_ynh_version = v.split("~ynh", 1)
            else:
                raw_upstream_version, raw_ynh_version = (v, "0")
            upstream_version = version.parse(raw_upstream_version)
            ynh_version = int(raw_ynh_version)
            return (upstream_version, ynh_version)

        # Check for security issues reported in the security issue index

        app_base_id = app["manifest"]["id"]
        if app_base_id in self.security_issues_list_per_app:
            app_version = app_version_parse(app["version"])
            security_issues_for_this_app: list[SecurityIssueInfos] = (
                self.security_issues_list_per_app[app_base_id]
            )
            for issue in security_issues_for_this_app:
                raw_fixed_in_version = issue["fixed_in_version"]
                if isinstance(raw_fixed_in_version, dict):
                    if debian_version() not in issue["fixed_in_version"]:
                        logger.warning(
                            f"Not able to check versions in which security issue is fixed for app '{app_base_id}' (no version specified for Debian {debian_version()})"
                        )
                        continue
                    fixed_in_version = app_version_parse(
                        raw_fixed_in_version[debian_version()]
                    )
                else:
                    fixed_in_version = app_version_parse(raw_fixed_in_version)

                if app_version >= fixed_in_version:
                    continue
                level = "error" if issue["level"] == "danger" else "warning"
                if isinstance(issue["more_infos"], list):
                    more_infos_list = ", ".join(issue["more_infos"])
                else:
                    more_infos_list = issue["more_infos"]

                # i18n: diagnosis_apps_security_issue_warning
                # i18n: diagnosis_apps_security_issue_error
                yield (
                    level,
                    (
                        f"diagnosis_apps_security_issue_{level}",
                        {
                            **issue,
                            "more_infos_list": more_infos_list,
                            "current_version": app["version"],
                        },
                    ),
                )

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
