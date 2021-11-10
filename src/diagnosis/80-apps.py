#!/usr/bin/env python

import os

from yunohost.app import app_list

from yunohost.diagnosis import Diagnoser


class MyDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies = []

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
            yield ("error", "diagnosis_apps_not_in_app_catalog")
        elif (
            not isinstance(app["from_catalog"].get("level"), int)
            or app["from_catalog"]["level"] == 0
        ):
            yield ("error", "diagnosis_apps_broken")
        elif app["from_catalog"]["level"] <= 4:
            yield ("warning", "diagnosis_apps_bad_quality")

        # Check for super old, deprecated practices

        yunohost_version_req = (
            app["manifest"].get("requirements", {}).get("yunohost", "").strip(">= ")
        )
        if yunohost_version_req.startswith("2."):
            yield ("error", "diagnosis_apps_outdated_ynh_requirement")

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
                    f"grep -hr '{deprecated_helper}' {app['setting_path']}/scripts/ | grep -v -q '^\\s*#'"
                )
                == 0
            ):
                yield ("error", "diagnosis_apps_deprecated_practices")

        old_arg_regex = r"^domain=\${?[0-9]"
        if (
            os.system(
                f"grep -q '{old_arg_regex}' {app['setting_path']}/scripts/install"
            )
            == 0
        ):
            yield ("error", "diagnosis_apps_deprecated_practices")
