# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2018 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" diagnosis.py

    Look for possible issues on the server
"""

import os
import time

from moulinette import m18n, msettings
from moulinette.utils import log
from moulinette.utils.filesystem import read_json, write_to_json

from yunohost.utils.error import YunohostError
from yunohost.hook import hook_list, hook_exec

logger = log.getActionLogger('yunohost.diagnosis')

DIAGNOSIS_CACHE = "/var/cache/yunohost/diagnosis/"


def diagnosis_list():
    all_categories_names = [h for h, _ in _list_diagnosis_categories()]
    return {"categories": all_categories_names}


def diagnosis_show(categories=[], issues=False, full=False, share=False):

    # Get all the categories
    all_categories = _list_diagnosis_categories()
    all_categories_names = [category for category, _ in all_categories]

    # Check the requested category makes sense
    if categories == []:
        categories = all_categories_names
    else:
        unknown_categories = [c for c in categories if c not in all_categories_names]
        if unknown_categories:
            raise YunohostError('unknown_categories', categories=", ".join(categories))

    # Fetch all reports
    all_reports = []
    for category in categories:
        try:
            report = Diagnoser.get_cached_report(category)
        except Exception as e:
            logger.error(m18n.n("diagnosis_failed", category=category, error=str(e)))
        else:
            if not full:
                del report["timestamp"]
                del report["cached_for"]
                for item in report["items"]:
                    del item["meta"]
                    if "data" in item:
                        del item["data"]
            if issues:
                report["items"] = [item for item in report["items"] if item["status"] != "SUCCESS"]
                # Ignore this category if no issue was found
                if not report["items"]:
                    continue

            all_reports.append(report)

    if share:
        from yunohost.utils.yunopaste import yunopaste
        content = _dump_human_readable_reports(all_reports)
        url = yunopaste(content)

        logger.info(m18n.n("log_available_on_yunopaste", url=url))
        if msettings.get('interface') == 'api':
            return {"url": url}
        else:
            return
    else:
        return {"reports": all_reports}

def _dump_human_readable_reports(reports):

    output = ""

    for report in reports:
        output += "=================================\n"
        output += "{description} ({id})\n".format(**report)
        output += "=================================\n\n"
        for item in report["items"]:
            output += "[{status}] {summary}\n".format(**item)
            for detail in item.get("details", []):
                output += "  - " + detail + "\n"
            output += "\n"
        output += "\n\n"

    return(output)


def diagnosis_run(categories=[], force=False):

    # Get all the categories
    all_categories = _list_diagnosis_categories()
    all_categories_names = [category for category, _ in all_categories]

    # Check the requested category makes sense
    if categories == []:
        categories = all_categories_names
    else:
        unknown_categories = [c for c in categories if c not in all_categories_names]
        if unknown_categories:
            raise YunohostError('unknown_categories', categories=", ".join(unknown_categories))

    issues = []
    # Call the hook ...
    diagnosed_categories = []
    for category in categories:
        logger.debug("Running diagnosis for %s ..." % category)
        path = [p for n, p in all_categories if n == category][0]

        try:
            code, report = hook_exec(path, args={"force": force}, env=None)
        except Exception as e:
            logger.error(m18n.n("diagnosis_failed_for_category", category=category, error=str(e)), exc_info=True)
        else:
            diagnosed_categories.append(category)
            if report != {}:
                issues.extend([item for item in report["items"] if item["status"] != "SUCCESS"])

    if issues:
        if msettings.get("interface") == "api":
            logger.info(m18n.n("diagnosis_display_tip_web"))
        else:
            logger.info(m18n.n("diagnosis_display_tip_cli"))

    return


def diagnosis_ignore(category, args="", unignore=False):
    pass

############################################################


class Diagnoser():

    def __init__(self, args, env, loggers):

        # FIXME ? That stuff with custom loggers is weird ... (mainly inherited from the bash hooks, idk)
        self.logger_debug, self.logger_warning, self.logger_info = loggers
        self.env = env
        self.args = args or {}
        self.cache_file = Diagnoser.cache_file(self.id_)
        self.description = Diagnoser.get_description(self.id_)

    def cached_time_ago(self):

        if not os.path.exists(self.cache_file):
            return 99999999
        return time.time() - os.path.getmtime(self.cache_file)

    def write_cache(self, report):
        if not os.path.exists(DIAGNOSIS_CACHE):
            os.makedirs(DIAGNOSIS_CACHE)
        return write_to_json(self.cache_file, report)

    def diagnose(self):

        if not self.args.get("force", False) and self.cached_time_ago() < self.cache_duration:
            self.logger_debug("Cache still valid : %s" % self.cache_file)
            logger.info(m18n.n("diagnosis_cache_still_valid", category=self.description))
            return 0, {}

        for dependency in self.dependencies:
            dep_report = Diagnoser.get_cached_report(dependency)
            dep_errors = [item for item in dep_report["items"] if item["status"] == "ERROR"]
            if dep_errors:
                logger.error(m18n.n("diagnosis_cant_run_because_of_dep", category=self.description, dep=Diagnoser.get_description(dependency)))
                return 1, {}

        self.logger_debug("Running diagnostic for %s" % self.id_)

        items = list(self.run())

        new_report = {"id": self.id_,
                      "cached_for": self.cache_duration,
                      "items": items}

        self.logger_debug("Updating cache %s" % self.cache_file)
        self.write_cache(new_report)
        Diagnoser.i18n(new_report)

        errors   = [item for item in new_report["items"] if item["status"] == "ERROR"]
        warnings = [item for item in new_report["items"] if item["status"] == "WARNING"]

        if errors:
            logger.error(m18n.n("diagnosis_found_issues", errors=len(errors), category=new_report["description"]))
        elif warnings:
            logger.warning(m18n.n("diagnosis_found_warnings", warnings=len(warnings), category=new_report["description"]))
        else:
            logger.success(m18n.n("diagnosis_everything_ok", category=new_report["description"]))

        return 0, new_report

    @staticmethod
    def cache_file(id_):
        return os.path.join(DIAGNOSIS_CACHE, "%s.json" % id_)

    @staticmethod
    def get_cached_report(id_):
        filename = Diagnoser.cache_file(id_)
        report = read_json(filename)
        report["timestamp"] = int(os.path.getmtime(filename))
        Diagnoser.i18n(report)
        return report

    @staticmethod
    def get_description(id_):
        key = "diagnosis_description_" + id_
        descr = m18n.n(key)
        # If no description available, fallback to id
        return descr if descr != key else id_

    @staticmethod
    def i18n(report):

        # "Render" the strings with m18n.n
        # N.B. : we do those m18n.n right now instead of saving the already-translated report
        # because we can't be sure we'll redisplay the infos with the same locale as it
        # was generated ... e.g. if the diagnosing happened inside a cron job with locale EN
        # instead of FR used by the actual admin...

        report["description"] = Diagnoser.get_description(report["id"])

        for item in report["items"]:
            summary_key, summary_args = item["summary"]
            item["summary"] = m18n.n(summary_key, **summary_args)

            if "details" in item:
                item["details"] = [m18n.n(key, *values) for key, values in item["details"]]


def _list_diagnosis_categories():
    hooks_raw = hook_list("diagnosis", list_by="priority", show_info=True)["hooks"]
    hooks = []
    for _, some_hooks in sorted(hooks_raw.items(), key=lambda h: int(h[0])):
        for name, info in some_hooks.items():
            hooks.append((name, info["path"]))

    return hooks
