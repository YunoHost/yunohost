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

import errno
import os
import time

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils import log
from moulinette.utils.filesystem import read_json, write_to_json

from yunohost.hook import hook_list, hook_exec

logger = log.getActionLogger('yunohost.diagnosis')

DIAGNOSIS_CACHE = "/var/cache/yunohost/diagnosis/"

def diagnosis_list():
    all_categories_names = [ h for h, _ in _list_diagnosis_categories() ]
    return { "categories": all_categories_names }

def diagnosis_show(categories=[], full=False):

    # Get all the categories
    all_categories = _list_diagnosis_categories()
    all_categories_names = [ category for category, _ in all_categories ]

    # Check the requested category makes sense
    if categories == []:
        categories = all_categories_names
    else:
        unknown_categories = [ c for c in categories if c not in all_categories_names ]
        if unknown_categories:
            raise MoulinetteError(m18n.n('unknown_categories', categories=", ".join(categories)))

    # Fetch all reports
    all_reports = []
    for category in categories:
        try:
            all_reports.append(Diagnoser.get_cached_report(category))
        except Exception as e:
            logger.error("Failed to fetch diagnosis result for category '%s' : %s" % (category, str(e))) # FIXME : i18n

    # "Render" the strings with m18n.n
    for report in all_reports:

        report["description"] = m18n.n(report["description"])

        for r in report["reports"]:
            type_, message_key, message_args = r["report"]
            r["report"] = (type_, m18n.n(message_key, **message_args))

    return {"reports": all_reports}

def diagnosis_run(categories=[], force=False, args=None):

    # Get all the categories
    all_categories = _list_diagnosis_categories()
    all_categories_names = [ category for category, _ in all_categories ]

    # Check the requested category makes sense
    if categories == []:
        categories = all_categories_names
    else:
        unknown_categories = [ c for c in categories if c not in all_categories_names ]
        if unknown_categories:
            raise MoulinetteError(m18n.n('unknown_categories', categories=", ".join(unknown_categories)))

    # Transform "arg1=val1&arg2=val2" to { "arg1": "val1", "arg2": "val2" }
    if args is not None:
        args = { arg.split("=")[0]: arg.split("=")[1] for arg in args.split("&") }
    else:
        args = {}
    args["force"] = force

    # Call the hook ...
    successes = []
    for category in categories:
        logger.debug("Running diagnosis for %s ..." % category)
        path = [p for n, p in all_categories if n == category ][0]

        try:
            hook_exec(path, args=args, env=None)
            successes.append(category)
        except Exception as e:
            # FIXME / TODO : add stacktrace here ?
            logger.error("Diagnosis failed for category '%s' : %s" % (category, str(e))) # FIXME : i18n 

    return diagnosis_show(successes)

def diagnosis_ignore(category, args="", unignore=False):
    pass

############################################################


class Diagnoser():

    def __init__(self, args, env, loggers):

        self.logger_debug, self.logger_warning, self.logger_info = loggers
        self.env = env
        self.args = args
        self.args.update(self.validate_args(args))
        self.cache_file = Diagnoser.cache_file(self.id_)

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
            return

        self.logger_debug("Running diagnostic for %s" % self.id_)

        new_report = { "id": self.id_,
                       "description": self.description,
                       "cached_for": self.cache_duration,
                       "reports": list(self.run())
                     }

        # TODO / FIXME : should handle the case where we only did a partial diagnosis
        self.logger_debug("Updating cache %s" % self.cache_file)
        self.write_cache(new_report)

    @staticmethod
    def cache_file(id_):
        return os.path.join(DIAGNOSIS_CACHE, "%s.json" % id_)

    @staticmethod
    def get_cached_report(id_):
        filename = Diagnoser.cache_file(id_)
        report = read_json(filename)
        report["timestamp"] = int(os.path.getmtime(filename))
        return report



def _list_diagnosis_categories():
    hooks_raw = hook_list("diagnosis", list_by="priority", show_info=True)["hooks"]
    hooks = []
    for _, some_hooks in sorted(hooks_raw.items(), key=lambda h:int(h[0])):
        for name, info in some_hooks.items():
            hooks.append((name, info["path"]))

    return hooks
