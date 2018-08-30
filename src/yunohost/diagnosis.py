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

def diagnosis_report(categories=[], full=False):
    pass

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
            raise MoulinetteError(m18n.n('unknown_categories', categories=", ".join(categories)))

    # Transform "arg1=val1&arg2=val2" to { "arg1": "val1", "arg2": "val2" }
    if args is not None:
        args = { arg.split("=")[0]: arg.split("=")[1] for arg in args.split("&") }
    else:
        args = {}
    args["force"] = force


    # Call the hook ...
    for category in categories:
        logger.debug("Running diagnosis for %s ..." % category)
        path = [p for n, p in all_categories if n == category ][0]

        # TODO : get the return value and do something with it
        return {"report": hook_exec(path, args=args, env=None) }


def diagnosis_ignore(category, args="", unignore=False):
    pass

############################################################

class Diagnoser():

    def __init__(self, args, env, loggers):

        self.logger_debug, self.logger_warning, self.logger_info = loggers
        self.env = env
        self.args = args
        self.args.update(self.validate_args(args))

    @property
    def cache_file(self):
        return os.path.join(DIAGNOSIS_CACHE, "%s.json" % self.id_)

    def cached_time_ago(self):

        if not os.path.exists(self.cache_file):
            return 99999999
        return time.time() - os.path.getmtime(self.cache_file)

    def get_cached_report(self):
        return read_json(self.cache_file)

    def write_cache(self, report):
        if not os.path.exists(DIAGNOSIS_CACHE):
            os.makedirs(DIAGNOSIS_CACHE)
        return write_to_json(self.cache_file, report)

    def report(self):

        if not self.args.get("force", False) and self.cached_time_ago() < self.cache_duration:
            self.logger_debug("Using cached report from %s" % self.cache_file)
            return self.get_cached_report()

        self.logger_debug("Running diagnostic for %s" % self.id_)

        new_report = { "id": self.id_,
                       "cached_for": self.cache_duration,
                       "reports": list(self.run())
                     }

        # TODO / FIXME : should handle the case where we only did a partial diagnosis
        self.logger_debug("Updating cache %s" % self.cache_file)
        self.write_cache(new_report)

        return new_report



def _list_diagnosis_categories():
    hooks_raw = hook_list("diagnosis", list_by="priority", show_info=True)["hooks"]
    hooks = []
    for _, some_hooks in sorted(hooks_raw.items(), key=lambda h:int(h[0])):
        for name, info in some_hooks.items():
            hooks.append((name, info["path"]))

    return hooks
