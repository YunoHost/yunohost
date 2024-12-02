#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
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
import glob
from logging import getLogger

from moulinette.core import MoulinetteError
from moulinette.utils.filesystem import (
    read_file,
    write_to_file,
)

from yunohost.utils.error import YunohostValidationError


logger = getLogger("yunohost.utils.legacy")


def _patch_legacy_helpers(app_folder):
    files_to_patch = []
    files_to_patch.extend(glob.glob("%s/scripts/*" % app_folder))
    files_to_patch.extend(glob.glob("%s/scripts/.*" % app_folder))

    stuff_to_replace = {
        "yunohost user create": {
            "pattern": r"yunohost user create (\S+) (-f|--firstname) (\S+) (-l|--lastname) \S+ (.*)",
            "replace": r"yunohost user create \1 --fullname \3 \5",
            "important": False,
        },
        # Remove
        #    Automatic diagnosis data from YunoHost
        #    __PRE_TAG1__$(yunohost tools diagnosis | ...)__PRE_TAG2__"
        #
        "yunohost tools diagnosis": {
            "pattern": r"(Automatic diagnosis data from YunoHost( *\n)*)? *(__\w+__)? *\$\(yunohost tools diagnosis.*\)(__\w+__)?",
            "replace": r"",
            "important": False,
        },
    }

    for helper, infos in stuff_to_replace.items():
        infos["pattern"] = (
            re.compile(infos["pattern"]) if infos.get("pattern") else None
        )
        infos["replace"] = infos.get("replace")

    for filename in files_to_patch:
        # Ignore non-regular files
        if not os.path.isfile(filename):
            continue

        try:
            content = read_file(filename)
        except MoulinetteError:
            continue

        replaced_stuff = False
        show_warning = False

        for helper, infos in stuff_to_replace.items():
            # Ignore if not relevant for this file
            if infos.get("only_for") and not any(
                filename.endswith(f) for f in infos["only_for"]
            ):
                continue

            # If helper is used, attempt to patch the file
            if helper in content and infos["pattern"]:
                content = infos["pattern"].sub(infos["replace"], content)
                replaced_stuff = True
                if infos["important"]:
                    show_warning = True

            # If the helper is *still* in the content, it means that we
            # couldn't patch the deprecated helper in the previous lines.  In
            # that case, abort the install or whichever step is performed
            if helper in content and infos["important"]:
                raise YunohostValidationError(
                    "This app is likely pretty old and uses deprecated / outdated helpers that can't be migrated easily. It can't be installed anymore.",
                    raw_msg=True,
                )

        if replaced_stuff:
            # Check the app do load the helper
            # If it doesn't, add the instruction ourselve (making sure it's after the #!/bin/bash if it's there...
            if filename.split("/")[-1] in [
                "install",
                "remove",
                "upgrade",
                "backup",
                "restore",
            ]:
                source_helpers = "source /usr/share/yunohost/helpers"
                if source_helpers not in content:
                    content.replace("#!/bin/bash", "#!/bin/bash\n" + source_helpers)
                if source_helpers not in content:
                    content = source_helpers + "\n" + content

            # Actually write the new content in the file
            write_to_file(filename, content)

        if show_warning:
            # And complain about those damn deprecated helpers
            logger.error(
                r"/!\ Packagers! This app uses very old deprecated helpers... YunoHost automatically patched the helpers to use the new recommended practice, but please do consider fixing the upstream code right now..."
            )
