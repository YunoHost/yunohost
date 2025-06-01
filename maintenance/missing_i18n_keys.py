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

import glob
import json
import os
import re
import subprocess
import sys

import toml
import yaml

ROOT = os.path.dirname(__file__) + "/../"
LOCALE_FOLDER = ROOT + "/locales/"
REFERENCE_FILE = LOCALE_FOLDER + "en.json"

###############################################################################
#   Find used keys in python code                                             #
###############################################################################


def find_expected_string_keys():
    # Try to find :
    #    m18n.n(   "foo"
    #    YunohostError("foo"
    #    YunohostValidationError("foo"
    #    # i18n: foo
    p1 = re.compile(r"m18n\.n\(\n*\s*[\"\'](\w+)[\"\']")
    p2 = re.compile(r"YunohostError\(\n*\s*[\'\"](\w+)[\'\"]")
    p3 = re.compile(
        r"Yunohost(Validation|Authentication)Error\(\n*\s*[\'\"](\w+)[\'\"]"
    )
    p4 = re.compile(r"# i18n: [\'\"]?(\w+)[\'\"]?")

    python_files = glob.glob(ROOT + "src/*.py")
    python_files.extend(glob.glob(ROOT + "src/utils/*.py"))
    python_files.extend(glob.glob(ROOT + "src/migrations/*.py"))
    python_files.extend(glob.glob(ROOT + "src/migrations/*.py.disabled"))
    python_files.extend(glob.glob(ROOT + "src/authenticators/*.py"))
    python_files.extend(glob.glob(ROOT + "src/diagnosers/*.py"))
    python_files.append(ROOT + "bin/yunohost")

    for python_file in python_files:
        content = open(python_file).read()
        for m in p1.findall(content):
            if m.endswith("_"):
                continue
            yield m
        for m in p2.findall(content):
            if m.endswith("_"):
                continue
            yield m
        for _, m in p3.findall(content):
            if m.endswith("_"):
                continue
            yield m
        for m in p4.findall(content):
            yield m

    # For each diagnosis, try to find strings like "diagnosis_stuff_foo" (c.f. diagnosis summaries)
    # Also we expect to have "diagnosis_description_<name>" for each diagnosis
    p3 = re.compile(r"[\"\'](diagnosis_[a-z]+_\w+)[\"\']")
    for python_file in glob.glob(ROOT + "src/diagnosers/*.py"):
        if "__init__.py" in python_file:
            continue
        content = open(python_file).read()
        for m in p3.findall(content):
            if m.endswith("_"):
                # Ignore some name fragments which are actually concatenated with other stuff..
                continue
            yield m
        yield "diagnosis_description_" + os.path.basename(python_file)[:-3].split("-")[
            -1
        ]

    # For each migration, expect to find "migration_description_<name>"
    for path in glob.glob(ROOT + "src/migrations/*.py"):
        if "__init__" in path:
            continue
        yield "migration_description_" + os.path.basename(path)[:-3]

    # For each default service, expect to find "service_description_<name>"
    for service, info in yaml.safe_load(
        open(ROOT + "conf/yunohost/services.yml")
    ).items():
        if info is None:
            continue
        yield "service_description_" + service

    # For all unit operations, expect to find "log_<name>"
    # A unit operation is created either using the @is_unit_operation decorator
    # or using OperationLogger(
    cmd = f"grep -hr '@is_unit_operation([^f]' {ROOT}/src/ -A3 2>/dev/null | grep '^def' | sed -E 's@^def (\\w+)\\(.*@\\1@g'"
    for funcname in (
        subprocess.check_output(cmd, shell=True).decode("utf-8").strip().split("\n")
    ):
        yield "log_" + funcname

    p4 = re.compile(r"OperationLogger\(\n*\s*[\"\'](\w+)[\"\']")
    for python_file in python_files:
        content = open(python_file).read()
        for m in ("log_" + match for match in p4.findall(content)):
            yield m

    # Keys for the actionmap ...
    for category in yaml.safe_load(open(ROOT + "share/actionsmap.yml")).values():
        if "actions" not in category.keys():
            continue
        for action in category["actions"].values():
            if "arguments" not in action.keys():
                continue
            for argument in action["arguments"].values():
                extra = argument.get("extra")
                if not extra:
                    continue
                if "password" in extra:
                    yield extra["password"]
                if "ask" in extra:
                    yield extra["ask"]
                if "comment" in extra:
                    yield extra["comment"]
                if "pattern" in extra:
                    yield extra["pattern"][1]
                if "help" in extra:
                    yield extra["help"]

    # Hardcoded expected keys ...
    yield "admin_password"  # Not sure that's actually used nowadays...

    for method in ["tar", "copy", "custom"]:
        yield "backup_applying_method_%s" % method
        yield "backup_method_%s_finished" % method

    registrars = toml.load(open(ROOT + "share/registrar_list.toml"))
    supported_registrars = ["ovh", "gandi", "godaddy"]
    for registrar in supported_registrars:
        for key in registrars[registrar].keys():
            yield f"domain_config_{key}"

    # Domain config panel
    domain_config = toml.load(open(ROOT + "share/config_domain.toml"))
    domain_settings_with_help_key = [
        "portal_logo",
        "portal_public_intro",
        "portal_theme",
        "portal_user_intro",
        "search_engine",
        "custom_css",
        "dns",
        "enable_public_apps_page",
    ]
    domain_section_with_no_name = ["app", "cert_", "mail", "registrar"]
    for panel_key, panel in domain_config.items():
        if not isinstance(panel, dict):
            continue
        yield f"domain_config_{panel_key}_name"
        for section_key, section in panel.items():
            if not isinstance(section, dict):
                continue
            if section_key not in domain_section_with_no_name:
                yield f"domain_config_{section_key}_name"
            for key, values in section.items():
                if not isinstance(values, dict):
                    continue
                yield f"domain_config_{key}"
                if key in domain_settings_with_help_key:
                    yield f"domain_config_{key}_help"

    # App config panel
    app_config = toml.load(open(ROOT + "share/config_app.toml"))
    app_settings_with_help_key = [
        "logo",
        "description",
        "force_upgrade",
    ]
    for panel_key, panel in app_config.items():
        if not isinstance(panel, dict):
            continue
        yield f"app_config_{panel_key}_name"
        for section_key, section in panel.items():
            if not isinstance(section, dict):
                continue
            if section_key != "permissions":
                yield f"app_config_{section_key}_name"
            for key, values in section.items():
                if not isinstance(values, dict) or values.get("visible") is False:
                    continue
                if section_key == "permissions":
                    key_ = "permission_" + key
                else:
                    key_ = key
                yield f"app_config_{key_}"
                if key in app_settings_with_help_key:
                    yield f"app_config_{key_}_help"

    # Global settings
    global_config = toml.load(open(ROOT + "share/config_global.toml"))
    # Boring hard-coding because there's no simple other way idk
    settings_without_help_key = [
        "passwordless_sudo",
        "smtp_relay_host",
        "smtp_relay_password",
        "smtp_relay_port",
        "smtp_relay_user",
        "ssowat_panel_overlay_enabled",
        "root_password",
        "root_access_explain",
        "root_password_confirm",
        "tls_passthrough_explain",
        "allow_edit_email",
        "allow_edit_email_alias",
        "allow_edit_email_forward",
    ]

    for panel_key, panel in global_config.items():
        if not isinstance(panel, dict):
            continue
        yield f"global_settings_setting_{panel_key}_name"
        for section_key, section in panel.items():
            if not isinstance(section, dict):
                continue
            yield f"global_settings_setting_{section_key}_name"
            for key, values in section.items():
                if not isinstance(values, dict):
                    continue
                yield f"global_settings_setting_{key}"
                if key not in settings_without_help_key:
                    yield f"global_settings_setting_{key}_help"


###############################################################################
#   Compare keys used and keys defined                                        #
###############################################################################

if len(sys.argv) <= 1 or sys.argv[1] not in ["--check", "--fix"]:
    print("Please specify --check or --fix")
    sys.exit(1)

expected_string_keys = set(find_expected_string_keys())
keys_defined_for_en = json.loads(open(REFERENCE_FILE).read()).keys()
keys_defined = set(keys_defined_for_en)

unused_keys = keys_defined.difference(expected_string_keys)
unused_keys = sorted(unused_keys)

undefined_keys = expected_string_keys.difference(keys_defined)
undefined_keys = sorted(undefined_keys)

mode = sys.argv[1].strip("-")
if mode == "check":
    # Unused keys are not too problematic, will be automatically
    # removed by the other autoreformat script,
    # but still informative to display them
    if unused_keys:
        print(
            "Those i18n keys appears unused:\n" "    - " + "\n    - ".join(unused_keys)
        )

    if undefined_keys:
        print(
            "Those i18n keys should be defined in en.json:\n"
            "    - " + "\n    - ".join(undefined_keys)
        )
        sys.exit(1)

elif mode == "fix":
    j = json.loads(open(REFERENCE_FILE).read())
    for key in undefined_keys:
        j[key] = "FIXME"
    for key in unused_keys:
        del j[key]

    json.dump(
        j,
        open(REFERENCE_FILE, "w"),
        indent=4,
        ensure_ascii=False,
        sort_keys=True,
    )
