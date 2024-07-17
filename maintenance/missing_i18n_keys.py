# -*- coding: utf-8 -*-

import toml
import os
import re
import glob
import json
import yaml
import subprocess
import sys

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
    p3 = re.compile(r"YunohostValidationError\(\n*\s*[\'\"](\w+)[\'\"]")
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
        for m in p3.findall(content):
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
    cmd = f"grep -hr '@is_unit_operation' {ROOT}/src/ -A3 2>/dev/null | grep '^def' | sed -E 's@^def (\\w+)\\(.*@\\1@g'"
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
    ]
    for panel in domain_config.values():
        if not isinstance(panel, dict):
            continue
        for section in panel.values():
            if not isinstance(section, dict):
                continue
            for key, values in section.items():
                if not isinstance(values, dict):
                    continue
                yield f"domain_config_{key}"
                if key in domain_settings_with_help_key:
                    yield f"domain_config_{key}_help"

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
    ]

    for panel in global_config.values():
        if not isinstance(panel, dict):
            continue
        for section in panel.values():
            if not isinstance(section, dict):
                continue
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
