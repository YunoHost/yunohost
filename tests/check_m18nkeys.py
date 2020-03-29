# -*- coding: utf-8 -*-

import os
import re
import sys
import glob
import json
import yaml
import subprocess

ignore = [ "password_too_simple_",
           "password_listed",
           "backup_method_",
           "backup_applying_method_",
           "confirm_app_install_",
        ]

###############################################################################
#   Find used keys in python code                                             #
###############################################################################

def find_expected_string_keys():

    # Try to find :
    #    m18n.n(   "foo"
    #    YunohostError("foo"
    p1 = re.compile(r'm18n\.n\(\s*[\"\'](\w+)[\"\']')
    p2 = re.compile(r'YunohostError\([\'\"](\w+)[\'\"]')

    python_files = glob.glob("../src/yunohost/*.py")
    python_files.extend(glob.glob("../src/yunohost/utils/*.py"))
    python_files.extend(glob.glob("../src/yunohost/data_migrations/*.py"))
    python_files.extend(glob.glob("../data/hooks/diagnosis/*.py"))
    python_files.append("../bin/yunohost")

    for python_file in python_files:
        content = open(python_file).read()
        yield from p1.findall(content)
        yield from p2.findall(content)

    # For each diagnosis, try to find strings like "diagnosis_stuff_foo" (c.f. diagnosis summaries)
    # Also we expect to have "diagnosis_description_<name>" for each diagnosis
    p3 = re.compile(r'[\"\'](diagnosis_[a-z]+_\w+)[\"\']')
    for python_file in glob.glob("../data/hooks/diagnosis/*.py"):
        content = open(python_file).read()
        yield from p3.findall(content)
        yield "diagnosis_description_" + os.path.basename(python_file)[:-3].split("-")[-1]

    # For each migration, expect to find "migration_description_<name>"
    for path in glob.glob("../src/yunohost/data_migrations/*.py"):
        if "__init__" in path:
            continue
        yield "migration_description_" + os.path.basename(path)[:-3]

    # For each default service, expect to find "service_description_<name>"
    for service, info in yaml.safe_load(open("../data/templates/yunohost/services.yml")).items():
        if info is None:
            continue
        yield "service_description_" + service

    # For all unit operations, expect to find "log_<name>"
    # A unit operation is created either using the @is_unit_operation decorator
    # or using OperationLogger(
    cmd = "grep -hr '@is_unit_operation' ../src/yunohost/ -A3 2>/dev/null | grep '^def' | sed -E 's@^def (\w+)\(.*@\\1@g'"
    for funcname in subprocess.check_output(cmd, shell=True).decode("utf-8").split("\n"):
        yield "log_"+funcname

    p4 = re.compile(r"OperationLogger\([\"\'](\w+)[\"\']")
    for python_file in python_files:
        content = open(python_file).read()
        yield from ("log_"+match for match in p4.findall(content))

    # Global settings descriptions
    # Will be on a line like : ("service.ssh.allow_deprecated_dsa_hostkey", {"type": "bool", ...
    p5 = re.compile(r" \([\"\'](\w[\w\.]+)[\"\'],")
    content = open("../src/yunohost/settings.py").read()
    yield from ("global_settings_setting_"+s.replace(".", "_") for s in p5.findall(content))

    # Keys for the actionmap ...
    for category in yaml.load(open("../data/actionsmap/yunohost.yml")).values():
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

expected_string_keys = set(find_expected_string_keys())

expected_string_keys.add("admin_password")

###############################################################################
#   Load en locale json keys                                                  #
###############################################################################

en_locale_file = "../locales/en.json"
with open(en_locale_file) as f:
    en_locale_json = json.loads(f.read())

en_locale_keys = set(en_locale_json.keys())

###############################################################################
#   Compare keys used and keys defined                                        #
###############################################################################

keys_used_but_not_defined = expected_string_keys.difference(en_locale_keys)
keys_defined_but_not_used = en_locale_keys.difference(expected_string_keys)

if len(keys_used_but_not_defined) != 0:
    print("> Error ! Those keys are used in some files but not defined :")
    for key in sorted(keys_used_but_not_defined):
        if any(key.startswith(i) for i in ignore):
            continue
        print("   - %s" % key)

if len(keys_defined_but_not_used) != 0:
    print("> Warning ! Those keys are defined but seems unused :")
    for key in sorted(keys_defined_but_not_used):
        if any(key.startswith(i) for i in ignore):
            continue
        print("   - %s" % key)


if len(keys_used_but_not_defined) != 0 or len(keys_defined_but_not_used) != 0:
    sys.exit(1)
