# -*- coding: utf-8 -*-

import re
import glob
import json
import yaml

ignore = [ "service_description_",
           "migration_description_",
           "global_settings_setting_",
           "password_too_simple_",
           "password_listed",
           "backup_method_",
           "backup_applying_method_",
           "confirm_app_install_",
           "log_",
        ]

###############################################################################
#   Find used keys in python code                                             #
###############################################################################

# This regex matches « foo » in patterns like « m18n.n(  "foo" »
p1 = re.compile(r'm18n\.n\(\s*[\"\']([a-zA-Z0-9_]+)[\"\']')
p2 = re.compile(r'YunohostError\([\'\"]([a-zA-Z0-9_]+)[\'\"]')

python_files = glob.glob("../src/yunohost/*.py")
python_files.extend(glob.glob("../src/yunohost/utils/*.py"))
python_files.extend(glob.glob("../src/yunohost/data_migrations/*.py"))
python_files.append("../bin/yunohost")

python_keys = set()
for python_file in python_files:
    content = open(python_file).read()
    for match in p1.findall(content):
        python_keys.add(match)
    for match in p2.findall(content):
        python_keys.add(match)

###############################################################################
#   Find keys used in actionmap                                               #
###############################################################################

actionmap_keys = set()
actionmap = yaml.load(open("../data/actionsmap/yunohost.yml"))
for _, category in actionmap.items():
    if "actions" not in category.keys():
        continue
    for _, action in category["actions"].items():
        if "arguments" not in action.keys():
            continue
        for _, argument in action["arguments"].items():
            if "extra" not in argument.keys():
                continue
            if "password" in argument["extra"]:
                actionmap_keys.add(argument["extra"]["password"])
            if "ask" in argument["extra"]:
                actionmap_keys.add(argument["extra"]["ask"])
            if "comment" in argument["extra"]:
                actionmap_keys.add(argument["extra"]["comment"])
            if "pattern" in argument["extra"]:
                actionmap_keys.add(argument["extra"]["pattern"][1])
            if "help" in argument["extra"]:
                print argument["extra"]["help"]

actionmap_keys.add("admin_password")

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

used_keys = python_keys.union(actionmap_keys)

keys_used_but_not_defined = used_keys.difference(en_locale_keys)
keys_defined_but_not_used = en_locale_keys.difference(used_keys)

if len(keys_used_but_not_defined) != 0:
    print "> Error ! Those keys are used in some files but not defined :"
    for key in sorted(keys_used_but_not_defined):
        if any(key.startswith(i) for i in ignore):
            continue
        print "   - %s" % key

if len(keys_defined_but_not_used) != 0:
    print "> Warning ! Those keys are defined but seems unused :"
    for key in sorted(keys_defined_but_not_used):
        if any(key.startswith(i) for i in ignore):
            continue
        print "   - %s" % key


