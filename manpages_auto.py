"""
Inspired by yunohost_completion.py (author: Christophe Vuillot)
=======

This script generates man pages for yunohost.
Pages are stored in OUTPUT_DIR
"""

import yaml
import os

ACTIONSMAP_FILE = '/usr/share/moulinette/actionsmap/yunohost.yml'
OUTPUT_DIR ="output/"

# creates output directory
os.system("mkdir "+ OUTPUT_DIR )


# man page of yunohost
cmd = "sudo help2man \" yunohost \" -o " + OUTPUT_DIR + "yunohost" 
print(cmd)
os.system(cmd)

# man pages of "yunohost *"
with open(ACTIONSMAP_FILE, 'r') as stream:

    # Getting the dictionary containning what actions are possible per domain
    OPTION_TREE = yaml.load(stream)
    DOMAINS = [str for str in OPTION_TREE.keys() if not str.startswith('_')]
    DOMAINS_STR = '"{}"'.format(' '.join(DOMAINS))
    ACTIONS_DICT = {}
    for domain in DOMAINS:
        ACTIONS = [str for str in OPTION_TREE[domain]['actions'].keys()
                   if not str.startswith('_')]
        ACTIONS_STR = '"{}"'.format(' '.join(ACTIONS))
        ACTIONS_DICT[domain] = ACTIONS_STR
        for action in ACTIONS:
            #print("yunohost", domain, action)
            cmd = "sudo help2man \" yunohost " + domain + "  "  + action + " --help \" -o " +  OUTPUT_DIR + "yunohost_" + domain+ "_" + action 
            print(cmd)
            os.system(cmd) 
