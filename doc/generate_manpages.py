"""
Inspired by yunohost_completion.py (author: Christophe Vuillot)
=======

This script generates man pages for yunohost.
Pages are stored in OUTPUT_DIR
"""

import os
import yaml
import subprocess

from datetime import date
from collections import OrderedDict

from jinja2 import Template

template = Template('''\
.TH YunoHost "1" "{{ month }} {{ year }}" "YunoHost Collectif"
.SH NAME
YunoHost \\- yunohost server administration command
.SH SYNOPSIS
yunohost \\fI\\,CATEGORY\\/\\fR \\fI\\,COMMAND\\/\\fR [\\fI\\,SUBCOMMAND\\/\\fR] [\\fI\\,ARGUMENTS\\/\\fR]... [\\fI\\,OPTIONS\\/\\fR]...
.SH DESCRIPTION
usage: yunohost
{{ '{' }}{{ ",".join(categories) }}{{ '}' }}
\&...
[\\-h|\\-\\-help] [\\-\\-no\\-cache] [\\-\\-output\\-as {json,plain,none}] [\\-\\-debug]
[\\-\\-quiet] [\\-\\-timeout ==SUPPRESS==] [\\-\\-admin\\-password PASSWORD]
[\\-v|\\-\\-version]
.SS "optional arguments:"
.TP
\\fB\\-h\\fR, \\fB\\-\\-help\\fR
show this help message and exit
.SS "categories:"
.IP
{{ '{' }}{{ ",".join(categories) }}{{ '}' }}
{% for name, value in categories.items() %}
.TP
{{ name }}
{{ value["category_help"] }}
{% endfor %}
Manage debug logs
.SS "global arguments:"
.TP
\\fB\\-\\-no\\-cache\\fR
Don't use actions map cache
.TP
\\fB\\-\\-output\\-as\\fR {json,plain,none}
Output result in another format
.TP
\\fB\\-\\-debug\\fR
Log and print debug messages
.TP
\\fB\\-\\-quiet\\fR
Don't produce any output
.TP
\\fB\\-\\-timeout\\fR SECONDS
Number of seconds before this command will timeout
because it can't acquire the lock (meaning that
another command is currently running), by default
there is no timeout and the command will wait until it
can get the lock
.TP
\\fB\\-\\-admin\\-password\\fR PASSWORD
The admin password to use to authenticate
.TP
\\fB\\-v\\fR, \\fB\\-\\-version\\fR
Display YunoHost packages versions
{% for name, value in categories.items() %}
.SH YUNOHOST {{ name.upper() }}
usage: yunohost {{ name }} {{ '{' }}{{ ",".join(value["actions"].keys()) }}{{ '}' }}
\\&...
.SS "description:"
.IP
{{ value["category_help"] }}
{% for action, action_value in value["actions"].items() %}
.SS "yunohost {{ name }} {{ action }} \
{% for argument_name, argument_value in action_value.get("arguments", {}).items() %}\
{% set required=(not str(argument_name).startswith("-")) or argument_value.get("extra", {}).get("required", False) %}\
{% if not required %}[{% endif %}\
\\fI\\,{{ argument_name }}\\/\\fR{% if argument_value.get("full") %}|\\fI\\,{{ argument_value["full"] }}\\fR{% endif %}\
{% if str(argument_name).startswith("-") and not argument_value.get("action") == "store_true" %} {{ (argument_value.get("full", argument_name)).lstrip("-") }}{% endif %}\
{% if not required %}]{% endif %} \
{% endfor %}"
{{ action_value["action_help"] }}
{% if "arguments" in action_value %}
{% for argument_name, argument_value in action_value["arguments"].items() %}
.TP
\\fB{{ argument_name }}\\fR{% if argument_value.get("full") %}, \\fB{{ argument_value["full"] }}\\fR{% endif %}\
{% if str(argument_name).startswith("-") and not argument_value.get("action") == "store_true" %} \\fI\\,{{ (argument_value.get("full", argument_name)).lstrip("-") }}\\fR{% endif %}
{{ argument_value.get("help", "")}}
{% endfor %}
{% endif %}
{% endfor %}
{% endfor %}
''')


THIS_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACTIONSMAP_FILE = os.path.join(THIS_SCRIPT_DIR, '../data/actionsmap/yunohost.yml')
OUTPUT_DIR = "output/"


def ordered_yaml_load(stream):
    class OrderedLoader(yaml.Loader):
        pass
    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        lambda loader, node: OrderedDict(loader.construct_pairs(node)))
    return yaml.load(stream, OrderedLoader)


# creates output directory
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


# man pages of "yunohost *"
with open(ACTIONSMAP_FILE, 'r') as actionsmap:

    # Getting the dictionary containning what actions are possible per domain
    actionsmap = ordered_yaml_load(actionsmap)

    for i in actionsmap.keys():
        if i.startswith("_"):
            del actionsmap[i]

    today = date.today()

    result = template.render(
        month=today.strftime("%B"),
        year=today.year,
        categories=actionsmap,
        str=str,
    )

with open(os.path.join(OUTPUT_DIR, "yunohost"), "w") as output:
    output.write(result)
