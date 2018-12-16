# -*- coding: utf-8 -*-

import requests
import json

from yunohost.utils.error import YunohostError


def yunopaste(data):

    paste_server = "https://paste.yunohost.org"

    try:
        r = requests.post("%s/documents" % paste_server, data=data, timeout=30)
    except Exception as e:
        raise YunohostError("Something wrong happened while trying to paste data on paste.yunohost.org : %s" % str(e), raw_msg=True)

    if r.status_code != 200:
        raise YunohostError("Something wrong happened while trying to paste data on paste.yunohost.org : %s, %s" % (r.status_code, r.text), raw_msg=True)

    try:
        url = json.loads(r.text)["key"]
    except:
        raise YunohostError("Uhoh, couldn't parse the answer from paste.yunohost.org : %s" % r.text, raw_msg=True)

    return "%s/raw/%s" % (paste_server, url)
