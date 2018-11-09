# -*- coding: utf-8 -*-

import requests
import json
import errno

from moulinette.core import MoulinetteError

def yunopaste(data):

    paste_server = "https://paste.yunohost.org"

    try:
        r = requests.post("%s/documents" % paste_server, data=data, timeout=30)
    except Exception as e:
        raise MoulinetteError("Something wrong happened while trying to paste data on paste.yunohost.org : %s" % str(e))

    if r.status_code != 200:
        raise MoulinetteError("Something wrong happened while trying to paste data on paste.yunohost.org : %s, %s" % (r.status_code, r.text))

    try:
        url = json.loads(r.text)["key"]
    except:
        raise MoulinetteError("Uhoh, couldn't parse the answer from paste.yunohost.org : %s" % r.text)

    return "%s/raw/%s" % (paste_server, url)
