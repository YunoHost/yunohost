#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
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

import json
import logging
import re

import requests

from yunohost.domain import _get_maindomain, domain_list
from yunohost.utils.error import YunohostError
from yunohost.utils.network import get_public_ip

logger = logging.getLogger("yunohost.utils.yunopaste")


def yunopaste(data):
    paste_server = "https://paste.yunohost.org"

    try:
        data = anonymize(data)
    except Exception as e:
        logger.warning(
            "For some reason, YunoHost was not able to anonymize the pasted data. Sorry about that. Be careful about sharing the link, as it may contain somewhat private infos like domain names or IP addresses. Error: %s"
            % e
        )

    data = data.encode()

    try:
        r = requests.post("%s/documents" % paste_server, data=data, timeout=30)
    except Exception as e:
        raise YunohostError(
            "Something wrong happened while trying to paste data on paste.yunohost.org : %s"
            % str(e),
            raw_msg=True,
        )

    if r.status_code != 200:
        raise YunohostError(
            "Something wrong happened while trying to paste data on paste.yunohost.org : %s, %s"
            % (r.status_code, r.text),
            raw_msg=True,
        )

    try:
        url = json.loads(r.text)["key"]
    except Exception:
        raise YunohostError(
            "Uhoh, couldn't parse the answer from paste.yunohost.org : %s" % r.text,
            raw_msg=True,
        )

    return "{}/raw/{}".format(paste_server, url)


def anonymize(data):
    def anonymize_domain(data, domain, redact):
        data = data.replace(domain, redact)
        # This stuff appears sometimes because some folder in
        # /var/lib/metronome/ have some folders named this way
        data = data.replace(domain.replace(".", "%2e"), redact.replace(".", "%2e"))
        return data

    data = re.sub("\nstarted_by: .*\n", "\nstarted_by: ******\n", data)

    # First, let's replace every occurence of the main domain by "domain.tld"
    # This should cover a good fraction of the info leaked
    main_domain = _get_maindomain()
    data = anonymize_domain(data, main_domain, "maindomain.tld")

    # Next, let's replace other domains. We do this in increasing lengths,
    # because e.g. knowing that the domain is a sub-domain of another domain may
    # still be informative.
    # So e.g. if there's jitsi.foobar.com as a subdomain of foobar.com, it may
    # be interesting to know that the log is about a supposedly dedicated domain
    # for jisti (hopefully this explanation make sense).
    domains = domain_list()["domains"]
    domains = sorted(domains, key=lambda d: len(d))

    count = 2
    for domain in domains:
        if domain not in data:
            continue
        data = anonymize_domain(data, domain, "domain%s.tld" % count)
        count += 1

    # We also want to anonymize the ips
    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    if ipv4:
        data = data.replace(str(ipv4), "xx.xx.xx.xx")

    if ipv6:
        data = data.replace(str(ipv6), "xx:xx:xx:xx:xx:xx")

    return data
