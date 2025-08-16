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

from ..domain import _get_maindomain, domain_list
from ..utils.error import YunohostError
from ..utils.network import get_public_ip

logger = logging.getLogger("yunohost.utils.yunopaste")


def yunopaste(data: str) -> str:
    paste_server = "https://paste.yunohost.org"

    try:
        data = anonymize(data)
    except Exception as err:
        logger.warning(
            "For some reason, YunoHost was not able to anonymize the pasted data. "
            "Sorry about that. Be careful about sharing the link, as it may contain "
            f"somewhat private infos like domain names or IP addresses. Error: {err}"
        )

    datab = data.encode()

    try:
        response = requests.post(f"{paste_server}/documents", data=datab, timeout=30)
    except Exception as err:
        raise YunohostError(
            "Something wrong happened while trying to paste data on "
            f"paste.yunohost.org: {err}",
            raw_msg=True,
        )

    if response.status_code != 200:
        raise YunohostError(
            "Something wrong happened while trying to paste data on "
            f"paste.yunohost.org: {response.status_code}, {response.text}",
            raw_msg=True,
        )

    try:
        url = json.loads(response.text)["key"]
    except Exception:
        raise YunohostError(
            f"Uhoh, couldn't parse the answer from paste.yunohost.org: {response.text}",
            raw_msg=True,
        )

    return f"{paste_server}/raw/{url}"


def anonymize(data: str) -> str:
    def anonymize_domain(data: str, domain: str, redact: str) -> str:
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
    domains: list[str] = domain_list()["domains"]  # type: ignore[assignment]
    domains = sorted(domains, key=lambda d: len(d))

    for count, domain in enumerate(domains, start=2):
        if domain not in data:
            continue
        data = anonymize_domain(data, domain, f"domain{count}.tld")

    # We also want to anonymize the ips
    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    if ipv4:
        data = data.replace(str(ipv4), "xx.xx.xx.xx")

    if ipv6:
        data = data.replace(str(ipv6), "xx:xx:xx:xx:xx:xx")

    return data
