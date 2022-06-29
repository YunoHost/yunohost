# -*- coding: utf-8 -*-

import requests
import json
import logging
import re

from yunohost.domain import _get_maindomain, domain_list
from yunohost.utils.error import YunohostError
from yunohost.utils.network import is_ip_local

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

    ipv4regex = r"[12]?\d{1,2}\.[12]?\d{1,2}\.[12]?\d{1,2}\.[12]?\d{1,2}"
    ipv6regex = r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    ipsv4 = re.findall(ipv4regex, data) 
    ipsv6 = re.findall(ipv6regex, data)

    # Filter local IPs
    ipsv4 = filter(lambda x: not is_ip_local(x), ipsv4)

    def gen_anonymized_ip(length,counter,sep='.'):
        # Generate anonymized IPs like "xx.xx.xx.yy"
        chars = "xy"
        binary_str = format(counter, 'b')
        indexes = [int(x) for x in binary_str]
        if len(indexes)<length:
            indexes = [0 for x in range(length-len(indexes))] + indexes
        return sep.join([ chars[x]*2 for x in indexes ])

    counter = 0
    for ip in ipsv4:
        data = data.replace(str(ip),gen_anonymized_ip(4,counter))
        counter +=1

    counter = 0
    for ip in ipsv6:
        data = data.replace(str(ip),gen_anonymized_ip(6,counter,sep=":"))
        counter +=1

    return data
