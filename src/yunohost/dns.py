# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_domain.py

    Manage domains
"""
import os
import re
import time
from collections import OrderedDict

from moulinette import m18n, Moulinette
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, write_to_file, read_toml

from yunohost.domain import domain_list, _assert_domain_exists, domain_config_get
from yunohost.utils.dns import dig, YNH_DYNDNS_DOMAINS
from yunohost.utils.error import YunohostValidationError
from yunohost.utils.network import get_public_ip
from yunohost.log import is_unit_operation
from yunohost.hook import hook_callback

logger = getActionLogger("yunohost.domain")

DOMAIN_REGISTRAR_LIST_PATH = "/usr/share/yunohost/other/registrar_list.toml"


def domain_dns_suggest(domain):
    """
    Generate DNS configuration for a domain

    Keyword argument:
        domain -- Domain name

    """

    _assert_domain_exists(domain)

    dns_conf = _build_dns_conf(domain)

    result = ""

    result += "; Basic ipv4/ipv6 records"
    for record in dns_conf["basic"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    result += "\n\n"
    result += "; XMPP"
    for record in dns_conf["xmpp"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    result += "\n\n"
    result += "; Mail"
    for record in dns_conf["mail"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)
    result += "\n\n"

    result += "; Extra"
    for record in dns_conf["extra"]:
        result += "\n{name} {ttl} IN {type} {value}".format(**record)

    for name, record_list in dns_conf.items():
        if name not in ("basic", "xmpp", "mail", "extra") and record_list:
            result += "\n\n"
            result += "; " + name
            for record in record_list:
                result += "\n{name} {ttl} IN {type} {value}".format(**record)

    if Moulinette.interface.type == "cli":
        # FIXME Update this to point to our "dns push" doc
        logger.info(m18n.n("domain_dns_conf_is_just_a_recommendation"))

    return result


def _list_subdomains_of(parent_domain):

    _assert_domain_exists(parent_domain)

    out = []
    for domain in domain_list()["domains"]:
        if domain.endswith(f".{parent_domain}"):
            out.append(domain)

    return out


def _build_dns_conf(base_domain):
    """
    Internal function that will returns a data structure containing the needed
    information to generate/adapt the dns configuration

    Arguments:
        domains -- List of a domain and its subdomains

    The returned datastructure will have the following form:
    {
        "basic": [
            # if ipv4 available
            {"type": "A", "name": "@", "value": "123.123.123.123", "ttl": 3600},
            # if ipv6 available
            {"type": "AAAA", "name": "@", "value": "valid-ipv6", "ttl": 3600},
        ],
        "xmpp": [
            {"type": "SRV", "name": "_xmpp-client._tcp", "value": "0 5 5222 domain.tld.", "ttl": 3600},
            {"type": "SRV", "name": "_xmpp-server._tcp", "value": "0 5 5269 domain.tld.", "ttl": 3600},
            {"type": "CNAME", "name": "muc", "value": "@", "ttl": 3600},
            {"type": "CNAME", "name": "pubsub", "value": "@", "ttl": 3600},
            {"type": "CNAME", "name": "vjud", "value": "@", "ttl": 3600}
            {"type": "CNAME", "name": "xmpp-upload", "value": "@", "ttl": 3600}
        ],
        "mail": [
            {"type": "MX", "name": "@", "value": "10 domain.tld.", "ttl": 3600},
            {"type": "TXT", "name": "@", "value": "\"v=spf1 a mx ip4:123.123.123.123 ipv6:valid-ipv6 -all\"", "ttl": 3600 },
            {"type": "TXT", "name": "mail._domainkey", "value": "\"v=DKIM1; k=rsa; p=some-super-long-key\"", "ttl": 3600},
            {"type": "TXT", "name": "_dmarc", "value": "\"v=DMARC1; p=none\"", "ttl": 3600}
        ],
        "extra": [
            # if ipv4 available
            {"type": "A", "name": "*", "value": "123.123.123.123", "ttl": 3600},
            # if ipv6 available
            {"type": "AAAA", "name": "*", "value": "valid-ipv6", "ttl": 3600},
            {"type": "CAA", "name": "@", "value": "128 issue \"letsencrypt.org\"", "ttl": 3600},
        ],
        "example_of_a_custom_rule": [
            {"type": "SRV", "name": "_matrix", "value": "domain.tld.", "ttl": 3600}
        ],
    }
    """

    basic = []
    mail = []
    xmpp = []
    extra = []
    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    subdomains = _list_subdomains_of(base_domain)
    domains_settings = {domain: domain_config_get(domain)
                        for domain in [base_domain] + subdomains}

    base_dns_zone = _get_dns_zone_for_domain(base_domain)

    for domain, settings in domains_settings.items():

        #   Domain           #   Base DNS zone   # Basename  #  Suffix  #
        # ------------------ # ----------------- # --------- # -------- #
        #         domain.tld #       domain.tld  #        @  #          #
        #     sub.domain.tld #       domain.tld  #      sub  # .sub     #
        # foo.sub.domain.tld #       domain.tld  #  foo.sub  # .foo.sub #
        #     sub.domain.tld #   sub.domain.tld  #        @  #          #
        # foo.sub.domain.tld #   sub.domain.tld  #      foo  # .foo     #

        # FIXME: shouldn't the basename just be based on the dns_zone setting of this domain ?
        basename = domain.replace(f"{base_dns_zone}", "").rstrip(".") or "@"
        suffix = f".{basename}" if basename != "@" else ""

        ttl = settings["ttl"]

        ###########################
        # Basic ipv4/ipv6 records #
        ###########################
        if ipv4:
            basic.append([basename, ttl, "A", ipv4])

        if ipv6:
            basic.append([basename, ttl, "AAAA", ipv6])
        # TODO
        # elif include_empty_AAAA_if_no_ipv6:
        #     basic.append(["@", ttl, "AAAA", None])

        #########
        # Email #
        #########
        if settings["mail_in"]:
            mail.append([basename, ttl, "MX", f"10 {domain}."])

        if settings["mail_out"]:
            mail.append([basename, ttl, "TXT", '"v=spf1 a mx -all"'])

            # DKIM/DMARC record
            dkim_host, dkim_publickey = _get_DKIM(domain)

            if dkim_host:
                mail += [
                    [f"{dkim_host}{suffix}", ttl, "TXT", dkim_publickey],
                    [f"_dmarc{suffix}", ttl, "TXT", '"v=DMARC1; p=none"'],
                ]

        ########
        # XMPP #
        ########
        if settings["xmpp"]:
            xmpp += [
                [
                    f"_xmpp-client._tcp{suffix}",
                    ttl,
                    "SRV",
                    f"0 5 5222 {domain}.",
                ],
                [
                    f"_xmpp-server._tcp{suffix}",
                    ttl,
                    "SRV",
                    f"0 5 5269 {domain}.",
                ],
                [f"muc{suffix}", ttl, "CNAME", basename],
                [f"pubsub{suffix}", ttl, "CNAME", basename],
                [f"vjud{suffix}", ttl, "CNAME", basename],
                [f"xmpp-upload{suffix}", ttl, "CNAME", basename],
            ]

        #########
        # Extra #
        #########

        if ipv4:
            extra.append([f"*{suffix}", ttl, "A", ipv4])

        if ipv6:
            extra.append([f"*{suffix}", ttl, "AAAA", ipv6])
        # TODO
        # elif include_empty_AAAA_if_no_ipv6:
        #     extra.append(["*", ttl, "AAAA", None])

        extra.append([basename, ttl, "CAA", '128 issue "letsencrypt.org"'])

        ####################
        # Standard records #
        ####################

    records = {
        "basic": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in basic
        ],
        "xmpp": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in xmpp
        ],
        "mail": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in mail
        ],
        "extra": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in extra
        ],
    }

    ##################
    # Custom records #
    ##################

    # Defined by custom hooks ships in apps for example ...

    hook_results = hook_callback("custom_dns_rules", args=[base_domain])
    for hook_name, results in hook_results.items():
        #
        # There can be multiple results per hook name, so results look like
        # {'/some/path/to/hook1':
        #       { 'state': 'succeed',
        #         'stdreturn': [{'type': 'SRV',
        #                        'name': 'stuff.foo.bar.',
        #                        'value': 'yoloswag',
        #                        'ttl': 3600}]
        #       },
        #  '/some/path/to/hook2':
        #       { ... },
        #  [...]
        #
        # Loop over the sub-results
        custom_records = [
            v["stdreturn"] for v in results.values() if v and v["stdreturn"]
        ]

        records[hook_name] = []
        for record_list in custom_records:
            # Check that record_list is indeed a list of dict
            # with the required keys
            if (
                not isinstance(record_list, list)
                or any(not isinstance(record, dict) for record in record_list)
                or any(
                    key not in record
                    for record in record_list
                    for key in ["name", "ttl", "type", "value"]
                )
            ):
                # Display an error, mainly for app packagers trying to implement a hook
                logger.warning(
                    "Ignored custom record from hook '%s' because the data is not a *list* of dict with keys name, ttl, type and value. Raw data : %s"
                    % (hook_name, record_list)
                )
                continue

            records[hook_name].extend(record_list)

    return records


def _get_DKIM(domain):
    DKIM_file = "/etc/dkim/{domain}.mail.txt".format(domain=domain)

    if not os.path.isfile(DKIM_file):
        return (None, None)

    with open(DKIM_file) as f:
        dkim_content = f.read()

    # Gotta manage two formats :
    #
    # Legacy
    # -----
    #
    # mail._domainkey IN      TXT     ( "v=DKIM1; k=rsa; "
    #           "p=<theDKIMpublicKey>" )
    #
    # New
    # ------
    #
    # mail._domainkey IN  TXT ( "v=DKIM1; h=sha256; k=rsa; "
    #           "p=<theDKIMpublicKey>" )

    is_legacy_format = " h=sha256; " not in dkim_content

    # Legacy DKIM format
    if is_legacy_format:
        dkim = re.match(
            (
                r"^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+"
                r'[^"]*"v=(?P<v>[^";]+);'
                r'[\s"]*k=(?P<k>[^";]+);'
                r'[\s"]*p=(?P<p>[^";]+)'
            ),
            dkim_content,
            re.M | re.S,
        )
    else:
        dkim = re.match(
            (
                r"^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+"
                r'[^"]*"v=(?P<v>[^";]+);'
                r'[\s"]*h=(?P<h>[^";]+);'
                r'[\s"]*k=(?P<k>[^";]+);'
                r'[\s"]*p=(?P<p>[^";]+)'
            ),
            dkim_content,
            re.M | re.S,
        )

    if not dkim:
        return (None, None)

    if is_legacy_format:
        return (
            dkim.group("host"),
            '"v={v}; k={k}; p={p}"'.format(
                v=dkim.group("v"), k=dkim.group("k"), p=dkim.group("p")
            ),
        )
    else:
        return (
            dkim.group("host"),
            '"v={v}; h={h}; k={k}; p={p}"'.format(
                v=dkim.group("v"),
                h=dkim.group("h"),
                k=dkim.group("k"),
                p=dkim.group("p"),
            ),
        )


def _get_dns_zone_for_domain(domain):
    """
    Get the DNS zone of a domain

    Keyword arguments:
        domain -- The domain name

    """

    # First, check if domain is a nohost.me / noho.st / ynh.fr
    # This is mainly meant to speed up things for "dyndns update"
    # ... otherwise we end up constantly doing a bunch of dig requests
    for ynh_dyndns_domain in YNH_DYNDNS_DOMAINS:
        if domain.endswith('.' + ynh_dyndns_domain):
            return ynh_dyndns_domain

    # Check cache
    cache_folder = "/var/cache/yunohost/dns_zones"
    cache_file = f"{cache_folder}/{domain}"
    cache_duration = 3600  # one hour
    if (
        os.path.exists(cache_file)
        and abs(os.path.getctime(cache_file) - time.time()) < cache_duration
    ):
        dns_zone = read_file(cache_file).strip()
        if dns_zone:
            return dns_zone

    # Check cache for parent domain
    # This is another strick to try to prevent this function from being
    # a bottleneck on system with 1 main domain + 10ish subdomains
    # when building the dns conf for the main domain (which will call domain_config_get, etc...)
    parent_domain = domain.split(".", 1)[1]
    if parent_domain in domain_list()["domains"]:
        parent_cache_file = f"{cache_folder}/{parent_domain}"
        if (
            os.path.exists(parent_cache_file)
            and abs(os.path.getctime(parent_cache_file) - time.time()) < cache_duration
        ):
            dns_zone = read_file(parent_cache_file).strip()
            if dns_zone:
                return dns_zone

    # For foo.bar.baz.gni we want to scan all the parent domains
    # (including the domain itself)
    # foo.bar.baz.gni
    #     bar.baz.gni
    #         baz.gni
    #             gni
    # Until we find the first one that has a NS record
    parent_list = [domain.split(".", i)[-1]
                   for i, _ in enumerate(domain.split("."))]

    for parent in parent_list:

        # Check if there's a NS record for that domain
        answer = dig(parent, rdtype="NS", full_answers=True, resolvers="force_external")
        if answer[0] == "ok":
            os.system(f"mkdir -p {cache_folder}")
            write_to_file(cache_file, parent)
            return parent

    logger.warning(f"Could not identify the dns_zone for domain {domain}, returning {parent_list[-1]}")
    return parent_list[-1]


def _get_registrar_config_section(domain):

    from lexicon.providers.auto import _relevant_provider_for_domain

    registrar_infos = {}

    dns_zone = _get_dns_zone_for_domain(domain)

    # If parent domain exists in yunohost
    parent_domain = domain.split(".", 1)[1]
    if parent_domain in domain_list()["domains"]:
        registrar_infos["explanation"] = OrderedDict({
            "type": "alert",
            "style": "info",
            "ask": f"This domain is a subdomain of {parent_domain}. DNS registrar configuration should be managed in {parent_domain}'s configuration panel.",  # FIXME: i18n
            "value": None
        })
        return OrderedDict(registrar_infos)

    # TODO big project, integrate yunohost's dynette as a registrar-like provider
    # TODO big project, integrate other dyndns providers such as netlib.re, or cf the list of dyndns providers supported by cloudron...
    if dns_zone in YNH_DYNDNS_DOMAINS:
        registrar_infos["explanation"] = OrderedDict({
            "type": "alert",
            "style": "success",
            "ask": "This domain is a nohost.me / nohost.st / ynh.fr and its DNS configuration is therefore automatically handled by Yunohost.",  # FIXME: i18n
            "value": "yunohost"
        })
        return OrderedDict(registrar_infos)

    try:
        registrar = _relevant_provider_for_domain(dns_zone)[0]
    except ValueError:
        registrar_infos["explanation"] = OrderedDict({
            "type": "alert",
            "style": "warning",
            "ask": "YunoHost could not automatically detect the registrar handling this domain. You should manually configure your DNS records following the documentation at https://yunohost.org/dns.",  # FIXME : i18n
            "value": None
        })
    else:

        registrar_infos["explanation"] = OrderedDict({
            "type": "alert",
            "style": "info",
            "ask": f"YunoHost automatically detected that this domain is handled by the registrar **{registrar}**. If you want, YunoHost will automatically configure this DNS zone, if you provide it with the following informations. You can also manually configure your DNS records following the documentation as https://yunohost.org/dns.",  # FIXME: i18n
            "value": registrar
        })
        # TODO : add a help tip with the link to the registar's API doc (c.f. Lexicon's README)
        registrar_list = read_toml(DOMAIN_REGISTRAR_LIST_PATH)
        registrar_infos.update(registrar_list[registrar])

    return OrderedDict(registrar_infos)


@is_unit_operation()
def domain_registrar_push(operation_logger, domain, dry_run=False):
    """
    Send DNS records to the previously-configured registrar of the domain.
    """

    from lexicon.client import Client as LexiconClient
    from lexicon.config import ConfigResolver as LexiconConfigResolver

    _assert_domain_exists(domain)

    registrar_settings = domain_config_get(domain, key='', full=True)

    if not registrar_settings:
        raise YunohostValidationError("registrar_is_not_set", domain=domain)

    # Convert the generated conf into a format that matches what we'll fetch using the API
    # Makes it easier to compare "wanted records" with "current records on remote"
    dns_conf = []
    for records in _build_dns_conf(domain).values():
        for record in records:

            # Make sure we got "absolute" values instead of @
            name = f"{record['name']}.{domain}" if record["name"] != "@" else f".{domain}"
            type_ = record["type"]
            content = record["value"]

            if content == "@" and record["type"] == "CNAME":
                content = domain + "."

            dns_conf.append({
                "name": name,
                "type": type_,
                "ttl": record["ttl"],
                "content": content
            })

    # FIXME Lexicon does not support CAA records
    # See https://github.com/AnalogJ/lexicon/issues/282 and https://github.com/AnalogJ/lexicon/pull/371
    # They say it's trivial to implement it!
    # And yet, it is still not done/merged
    dns_conf = [record for record in dns_conf if record["type"] != "CAA"]

    # Construct the base data structure to use lexicon's API.
    base_config = {
        "provider_name": registrar_settings["name"],
        "domain": domain,
        registrar_settings["name"]: registrar_settings["options"]
    }

    # Fetch all types present in the generated records
    current_remote_records = []

    # Get unique types present in the generated records
    types = ["A", "AAAA", "MX", "TXT", "CNAME", "SRV"]

    for key in types:
        print("fetcing type: " + key)
        fetch_records_for_type = {
            "action": "list",
            "type": key,
        }
        query = (
            LexiconConfigResolver()
            .with_dict(dict_object=base_config)
            .with_dict(dict_object=fetch_records_for_type)
        )
        current_remote_records.extend(LexiconClient(query).execute())

    changes = {}

    if dry_run:
        return {"current_records": current_remote_records, "dns_conf": dns_conf, "changes": changes}

    operation_logger.start()

    # Push the records
    for record in dns_conf:

        # For each record, first check if one record exists for the same (type, name) couple
        # TODO do not push if local and distant records are exactly the same ?
        type_and_name = (record["type"], record["name"])
        already_exists = any((r["type"], r["name"]) == type_and_name
                             for r in current_remote_records)

        # Finally, push the new record or update the existing one
        record_to_push = {
            "action": "update" if already_exists else "create",
            "type": record["type"],
            "name": record["name"],
            "content": record["value"],
            "ttl": record["ttl"],
        }

        # FIXME Removed TTL, because it doesn't work with Gandi.
        # See https://github.com/AnalogJ/lexicon/issues/726 (similar issue)
        # But I think there is another issue with Gandi. Or I'm misusing the API...
        if base_config["provider_name"] == "gandi":
            del record_to_push["ttl"]

        print("pushed_record:", record_to_push)


        # FIXME FIXME FIXME: if a matching record already exists multiple time,
        # the current code crashes (at least on OVH) ... we need to provide a specific identifier to update
        query = (
            LexiconConfigResolver()
            .with_dict(dict_object=base_config)
            .with_dict(dict_object=record_to_push)
        )

        print(query)
        print(query.__dict__)
        results = LexiconClient(query).execute()
        print("results:", results)
        # print("Failed" if results == False else "Ok")

        # FIXME FIXME FIXME : if one create / update crash, it shouldn't block everything

        # FIXME : is it possible to push multiple create/update request at once ?


# def domain_config_fetch(domain, key, value):
