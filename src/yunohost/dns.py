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
    domains_settings = {domain: domain_config_get(domain, export=True)
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
        registrar_infos["registrar"] = OrderedDict({
            "type": "alert",
            "style": "info",
            "ask": f"This domain is a subdomain of {parent_domain}. DNS registrar configuration should be managed in {parent_domain}'s configuration panel.",  # FIXME: i18n
            "value": None
        })
        return OrderedDict(registrar_infos)

    # TODO big project, integrate yunohost's dynette as a registrar-like provider
    # TODO big project, integrate other dyndns providers such as netlib.re, or cf the list of dyndns providers supported by cloudron...
    if dns_zone in YNH_DYNDNS_DOMAINS:
        registrar_infos["registrar"] = OrderedDict({
            "type": "alert",
            "style": "success",
            "ask": "This domain is a nohost.me / nohost.st / ynh.fr and its DNS configuration is therefore automatically handled by Yunohost.",  # FIXME: i18n
            "value": "yunohost"
        })
        return OrderedDict(registrar_infos)

    try:
        registrar = _relevant_provider_for_domain(dns_zone)[0]
    except ValueError:
        registrar_infos["registrar"] = OrderedDict({
            "type": "alert",
            "style": "warning",
            "ask": "YunoHost could not automatically detect the registrar handling this domain. You should manually configure your DNS records following the documentation at https://yunohost.org/dns.",  # FIXME : i18n
            "value": None
        })
    else:

        registrar_infos["registrar"] = OrderedDict({
            "type": "alert",
            "style": "info",
            "ask": f"YunoHost automatically detected that this domain is handled by the registrar **{registrar}**. If you want, YunoHost will automatically configure this DNS zone, if you provide it with the appropriate API credentials. You can also manually configure your DNS records following the documentation as https://yunohost.org/dns.",  # FIXME: i18n
            "value": registrar
        })
        # TODO : add a help tip with the link to the registar's API doc (c.f. Lexicon's README)
        registrar_list = read_toml(DOMAIN_REGISTRAR_LIST_PATH)
        registrar_credentials = registrar_list[registrar]
        for credential, infos in registrar_credentials.items():
            infos["default"] = infos.get("default", "")
            infos["optional"] = infos.get("optional", "False")
        registrar_infos.update(registrar_credentials)

    return OrderedDict(registrar_infos)


@is_unit_operation()
def domain_registrar_push(operation_logger, domain, dry_run=False):
    """
    Send DNS records to the previously-configured registrar of the domain.
    """

    from lexicon.client import Client as LexiconClient
    from lexicon.config import ConfigResolver as LexiconConfigResolver

    _assert_domain_exists(domain)

    settings = domain_config_get(domain, key='dns.registrar')

    registrar_id = settings["dns.registrar.registrar"].get("value")

    if not registrar_id or registrar_id == "yunohost":
        raise YunohostValidationError("registrar_push_not_applicable", domain=domain)

    registrar_credentials = {
            k.split('.')[-1]: v["value"]
            for k, v in settings.items()
            if k != "dns.registrar.registar"
    }

    if not all(registrar_credentials.values()):
        raise YunohostValidationError("registrar_is_not_configured", domain=domain)

    # Convert the generated conf into a format that matches what we'll fetch using the API
    # Makes it easier to compare "wanted records" with "current records on remote"
    wanted_records = []
    for records in _build_dns_conf(domain).values():
        for record in records:

            # Make sure we got "absolute" values instead of @
            name = f"{record['name']}.{domain}" if record["name"] != "@" else f".{domain}"
            type_ = record["type"]
            content = record["value"]

            if content == "@" and record["type"] == "CNAME":
                content = domain + "."

            wanted_records.append({
                "name": name,
                "type": type_,
                "ttl": record["ttl"],
                "content": content
            })

    # FIXME Lexicon does not support CAA records
    # See https://github.com/AnalogJ/lexicon/issues/282 and https://github.com/AnalogJ/lexicon/pull/371
    # They say it's trivial to implement it!
    # And yet, it is still not done/merged
    wanted_records = [record for record in wanted_records if record["type"] != "CAA"]

    # Construct the base data structure to use lexicon's API.

    base_config = {
        "provider_name": registrar_id,
        "domain": domain,
        registrar_id: registrar_credentials
    }

    # Fetch all types present in the generated records
    current_records = []

    # Get unique types present in the generated records
    types = ["A", "AAAA", "MX", "TXT", "CNAME", "SRV"]

    for key in types:
        print("fetching type: " + key)
        fetch_records_for_type = {
            "action": "list",
            "type": key,
        }
        query = (
            LexiconConfigResolver()
            .with_dict(dict_object=base_config)
            .with_dict(dict_object=fetch_records_for_type)
        )
        current_records.extend(LexiconClient(query).execute())

    # Ignore records which are for a higher-level domain
    # i.e. we don't care about the records for domain.tld when pushing yuno.domain.tld
    current_records = [r for r in current_records if r['name'].endswith(f'.{domain}')]

    # Step 0 : Get the list of unique (type, name)
    # And compare the current and wanted records
    #
    # i.e. we want this kind of stuff:
    #                         wanted             current
    # (A, .domain.tld)        1.2.3.4           1.2.3.4
    # (A, www.domain.tld)     1.2.3.4           5.6.7.8
    # (A, foobar.domain.tld)  1.2.3.4
    # (AAAA, .domain.tld)                      2001::abcd
    # (MX, .domain.tld)      10 domain.tld     [10 mx1.ovh.net, 20 mx2.ovh.net]
    # (TXT, .domain.tld)     "v=spf1 ..."      ["v=spf1", "foobar"]
    # (SRV, .domain.tld)                       0 5 5269 domain.tld
    changes = {"delete": [], "update": [], "create": []}
    type_and_names = set([(r["type"], r["name"]) for r in current_records + wanted_records])
    comparison = {type_and_name: {"current": [], "wanted": []} for type_and_name in type_and_names}

    for record in current_records:
        comparison[(record["type"], record["name"])]["current"].append(record)

    for record in wanted_records:
        comparison[(record["type"], record["name"])]["wanted"].append(record)

    for type_and_name, records in comparison.items():
        #
        # Step 1 : compute a first "diff" where we remove records which are the same on both sides
        # NB / FIXME? : in all this we ignore the TTL value for now...
        #
        diff = {"current": [], "wanted": []}
        current_contents = [r["content"] for r in records["current"]]
        wanted_contents = [r["content"] for r in records["wanted"]]

        print("--------")
        print(type_and_name)
        print(current_contents)
        print(wanted_contents)

        for record in records["current"]:
            if record["content"] not in wanted_contents:
                diff["current"].append(record)
        for record in records["wanted"]:
            if record["content"] not in current_contents:
                diff["wanted"].append(record)

        #
        # Step 2 : simple case: 0 or 1 record on one side, 0 or 1 on the other
        #           -> either nothing do (0/0) or a creation (0/1) or a deletion (1/0), or an update (1/1)
        #
        if len(diff["current"]) == 0 and len(diff["wanted"]) == 0:
            # No diff, nothing to do
            continue

        if len(diff["current"]) == 1 and len(diff["wanted"]) == 0:
            changes["delete"].append(diff["current"][0])
            continue

        if len(diff["current"]) == 0 and len(diff["wanted"]) == 1:
            changes["create"].append(diff["wanted"][0])
            continue
        #
        if len(diff["current"]) == 1 and len(diff["wanted"]) == 1:
            diff["current"][0]["content"] = diff["wanted"][0]["content"]
            changes["update"].append(diff["current"][0])
            continue

        #
        # Step 3 : N record on one side, M on the other, watdo # FIXME
        #
        for record in diff["wanted"]:
            print(f"Dunno watdo with {type_and_name} : {record['content']}")
        for record in diff["current"]:
            print(f"Dunno watdo with {type_and_name} : {record['content']}")


    if dry_run:
        return {"changes": changes}

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
