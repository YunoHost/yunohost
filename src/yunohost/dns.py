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

from lexicon.client import Client
from lexicon.config import ConfigResolver

from moulinette import m18n, Moulinette
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import mkdir, read_yaml, write_to_yaml

from yunohost.domain import domain_list, _get_domain_settings
from yunohost.app import _parse_args_in_yunohost_format
from yunohost.utils.error import YunohostValidationError
from yunohost.utils.network import get_public_ip
from yunohost.log import is_unit_operation
from yunohost.hook import hook_callback

logger = getActionLogger("yunohost.domain")

REGISTRAR_SETTINGS_DIR = "/etc/yunohost/registrars"
REGISTRAR_LIST_PATH = "/usr/share/yunohost/other/registrar_list.yml"


def domain_dns_conf(domain):
    """
    Generate DNS configuration for a domain

    Keyword argument:
        domain -- Domain name

    """

    if domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

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

    domain_list_ = domain_list()["domains"]

    if parent_domain not in domain_list_:
        raise YunohostError("domain_name_unknown", domain=domain)

    out = []
    for domain in domain_list_:
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
    domains_settings = {domain: _get_domain_settings(domain)
                        for domain in [base_domain] + subdomains}

    base_dns_zone = domains_settings[base_domain].get("dns_zone")

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


def _get_registrar_settings(dns_zone):
    on_disk_settings = {}
    filepath = f"{REGISTRAR_SETTINGS_DIR}/{dns_zone}.yml"
    if os.path.exists(filepath) and os.path.isfile(filepath):
        on_disk_settings = read_yaml(filepath) or {}

    return on_disk_settings


def _set_registrar_settings(dns_zone, domain_registrar):
    if not os.path.exists(REGISTRAR_SETTINGS_DIR):
        mkdir(REGISTRAR_SETTINGS_DIR, mode=0o700)
    filepath = f"{REGISTRAR_SETTINGS_DIR}/{dns_zone}.yml"
    write_to_yaml(filepath, domain_registrar)


def domain_registrar_info(domain):

    dns_zone = _get_domain_settings(domain)["dns_zone"]
    registrar_info = _get_registrar_settings(dns_zone)
    if not registrar_info:
        raise YunohostValidationError("registrar_is_not_set", dns_zone=dns_zone)

    return registrar_info


def domain_registrar_catalog(registrar_name, full):
    registrars = read_yaml(REGISTRAR_LIST_PATH)

    if registrar_name:
        if registrar_name not in registrars.keys():
            raise YunohostValidationError("domain_registrar_unknown", registrar=registrar_name)
        else:
            return registrars[registrar_name]
    else:
        return registrars


def domain_registrar_set(domain, registrar, args):

    registrars = read_yaml(REGISTRAR_LIST_PATH)
    if registrar not in registrars.keys():
        raise YunohostValidationError("domain_registrar_unknown", registrar=registrar)

    parameters = registrars[registrar]
    ask_args = []
    for parameter in parameters:
        ask_args.append(
            {
                "name": parameter,
                "type": "string",
                "example": "",
                "default": "",
            }
        )
    args_dict = (
        {} if not args else dict(urllib.parse.parse_qsl(args, keep_blank_values=True))
    )
    parsed_answer_dict = _parse_args_in_yunohost_format(args_dict, ask_args)

    domain_registrar = {"name": registrar, "options": {}}
    for arg_name, arg_value_and_type in parsed_answer_dict.items():
        domain_registrar["options"][arg_name] = arg_value_and_type[0]

    dns_zone = _get_domain_settings(domain)["dns_zone"]
    _set_registrar_settings(dns_zone, domain_registrar)


@is_unit_operation()
def domain_registrar_push(operation_logger, domain):
    """
    Send DNS records to the previously-configured registrar of the domain.
    """
    # Generate the records
    if domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

    dns_conf = _build_dns_conf(domain)

    dns_zone = _get_domain_settings(domain)["dns_zone"]
    registrar_setting = _get_registrar_settings(dns_zone)

    if not registrar_setting:
        # FIXME add locales
        raise YunohostValidationError("registrar_is_not_set", domain=domain)

    # Flatten the DNS conf
    flatten_dns_conf = []
    for key in dns_conf:
        list_of_records = dns_conf[key]
        for record in list_of_records:
            # FIXME Lexicon does not support CAA records
            # See https://github.com/AnalogJ/lexicon/issues/282 and https://github.com/AnalogJ/lexicon/pull/371
            # They say it's trivial to implement it!
            # And yet, it is still not done/merged
            if record["type"] != "CAA":
                # Add .domain.tdl to the name entry
                record["name"] = "{}.{}".format(record["name"], domain)
                flatten_dns_conf.append(record)

    # Construct the base data structure to use lexicon's API.
    base_config = {
        "provider_name": registrar_setting["name"],
        "domain": domain,  # domain name
    }
    base_config[registrar_setting["name"]] = registrar_setting["options"]

    # Get types present in the generated records
    types = set()

    for record in flatten_dns_conf:
        types.add(record["type"])

    operation_logger.start()

    # Fetch all types present in the generated records
    distant_records = {}

    for key in types:
        record_config = {
            "action": "list",
            "type": key,
        }
        final_lexicon = (
            ConfigResolver()
            .with_dict(dict_object=base_config)
            .with_dict(dict_object=record_config)
        )
        # print('final_lexicon:', final_lexicon);
        client = Client(final_lexicon)
        distant_records[key] = client.execute()

    for key in types:
        for distant_record in distant_records[key]:
            logger.debug(f"distant_record: {distant_record}")
    for local_record in flatten_dns_conf:
        print("local_record:", local_record)

    # Push the records
    for record in flatten_dns_conf:
        # For each record, first check if one record exists for the same (type, name) couple
        it_exists = False
        # TODO do not push if local and distant records are exactly the same ?
        # is_the_same_record = False

        for distant_record in distant_records[record["type"]]:
            if (
                distant_record["type"] == record["type"]
                and distant_record["name"] == record["name"]
            ):
                it_exists = True
                # see previous TODO
                # if distant_record["ttl"] = ... and distant_record["name"] ...
                #     is_the_same_record = True

        # Finally, push the new record or update the existing one
        record_config = {
            "action": "update"
            if it_exists
            else "create",  # create, list, update, delete
            "type": record[
                "type"
            ],  # specify a type for record filtering, case sensitive in some cases.
            "name": record["name"],
            "content": record["value"],
            # FIXME Removed TTL, because it doesn't work with Gandi.
            # See https://github.com/AnalogJ/lexicon/issues/726 (similar issue)
            # But I think there is another issue with Gandi. Or I'm misusing the API...
            # "ttl": record["ttl"],
        }
        final_lexicon = (
            ConfigResolver()
            .with_dict(dict_object=base_config)
            .with_dict(dict_object=record_config)
        )
        client = Client(final_lexicon)
        print("pushed_record:", record_config, "→", end=" ")
        results = client.execute()
        print("results:", results)
        # print("Failed" if results == False else "Ok")


# def domain_config_fetch(domain, key, value):
