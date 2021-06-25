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
import sys
import yaml
import functools

from lexicon.client import Client
from lexicon.config import ConfigResolver

from moulinette import m18n, msettings, msignals
from moulinette.core import MoulinetteError
from yunohost.utils.error import YunohostError, YunohostValidationError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import write_to_file

from yunohost.app import (
    app_ssowatconf,
    _installed_apps,
    _get_app_settings,
    _get_conflicting_apps,
    _parse_args_in_yunohost_format,
)
from yunohost.regenconf import regen_conf, _force_clear_hashes, _process_regen_conf
from yunohost.utils.network import get_public_ip
from yunohost.utils.dns import get_dns_zone_from_domain
from yunohost.log import is_unit_operation
from yunohost.hook import hook_callback

logger = getActionLogger("yunohost.domain")

DOMAIN_SETTINGS_DIR = "/etc/yunohost/domains"
REGISTRAR_SETTINGS_DIR = "/etc/yunohost/registrars"
REGISTRAR_LIST_PATH = "/usr/share/yunohost/other/registrar_list.yml"


def domain_list(exclude_subdomains=False):
    """
    List domains

    Keyword argument:
        exclude_subdomains -- Filter out domains that are subdomains of other declared domains

    """
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()
    result = [
        entry["virtualdomain"][0]
        for entry in ldap.search(
            "ou=domains,dc=yunohost,dc=org", "virtualdomain=*", ["virtualdomain"]
        )
    ]

    result_list = []
    for domain in result:
        if exclude_subdomains:
            parent_domain = domain.split(".", 1)[1]
            if parent_domain in result:
                continue

        result_list.append(domain)

    def cmp_domain(domain):
        # Keep the main part of the domain and the extension together
        # eg: this.is.an.example.com -> ['example.com', 'an', 'is', 'this']
        domain = domain.split(".")
        domain[-1] = domain[-2] + domain.pop()
        domain = list(reversed(domain))
        return domain

    result_list = sorted(result_list, key=cmp_domain)

    return {"domains": result_list, "main": _get_maindomain()}


@is_unit_operation()
def domain_add(operation_logger, domain, dyndns=False):
    """
    Create a custom domain

    Keyword argument:
        domain -- Domain name to add
        dyndns -- Subscribe to DynDNS

    """
    from yunohost.hook import hook_callback
    from yunohost.app import app_ssowatconf
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.certificate import _certificate_install_selfsigned

    if domain.startswith("xmpp-upload."):
        raise YunohostValidationError("domain_cannot_add_xmpp_upload")

    ldap = _get_ldap_interface()

    try:
        ldap.validate_uniqueness({"virtualdomain": domain})
    except MoulinetteError:
        raise YunohostValidationError("domain_exists")

    # Lower domain to avoid some edge cases issues
    # See: https://forum.yunohost.org/t/invalid-domain-causes-diagnosis-web-to-fail-fr-on-demand/11765
    domain = domain.lower()

    # DynDNS domain
    if dyndns:

        from yunohost.dyndns import _dyndns_provides, _guess_current_dyndns_domain

        # Do not allow to subscribe to multiple dyndns domains...
        if _guess_current_dyndns_domain("dyndns.yunohost.org") != (None, None):
            raise YunohostValidationError("domain_dyndns_already_subscribed")

        # Check that this domain can effectively be provided by
        # dyndns.yunohost.org. (i.e. is it a nohost.me / noho.st)
        if not _dyndns_provides("dyndns.yunohost.org", domain):
            raise YunohostValidationError("domain_dyndns_root_unknown")

    operation_logger.start()

    if dyndns:
        from yunohost.dyndns import dyndns_subscribe

        # Actually subscribe
        dyndns_subscribe(domain=domain)

    _certificate_install_selfsigned([domain], False)

    try:
        attr_dict = {
            "objectClass": ["mailDomain", "top"],
            "virtualdomain": domain,
        }

        try:
            ldap.add("virtualdomain=%s,ou=domains" % domain, attr_dict)
        except Exception as e:
            raise YunohostError("domain_creation_failed", domain=domain, error=e)

        # Don't regen these conf if we're still in postinstall
        if os.path.exists("/etc/yunohost/installed"):
            # Sometime we have weird issues with the regenconf where some files
            # appears as manually modified even though they weren't touched ...
            # There are a few ideas why this happens (like backup/restore nginx
            # conf ... which we shouldnt do ...). This in turns creates funky
            # situation where the regenconf may refuse to re-create the conf
            # (when re-creating a domain..)
            # So here we force-clear the has out of the regenconf if it exists.
            # This is a pretty ad hoc solution and only applied to nginx
            # because it's one of the major service, but in the long term we
            # should identify the root of this bug...
            _force_clear_hashes(["/etc/nginx/conf.d/%s.conf" % domain])
            regen_conf(names=["nginx", "metronome", "dnsmasq", "postfix", "rspamd"])
            app_ssowatconf()

    except Exception as e:
        # Force domain removal silently
        try:
            domain_remove(domain, force=True)
        except Exception:
            pass
        raise e

    hook_callback("post_domain_add", args=[domain])

    logger.success(m18n.n("domain_created"))


@is_unit_operation()
def domain_remove(operation_logger, domain, remove_apps=False, force=False):
    """
    Delete domains

    Keyword argument:
        domain -- Domain to delete
        remove_apps -- Remove applications installed on the domain
        force -- Force the domain removal and don't not ask confirmation to
                 remove apps if remove_apps is specified

    """
    from yunohost.hook import hook_callback
    from yunohost.app import app_ssowatconf, app_info, app_remove
    from yunohost.utils.ldap import _get_ldap_interface

    # the 'force' here is related to the exception happening in domain_add ...
    # we don't want to check the domain exists because the ldap add may have
    # failed
    if not force and domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

    # Check domain is not the main domain
    if domain == _get_maindomain():
        other_domains = domain_list()["domains"]
        other_domains.remove(domain)

        if other_domains:
            raise YunohostValidationError(
                "domain_cannot_remove_main",
                domain=domain,
                other_domains="\n * " + ("\n * ".join(other_domains)),
            )
        else:
            raise YunohostValidationError(
                "domain_cannot_remove_main_add_new_one", domain=domain
            )

    # Check if apps are installed on the domain
    apps_on_that_domain = []

    for app in _installed_apps():
        settings = _get_app_settings(app)
        label = app_info(app)["name"]
        if settings.get("domain") == domain:
            apps_on_that_domain.append(
                (
                    app,
                    '    - %s "%s" on https://%s%s'
                    % (app, label, domain, settings["path"])
                    if "path" in settings
                    else app,
                )
            )

    if apps_on_that_domain:
        if remove_apps:
            if msettings.get("interface") == "cli" and not force:
                answer = msignals.prompt(
                    m18n.n(
                        "domain_remove_confirm_apps_removal",
                        apps="\n".join([x[1] for x in apps_on_that_domain]),
                        answers="y/N",
                    ),
                    color="yellow",
                )
                if answer.upper() != "Y":
                    raise YunohostError("aborting")

            for app, _ in apps_on_that_domain:
                app_remove(app)
        else:
            raise YunohostValidationError(
                "domain_uninstall_app_first",
                apps="\n".join([x[1] for x in apps_on_that_domain]),
            )

    operation_logger.start()

    ldap = _get_ldap_interface()
    try:
        ldap.remove("virtualdomain=" + domain + ",ou=domains")
    except Exception as e:
        raise YunohostError("domain_deletion_failed", domain=domain, error=e)

    os.system("rm -rf /etc/yunohost/certs/%s" % domain)

    # Delete dyndns keys for this domain (if any)
    os.system("rm -rf /etc/yunohost/dyndns/K%s.+*" % domain)

    # Sometime we have weird issues with the regenconf where some files
    # appears as manually modified even though they weren't touched ...
    # There are a few ideas why this happens (like backup/restore nginx
    # conf ... which we shouldnt do ...). This in turns creates funky
    # situation where the regenconf may refuse to re-create the conf
    # (when re-creating a domain..)
    #
    # So here we force-clear the has out of the regenconf if it exists.
    # This is a pretty ad hoc solution and only applied to nginx
    # because it's one of the major service, but in the long term we
    # should identify the root of this bug...
    _force_clear_hashes(["/etc/nginx/conf.d/%s.conf" % domain])
    # And in addition we even force-delete the file Otherwise, if the file was
    # manually modified, it may not get removed by the regenconf which leads to
    # catastrophic consequences of nginx breaking because it can't load the
    # cert file which disappeared etc..
    if os.path.exists("/etc/nginx/conf.d/%s.conf" % domain):
        _process_regen_conf(
            "/etc/nginx/conf.d/%s.conf" % domain, new_conf=None, save=True
        )

    regen_conf(names=["nginx", "metronome", "dnsmasq", "postfix"])
    app_ssowatconf()

    hook_callback("post_domain_remove", args=[domain])

    logger.success(m18n.n("domain_deleted"))


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

    if msettings.get("interface") == "cli":
        # FIXME Update this to point to our "dns push" doc
        logger.info(m18n.n("domain_dns_conf_is_just_a_recommendation"))

    return result


@is_unit_operation()
def domain_main_domain(operation_logger, new_main_domain=None):
    """
    Check the current main domain, or change it

    Keyword argument:
        new_main_domain -- The new domain to be set as the main domain

    """
    from yunohost.tools import _set_hostname

    # If no new domain specified, we return the current main domain
    if not new_main_domain:
        return {"current_main_domain": _get_maindomain()}

    # Check domain exists
    if new_main_domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=new_main_domain)

    operation_logger.related_to.append(("domain", new_main_domain))
    operation_logger.start()

    # Apply changes to ssl certs
    try:
        write_to_file("/etc/yunohost/current_host", new_main_domain)

        _set_hostname(new_main_domain)
    except Exception as e:
        logger.warning("%s" % e, exc_info=1)
        raise YunohostError("main_domain_change_failed")

    # Generate SSOwat configuration file
    app_ssowatconf()

    # Regen configurations
    if os.path.exists("/etc/yunohost/installed"):
        regen_conf()

    logger.success(m18n.n("main_domain_changed"))


def domain_cert_status(domain_list, full=False):
    import yunohost.certificate

    return yunohost.certificate.certificate_status(domain_list, full)


def domain_cert_install(
    domain_list, force=False, no_checks=False, self_signed=False, staging=False
):
    import yunohost.certificate

    return yunohost.certificate.certificate_install(
        domain_list, force, no_checks, self_signed, staging
    )


def domain_cert_renew(
    domain_list, force=False, no_checks=False, email=False, staging=False
):
    import yunohost.certificate

    return yunohost.certificate.certificate_renew(
        domain_list, force, no_checks, email, staging
    )


def domain_url_available(domain, path):
    """
    Check availability of a web path

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
    """

    return len(_get_conflicting_apps(domain, path)) == 0


def _get_maindomain():
    with open("/etc/yunohost/current_host", "r") as f:
        maindomain = f.readline().rstrip()
    return maindomain


def _build_dns_conf(domain):
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

    domains = _get_domain_settings(domain, True)

    basic = []
    mail = []
    xmpp = []
    extra = []
    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)
    owned_dns_zone = (
        # TODO test this
        "dns_zone" in domains[domain] and domains[domain]["dns_zone"] == domain
    )

    root_prefix = domain.partition(".")[0]
    child_domain_suffix = ""

    for domain_name, domain in domains.items():
        ttl = domain["ttl"]

        if domain_name == domain:
            name = "@" if owned_dns_zone else root_prefix
        else:
            name = domain_name[0 : -(1 + len(domain))]
            if not owned_dns_zone:
                name += "." + root_prefix

        if name != "@":
            child_domain_suffix = "." + name

        ###########################
        # Basic ipv4/ipv6 records #
        ###########################
        if ipv4:
            basic.append([name, ttl, "A", ipv4])

        if ipv6:
            basic.append([name, ttl, "AAAA", ipv6])
        # TODO
        # elif include_empty_AAAA_if_no_ipv6:
        #     basic.append(["@", ttl, "AAAA", None])

        #########
        # Email #
        #########
        if domain["mail"]:

            mail += [
                [name, ttl, "MX", "10 %s." % domain_name],
                [name, ttl, "TXT", '"v=spf1 a mx -all"'],
            ]

            # DKIM/DMARC record
            dkim_host, dkim_publickey = _get_DKIM(domain_name)

            if dkim_host:
                mail += [
                    [dkim_host, ttl, "TXT", dkim_publickey],
                    [f"_dmarc{child_domain_suffix}", ttl, "TXT", '"v=DMARC1; p=none"'],
                ]

        ########
        # XMPP #
        ########
        if domain["xmpp"]:
            xmpp += [
                [
                    f"_xmpp-client._tcp{child_domain_suffix}",
                    ttl,
                    "SRV",
                    f"0 5 5222 {domain_name}.",
                ],
                [
                    f"_xmpp-server._tcp{child_domain_suffix}",
                    ttl,
                    "SRV",
                    f"0 5 5269 {domain_name}.",
                ],
                ["muc" + child_domain_suffix, ttl, "CNAME", name],
                ["pubsub" + child_domain_suffix, ttl, "CNAME", name],
                ["vjud" + child_domain_suffix, ttl, "CNAME", name],
                ["xmpp-upload" + child_domain_suffix, ttl, "CNAME", name],
            ]

        #########
        # Extra #
        #########

        if ipv4:
            extra.append([f"*{child_domain_suffix}", ttl, "A", ipv4])

        if ipv6:
            extra.append([f"*{child_domain_suffix}", ttl, "AAAA", ipv6])
        # TODO
        # elif include_empty_AAAA_if_no_ipv6:
        #     extra.append(["*", ttl, "AAAA", None])

        extra.append([name, ttl, "CAA", '128 issue "letsencrypt.org"'])

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

    hook_results = hook_callback("custom_dns_rules", args=[domain])
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


def _load_domain_settings(domains=[]):
    """
    Retrieve entries in /etc/yunohost/domains/[domain].yml
    And fill the holes if any
    """
    # Retrieve actual domain list
    get_domain_list = domain_list()

    if domains:
        # check existence of requested domains
        all_known_domains = get_domain_list["domains"]
        # filter inexisting domains
        unknown_domains = filter(lambda domain : not domain in all_known_domains, domains)
        # get first unknown domain
        unknown_domain = next(unknown_domains, None)
        if unknown_domain != None:
            raise YunohostValidationError("domain_name_unknown", domain=unknown_domain)
    else:
        domains = domain_list()["domains"]


    # Create sanitized data
    new_domains = dict()

    # Load main domain
    maindomain = get_domain_list["main"]

    for domain in domains:
        # Retrieve entries in the YAML
        filepath = f"{DOMAIN_SETTINGS_DIR}/{domain}.yml"
        on_disk_settings = {}
        if os.path.exists(filepath) and os.path.isfile(filepath):
            on_disk_settings = yaml.load(open(filepath, "r+"))
            # If the file is empty or "corrupted"
            if not type(on_disk_settings) is dict:
                on_disk_settings = {}
        # Generate defaults
        is_maindomain = domain == maindomain
        dns_zone = get_dns_zone_from_domain(domain)
        default_settings = {
            "xmpp": is_maindomain,
            "mail": True,
            "dns_zone": dns_zone,
            "ttl": 3600,
        }
        # Update each setting if not present
        default_settings.update(on_disk_settings)
        # Add the domain to the list
        new_domains[domain] = default_settings

    return new_domains


def _load_registrar_setting(dns_zone):
    """
    Retrieve entries in registrars/[dns_zone].yml
    """

    on_disk_settings = {}
    filepath = f"{REGISTRAR_SETTINGS_DIR}/{dns_zone}.yml"
    if os.path.exists(filepath) and os.path.isfile(filepath):
        on_disk_settings = yaml.load(open(filepath, "r+"))
        # If the file is empty or "corrupted"
        if not type(on_disk_settings) is dict:
            on_disk_settings = {}

    return on_disk_settings


def domain_setting(domain, key, value=None, delete=False):
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """

    domains = _load_domain_settings([ domain ])

    if not domain in domains.keys():
        raise YunohostError("domain_name_unknown", domain=domain)

    domain_settings = domains[domain]

    # GET
    if value is None and not delete:
        if not key in domain_settings:
            raise YunohostValidationError("domain_property_unknown", property=key)

        return domain_settings[key]

    # DELETE
    if delete:
        if key in domain_settings:
            del domain_settings[key]
            _set_domain_settings(domain, domain_settings)

    # SET
    else:

        if "ttl" == key:
            try:
                ttl = int(value)
            except ValueError:
                # TODO add locales
                raise YunohostError("invalid_number", value_type=type(ttl))

            if ttl < 0:
                raise YunohostError("pattern_positive_number", value_type=type(ttl))
        domain_settings[key] = value
        _set_domain_settings(domain, domain_settings)


def _is_subdomain_of(subdomain, domain):
    return True if re.search("(^|\\.)" + domain + "$", subdomain) else False


def _get_domain_settings(domain, subdomains):
    """
    Get settings of a domain

    Keyword arguments:
        domain -- The domain name
        subdomains -- Do we include the subdomains? Default is False

    """
    domains = _load_domain_settings()
    if not domain in domains.keys():
        raise YunohostError("domain_name_unknown", domain=domain)

    only_wanted_domains = dict()
    for entry in domains.keys():
        if subdomains:
            if _is_subdomain_of(entry, domain):
                only_wanted_domains[entry] = domains[entry]
        else:
            if domain == entry:
                only_wanted_domains[entry] = domains[entry]

    return only_wanted_domains


def _set_domain_settings(domain, domain_settings):
    """
    Set settings of a domain

    Keyword arguments:
        domain -- The domain name
        settings -- Dict with doamin settings

    """
    if domain not in domain_list()["domains"]:
        raise YunohostError("domain_name_unknown", domain=domain)

    # First create the DOMAIN_SETTINGS_DIR if it doesn't exist
    if not os.path.exists(DOMAIN_SETTINGS_DIR):
        os.mkdir(DOMAIN_SETTINGS_DIR)
    # Save the settings to the .yaml file
    filepath = f"{DOMAIN_SETTINGS_DIR}/{domain}.yml"
    with open(filepath, "w") as file:
        yaml.dump(domain_settings, file, default_flow_style=False)


def _load_zone_of_domain(domain):
    if domain not in domain_list()["domains"]:
        raise YunohostError("domain_name_unknown", domain=domain)

    return domains[domain]["dns_zone"]


def domain_registrar_info(domain):

    dns_zone = _load_zone_of_domain(domain)
    registrar_info = _load_registrar_setting(dns_zone)
    if not registrar_info:
        # TODO add locales
        raise YunohostError("registrar_is_not_set", dns_zone=dns_zone)
    
    logger.info("Registrar name: " + registrar_info['name'])
    for option_key, option_value in registrar_info['options'].items():
        logger.info("Option " + option_key + ": " + option_value)

def domain_registrar_catalog(full):
    registrars = yaml.load(open(REGISTRAR_LIST_PATH, "r+"))
    for registrar in registrars:
        logger.info("Registrar : " + registrar)
        if full : 
            logger.info("Options : ")
            for option in registrars[registrar]:
                logger.info("\t- " + option)
        

def domain_registrar_set(domain, registrar, args):

    dns_zone = _load_zone_of_domain(domain)
    registrar_info = _load_registrar_setting(dns_zone)

    registrars = yaml.load(open(REGISTRAR_LIST_PATH, "r+"))
    if not registrar in registrars.keys():
        # FIXME créer l'erreur
        raise YunohostError("domain_registrar_unknown")

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

    # First create the REGISTRAR_SETTINGS_DIR if it doesn't exist
    if not os.path.exists(REGISTRAR_SETTINGS_DIR):
        os.mkdir(REGISTRAR_SETTINGS_DIR)
    # Save the settings to the .yaml file
    filepath = f"{REGISTRAR_SETTINGS_DIR}/{dns_zone}.yml"
    with open(filepath, "w") as file:
        yaml.dump(domain_registrar, file, default_flow_style=False)


def domain_push_config(domain):
    """
    Send DNS records to the previously-configured registrar of the domain.
    """
    # Generate the records
    if domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_name_unknown", domain=domain)

    dns_conf = _build_dns_conf(domain)

    domain_settings = _load_domain_settings([ domain ])
    dns_zone = domain_settings[domain]["dns_zone"]
    registrar_setting = _load_registrar_setting(dns_zone)

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
