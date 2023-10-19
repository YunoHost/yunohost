#
# Copyright (c) 2023 YunoHost Contributors
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
import os
import time
from pathlib import Path
from typing import List, Optional
from collections import OrderedDict
from logging import getLogger

from moulinette import m18n, Moulinette
from moulinette.core import MoulinetteError
from moulinette.utils.filesystem import (
    read_json,
    read_yaml,
    rm,
    write_to_file,
    write_to_json,
    write_to_yaml,
)

from yunohost.app import (
    app_ssowatconf,
    _installed_apps,
    _get_app_settings,
    _get_conflicting_apps,
)
from yunohost.regenconf import regen_conf, _force_clear_hashes, _process_regen_conf
from yunohost.utils.configpanel import ConfigPanel
from yunohost.utils.form import BaseOption
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.dns import is_yunohost_dyndns_domain
from yunohost.log import is_unit_operation

logger = getLogger("yunohost.domain")

DOMAIN_SETTINGS_DIR = "/etc/yunohost/domains"

# Lazy dev caching to avoid re-query ldap every time we need the domain list
# The cache automatically expire every 15 seconds, to prevent desync between
#  yunohost CLI and API which run in different processes
domain_list_cache: List[str] = []
domain_list_cache_timestamp = 0
main_domain_cache: Optional[str] = None
main_domain_cache_timestamp = 0
DOMAIN_CACHE_DURATION = 15


def _get_maindomain():
    global main_domain_cache
    global main_domain_cache_timestamp
    if (
        not main_domain_cache
        or abs(main_domain_cache_timestamp - time.time()) > DOMAIN_CACHE_DURATION
    ):
        with open("/etc/yunohost/current_host", "r") as f:
            main_domain_cache = f.readline().rstrip()
        main_domain_cache_timestamp = time.time()

    return main_domain_cache


def _get_domains(exclude_subdomains=False):
    global domain_list_cache
    global domain_list_cache_timestamp
    if (
        not domain_list_cache
        or abs(domain_list_cache_timestamp - time.time()) > DOMAIN_CACHE_DURATION
    ):
        from yunohost.utils.ldap import _get_ldap_interface

        ldap = _get_ldap_interface()
        result = [
            entry["virtualdomain"][0]
            for entry in ldap.search("ou=domains", "virtualdomain=*", ["virtualdomain"])
        ]

        def cmp_domain(domain):
            # Keep the main part of the domain and the extension together
            # eg: this.is.an.example.com -> ['example.com', 'an', 'is', 'this']
            domain = domain.split(".")
            domain[-1] = domain[-2] + domain.pop()
            return list(reversed(domain))

        domain_list_cache = sorted(result, key=cmp_domain)
        domain_list_cache_timestamp = time.time()

    if exclude_subdomains:
        return [
            domain for domain in domain_list_cache if not _get_parent_domain_of(domain)
        ]

    return domain_list_cache


def _get_domain_portal_dict():

    domains = _get_domains()
    out = OrderedDict()

    for domain in domains:

        parent = None

        # Use the topest parent domain if any
        for d in out.keys():
            if domain.endswith(f".{d}"):
                parent = d
                break

        out[domain] = f'{parent or domain}/yunohost/sso'

    # By default, redirect to $host/yunohost/admin for domains not listed in the dict
    # maybe in the future, we can allow to tweak this
    out["default"] = "/yunohost/admin"

    return dict(out)


def domain_list(exclude_subdomains=False, tree=False, features=[]):
    """
    List domains

    Keyword argument:
        exclude_subdomains -- Filter out domains that are subdomains of other declared domains
        tree -- Display domains as a hierarchy tree

    """

    domains = _get_domains(exclude_subdomains)
    main = _get_maindomain()

    if features:
        domains_filtered = []
        for domain in domains:
            config = domain_config_get(domain, key="feature", export=True)
            if any(config.get(feature) == 1 for feature in features):
                domains_filtered.append(domain)
        domains = domains_filtered

    if not tree:
        return {"domains": domains, "main": main}

    if tree and exclude_subdomains:
        return {
            "domains": OrderedDict({domain: {} for domain in domains}),
            "main": main,
        }

    def get_parent_dict(tree, child):
        # If parent exists it should be the last added (see `_get_domains` ordering)
        possible_parent = next(reversed(tree)) if tree else None
        if possible_parent and child.endswith(f".{possible_parent}"):
            return get_parent_dict(tree[possible_parent], child)
        return tree

    result = OrderedDict()
    for domain in domains:
        parent = get_parent_dict(result, domain)
        parent[domain] = OrderedDict()

    return {"domains": result, "main": main}


def domain_info(domain):
    """
    Print aggregate data for a specific domain

    Keyword argument:
        domain     -- Domain to be checked
    """

    from yunohost.app import app_info
    from yunohost.dns import _get_registar_settings
    from yunohost.certificate import certificate_status

    _assert_domain_exists(domain)

    registrar, _ = _get_registar_settings(domain)
    certificate = certificate_status([domain], full=True)["certificates"][domain]

    apps = []
    for app in _installed_apps():
        settings = _get_app_settings(app)
        if settings.get("domain") == domain:
            apps.append(
                {
                    "name": app_info(app)["name"],
                    "id": app,
                    "path": settings.get("path", ""),
                }
            )

    return {
        "certificate": certificate,
        "registrar": registrar,
        "apps": apps,
        "main": _get_maindomain() == domain,
        "topest_parent": _get_parent_domain_of(domain, topest=True),
        # TODO : add parent / child domains ?
    }


def _assert_domain_exists(domain):
    if domain not in _get_domains():
        raise YunohostValidationError("domain_unknown", domain=domain)


def _list_subdomains_of(parent_domain):
    _assert_domain_exists(parent_domain)

    out = []
    for domain in _get_domains():
        if domain.endswith(f".{parent_domain}"):
            out.append(domain)

    return out


def _get_parent_domain_of(domain, return_self=False, topest=False):
    domains = _get_domains(exclude_subdomains=topest)

    domain_ = domain
    while "." in domain_:
        domain_ = domain_.split(".", 1)[1]
        if domain_ in domains:
            return domain_

    return domain if return_self else None


@is_unit_operation(exclude=["dyndns_recovery_password"])
def domain_add(
    operation_logger, domain, dyndns_recovery_password=None, ignore_dyndns=False
):
    """
    Create a custom domain

    Keyword argument:
        domain -- Domain name to add
        dyndns -- Subscribe to DynDNS
        dyndns_recovery_password -- Password used to later unsubscribe from DynDNS
        ignore_dyndns -- If we want to just add the DynDNS domain to the list, without subscribing
    """
    from yunohost.hook import hook_callback
    from yunohost.app import app_ssowatconf
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.certificate import _certificate_install_selfsigned

    if dyndns_recovery_password:
        operation_logger.data_to_redact.append(dyndns_recovery_password)

    if domain.startswith("xmpp-upload."):
        raise YunohostValidationError("domain_cannot_add_xmpp_upload")

    if domain.startswith("muc."):
        raise YunohostError("domain_cannot_add_muc_upload")

    ldap = _get_ldap_interface()

    try:
        ldap.validate_uniqueness({"virtualdomain": domain})
    except MoulinetteError:
        raise YunohostValidationError("domain_exists")

    # Lower domain to avoid some edge cases issues
    # See: https://forum.yunohost.org/t/invalid-domain-causes-diagnosis-web-to-fail-fr-on-demand/11765
    domain = domain.lower()

    # Non-latin characters (e.g. café.com => xn--caf-dma.com)
    domain = domain.encode("idna").decode("utf-8")

    # Detect if this is a DynDNS domain ( and not a subdomain of a DynDNS domain )
    dyndns = (
        not ignore_dyndns
        and is_yunohost_dyndns_domain(domain)
        and len(domain.split(".")) == 3
    )
    if dyndns:
        from yunohost.dyndns import is_subscribing_allowed

        # Do not allow to subscribe to multiple dyndns domains...
        if not is_subscribing_allowed():
            raise YunohostValidationError("domain_dyndns_already_subscribed")
        if dyndns_recovery_password:
            assert_password_is_strong_enough("admin", dyndns_recovery_password)

    operation_logger.start()

    if dyndns:
        domain_dyndns_subscribe(
            domain=domain, recovery_password=dyndns_recovery_password
        )

    _certificate_install_selfsigned([domain], True)

    try:
        attr_dict = {
            "objectClass": ["mailDomain", "top"],
            "virtualdomain": domain,
        }

        try:
            ldap.add(f"virtualdomain={domain},ou=domains", attr_dict)
        except Exception as e:
            raise YunohostError("domain_creation_failed", domain=domain, error=e)
        finally:
            global domain_list_cache
            domain_list_cache = []

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
            _force_clear_hashes([f"/etc/nginx/conf.d/{domain}.conf"])
            regen_conf(
                names=["nginx", "metronome", "dnsmasq", "postfix", "rspamd", "mdns"]
            )
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


@is_unit_operation(exclude=["dyndns_recovery_password"])
def domain_remove(
    operation_logger,
    domain,
    remove_apps=False,
    force=False,
    dyndns_recovery_password=None,
    ignore_dyndns=False,
):
    """
    Delete domains

    Keyword argument:
        domain -- Domain to delete
        remove_apps -- Remove applications installed on the domain
        force -- Force the domain removal and don't not ask confirmation to
                 remove apps if remove_apps is specified
        dyndns_recovery_password -- Recovery password used at the creation of the DynDNS domain
        ignore_dyndns -- If we just remove the DynDNS domain, without unsubscribing
    """
    from yunohost.hook import hook_callback
    from yunohost.app import app_ssowatconf, app_info, app_remove
    from yunohost.utils.ldap import _get_ldap_interface

    if dyndns_recovery_password:
        operation_logger.data_to_redact.append(dyndns_recovery_password)

    # the 'force' here is related to the exception happening in domain_add ...
    # we don't want to check the domain exists because the ldap add may have
    # failed
    if not force:
        _assert_domain_exists(domain)

    # Check domain is not the main domain
    if domain == _get_maindomain():
        other_domains = _get_domains()
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
                    f"    - {app} \"{label}\" on https://{domain}{settings['path']}"
                    if "path" in settings
                    else app,
                )
            )

    if apps_on_that_domain:
        if remove_apps:
            if Moulinette.interface.type == "cli" and not force:
                answer = Moulinette.prompt(
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

    # Detect if this is a DynDNS domain ( and not a subdomain of a DynDNS domain )
    dyndns = (
        not ignore_dyndns
        and is_yunohost_dyndns_domain(domain)
        and len(domain.split(".")) == 3
    )

    operation_logger.start()

    ldap = _get_ldap_interface()
    try:
        ldap.remove("virtualdomain=" + domain + ",ou=domains")
    except Exception as e:
        raise YunohostError("domain_deletion_failed", domain=domain, error=e)
    finally:
        global domain_list_cache
        domain_list_cache = []

    stuff_to_delete = [
        f"/etc/yunohost/certs/{domain}",
        f"/etc/yunohost/dyndns/K{domain}.+*",
        f"{DOMAIN_SETTINGS_DIR}/{domain}.yml",
    ]

    for stuff in stuff_to_delete:
        rm(stuff, force=True, recursive=True)

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
    _force_clear_hashes([f"/etc/nginx/conf.d/{domain}.conf"])
    # And in addition we even force-delete the file Otherwise, if the file was
    # manually modified, it may not get removed by the regenconf which leads to
    # catastrophic consequences of nginx breaking because it can't load the
    # cert file which disappeared etc..
    if os.path.exists(f"/etc/nginx/conf.d/{domain}.conf"):
        _process_regen_conf(
            f"/etc/nginx/conf.d/{domain}.conf", new_conf=None, save=True
        )

    regen_conf(names=["nginx", "metronome", "dnsmasq", "postfix", "rspamd", "mdns"])
    app_ssowatconf()

    hook_callback("post_domain_remove", args=[domain])

    # If a password is provided, delete the DynDNS record
    if dyndns:
        # Actually unsubscribe
        domain_dyndns_unsubscribe(
            domain=domain, recovery_password=dyndns_recovery_password
        )

    logger.success(m18n.n("domain_deleted"))


def domain_dyndns_subscribe(*args, **kwargs):
    """
    Subscribe to a DynDNS domain
    """
    from yunohost.dyndns import dyndns_subscribe

    dyndns_subscribe(*args, **kwargs)


def domain_dyndns_unsubscribe(*args, **kwargs):
    """
    Unsubscribe from a DynDNS domain
    """
    from yunohost.dyndns import dyndns_unsubscribe

    dyndns_unsubscribe(*args, **kwargs)


def domain_dyndns_list():
    """
    Returns all currently subscribed DynDNS domains
    """
    from yunohost.dyndns import dyndns_list

    return dyndns_list()


def domain_dyndns_update(*args, **kwargs):
    """
    Update a DynDNS domain
    """
    from yunohost.dyndns import dyndns_update

    dyndns_update(*args, **kwargs)


def domain_dyndns_set_recovery_password(*args, **kwargs):
    """
    Set a recovery password for an already registered dyndns domain
    """
    from yunohost.dyndns import dyndns_set_recovery_password

    dyndns_set_recovery_password(*args, **kwargs)


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

    old_main_domain = _get_maindomain()

    # Check domain exists
    _assert_domain_exists(new_main_domain)

    operation_logger.related_to.append(("domain", new_main_domain))
    operation_logger.start()

    # Apply changes to ssl certs
    try:
        write_to_file("/etc/yunohost/current_host", new_main_domain)
        global main_domain_cache
        main_domain_cache = new_main_domain
        _set_hostname(new_main_domain)
    except Exception as e:
        logger.warning(str(e), exc_info=1)
        raise YunohostError("main_domain_change_failed")

    # Generate SSOwat configuration file
    app_ssowatconf()

    # Regen configurations
    if os.path.exists("/etc/yunohost/installed"):
        regen_conf()

    from yunohost.user import _update_admins_group_aliases

    _update_admins_group_aliases(
        old_main_domain=old_main_domain, new_main_domain=new_main_domain
    )

    logger.success(m18n.n("main_domain_changed"))


def domain_url_available(domain, path):
    """
    Check availability of a web path

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
    """

    return len(_get_conflicting_apps(domain, path)) == 0


def domain_config_get(domain, key="", full=False, export=False):
    """
    Display a domain configuration
    """

    if full and export:
        raise YunohostValidationError(
            "You can't use --full and --export together.", raw_msg=True
        )

    if full:
        mode = "full"
    elif export:
        mode = "export"
    else:
        mode = "classic"

    config = DomainConfigPanel(domain)
    return config.get(key, mode)


@is_unit_operation()
def domain_config_set(
    operation_logger, domain, key=None, value=None, args=None, args_file=None
):
    """
    Apply a new domain configuration
    """
    BaseOption.operation_logger = operation_logger
    config = DomainConfigPanel(domain)
    return config.set(key, value, args, args_file, operation_logger=operation_logger)


class DomainConfigPanel(ConfigPanel):
    entity_type = "domain"
    save_path_tpl = f"{DOMAIN_SETTINGS_DIR}/{{entity}}.yml"
    save_mode = "diff"

    def get(self, key="", mode="classic"):
        result = super().get(key=key, mode=mode)

        if mode == "full":
            for panel, section, option in self._iterate():
                # This injects:
                # i18n: domain_config_cert_renew_help
                # i18n: domain_config_default_app_help
                # i18n: domain_config_xmpp_help
                if m18n.key_exists(self.config["i18n"] + "_" + option["id"] + "_help"):
                    option["help"] = m18n.n(
                        self.config["i18n"] + "_" + option["id"] + "_help"
                    )
            return self.config

        return result

    def _get_raw_config(self):
        toml = super()._get_raw_config()

        toml["feature"]["xmpp"]["xmpp"]["default"] = (
            1 if self.entity == _get_maindomain() else 0
        )

        # Portal settings are only available on "topest" domains
        if _get_parent_domain_of(self.entity, topest=True) is not None:
            del toml["feature"]["portal"]

        # Optimize wether or not to load the DNS section,
        # e.g. we don't want to trigger the whole _get_registary_config_section
        # when just getting the current value from the feature section
        filter_key = self.filter_key.split(".") if self.filter_key != "" else []
        if not filter_key or filter_key[0] == "dns":
            from yunohost.dns import _get_registrar_config_section

            toml["dns"]["registrar"] = _get_registrar_config_section(self.entity)

            # FIXME: Ugly hack to save the registar id/value and reinject it in _get_raw_settings ...
            self.registar_id = toml["dns"]["registrar"]["registrar"]["value"]
            del toml["dns"]["registrar"]["registrar"]["value"]

        # Cert stuff
        if not filter_key or filter_key[0] == "cert":
            from yunohost.certificate import certificate_status

            status = certificate_status([self.entity], full=True)["certificates"][
                self.entity
            ]

            toml["cert"]["cert"]["cert_summary"]["style"] = status["style"]

            # i18n: domain_config_cert_summary_expired
            # i18n: domain_config_cert_summary_selfsigned
            # i18n: domain_config_cert_summary_abouttoexpire
            # i18n: domain_config_cert_summary_ok
            # i18n: domain_config_cert_summary_letsencrypt
            toml["cert"]["cert"]["cert_summary"]["ask"] = m18n.n(
                f"domain_config_cert_summary_{status['summary']}"
            )

            # FIXME: Ugly hack to save the cert status and reinject it in _get_raw_settings ...
            self.cert_status = status

        return toml

    def _get_raw_settings(self):
        # TODO add mechanism to share some settings with other domains on the same zone
        super()._get_raw_settings()

        # FIXME: Ugly hack to save the registar id/value and reinject it in _get_raw_settings ...
        filter_key = self.filter_key.split(".") if self.filter_key != "" else []
        if not filter_key or filter_key[0] == "dns":
            self.values["registrar"] = self.registar_id

        # FIXME: Ugly hack to save the cert status and reinject it in _get_raw_settings ...
        if not filter_key or filter_key[0] == "cert":
            self.values["cert_validity"] = self.cert_status["validity"]
            self.values["cert_issuer"] = self.cert_status["CA_type"]
            self.values["acme_eligible"] = self.cert_status["ACME_eligible"]
            self.values["summary"] = self.cert_status["summary"]

    def _apply(self):
        if (
            "default_app" in self.future_values
            and self.future_values["default_app"] != self.values["default_app"]
        ):
            from yunohost.app import app_ssowatconf, app_map

            if "/" in app_map(raw=True).get(self.entity, {}):
                raise YunohostValidationError(
                    "app_make_default_location_already_used",
                    app=self.future_values["default_app"],
                    domain=self.entity,
                    other_app=app_map(raw=True)[self.entity]["/"]["id"],
                )

        portal_options = [
            "default_app",
            "show_other_domains_apps",
            "portal_title",
            # "portal_logo",
            "portal_theme",
        ]
        if _get_parent_domain_of(self.entity, topest=True) is None and any(
            option in self.future_values
            and self.new_values[option] != self.values.get(option)
            for option in portal_options
        ):
            from yunohost.portal import PORTAL_SETTINGS_DIR

            # Portal options are also saved in a `domain.portal.yml` file
            # that can be read by the portal API.
            # FIXME remove those from the config panel saved values?
            portal_values = {
                option: self.future_values[option] for option in portal_options
            }

            portal_settings_path = Path(f"{PORTAL_SETTINGS_DIR}/{self.entity}.json")
            portal_settings = {"apps": {}}

            if portal_settings_path.exists():
                portal_settings.update(read_json(str(portal_settings_path)))

            # Merge settings since this config file is shared with `app_ssowatconf()` which populate the `apps` key.
            portal_settings.update(portal_values)
            write_to_json(
                str(portal_settings_path), portal_settings, sort_keys=True, indent=4
            )

        super()._apply()

        # Reload ssowat if default app changed
        if (
            "default_app" in self.future_values
            and self.future_values["default_app"] != self.values["default_app"]
        ):
            app_ssowatconf()

        stuff_to_regen_conf = []
        if (
            "xmpp" in self.future_values
            and self.future_values["xmpp"] != self.values["xmpp"]
        ):
            stuff_to_regen_conf.append("nginx")
            stuff_to_regen_conf.append("metronome")

        if (
            "mail_in" in self.future_values
            and self.future_values["mail_in"] != self.values["mail_in"]
        ) or (
            "mail_out" in self.future_values
            and self.future_values["mail_out"] != self.values["mail_out"]
        ):
            if "nginx" not in stuff_to_regen_conf:
                stuff_to_regen_conf.append("nginx")
            stuff_to_regen_conf.append("postfix")
            stuff_to_regen_conf.append("dovecot")
            stuff_to_regen_conf.append("rspamd")

        if stuff_to_regen_conf:
            regen_conf(names=stuff_to_regen_conf)


def domain_action_run(domain, action, args=None):
    import urllib.parse

    if action == "cert.cert.cert_install":
        from yunohost.certificate import certificate_install as action_func
    elif action == "cert.cert.cert_renew":
        from yunohost.certificate import certificate_renew as action_func

    args = dict(urllib.parse.parse_qsl(args or "", keep_blank_values=True))
    no_checks = args["cert_no_checks"] in ("y", "yes", "on", "1")

    action_func([domain], force=True, no_checks=no_checks)


def _get_domain_settings(domain: str) -> dict:
    _assert_domain_exists(domain)

    if os.path.exists(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml"):
        return read_yaml(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml") or {}
    else:
        return {}


def _set_domain_settings(domain: str, settings: dict) -> None:
    _assert_domain_exists(domain)

    write_to_yaml(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml", settings)


#
#
# Stuff managed in other files
#
#


def domain_cert_status(domain_list, full=False):
    from yunohost.certificate import certificate_status

    return certificate_status(domain_list, full)


def domain_cert_install(domain_list, force=False, no_checks=False, self_signed=False):
    from yunohost.certificate import certificate_install

    return certificate_install(domain_list, force, no_checks, self_signed)


def domain_cert_renew(domain_list, force=False, no_checks=False, email=False):
    from yunohost.certificate import certificate_renew

    return certificate_renew(domain_list, force, no_checks, email)


def domain_dns_suggest(domain):
    from yunohost.dns import domain_dns_suggest

    return domain_dns_suggest(domain)


def domain_dns_push(domain, dry_run, force, purge):
    from yunohost.dns import domain_dns_push

    return domain_dns_push(domain, dry_run, force, purge)
