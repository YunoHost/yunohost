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
from typing import Dict, Any

from moulinette import m18n, Moulinette
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import write_to_file, read_yaml, write_to_yaml, rm

from yunohost.app import (
    app_ssowatconf,
    _installed_apps,
    _get_app_settings,
    _get_conflicting_apps,
)
from yunohost.regenconf import regen_conf, _force_clear_hashes, _process_regen_conf
from yunohost.utils.config import ConfigPanel, Question
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.log import is_unit_operation

logger = getActionLogger("yunohost.domain")

DOMAIN_CONFIG_PATH = "/usr/share/yunohost/config_domain.toml"
DOMAIN_SETTINGS_DIR = "/etc/yunohost/domains"

# Lazy dev caching to avoid re-query ldap every time we need the domain list
domain_list_cache: Dict[str, Any] = {}


def domain_list(exclude_subdomains=False):
    """
    List domains

    Keyword argument:
        exclude_subdomains -- Filter out domains that are subdomains of other declared domains

    """
    global domain_list_cache
    if not exclude_subdomains and domain_list_cache:
        return domain_list_cache

    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()
    result = [
        entry["virtualdomain"][0]
        for entry in ldap.search("ou=domains", "virtualdomain=*", ["virtualdomain"])
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

    # Don't cache answer if using exclude_subdomains
    if exclude_subdomains:
        return {"domains": result_list, "main": _get_maindomain()}

    domain_list_cache = {"domains": result_list, "main": _get_maindomain()}
    return domain_list_cache


def _assert_domain_exists(domain):
    if domain not in domain_list()["domains"]:
        raise YunohostValidationError("domain_unknown", domain=domain)


def _list_subdomains_of(parent_domain):

    _assert_domain_exists(parent_domain)

    out = []
    for domain in domain_list()["domains"]:
        if domain.endswith(f".{parent_domain}"):
            out.append(domain)

    return out


def _get_parent_domain_of(domain):

    _assert_domain_exists(domain)

    if "." not in domain:
        return domain

    parent_domain = domain.split(".", 1)[-1]
    if parent_domain not in domain_list()["domains"]:
        return domain  # Domain is its own parent

    else:
        return _get_parent_domain_of(parent_domain)


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

    # Non-latin characters (e.g. café.com => xn--caf-dma.com)
    domain = domain.encode("idna").decode("utf-8")

    # DynDNS domain
    if dyndns:

        from yunohost.utils.dns import is_yunohost_dyndns_domain
        from yunohost.dyndns import _guess_current_dyndns_domain

        # Do not allow to subscribe to multiple dyndns domains...
        if _guess_current_dyndns_domain() != (None, None):
            raise YunohostValidationError("domain_dyndns_already_subscribed")

        # Check that this domain can effectively be provided by
        # dyndns.yunohost.org. (i.e. is it a nohost.me / noho.st)
        if not is_yunohost_dyndns_domain(domain):
            raise YunohostValidationError("domain_dyndns_root_unknown")

    operation_logger.start()

    if dyndns:
        from yunohost.dyndns import dyndns_subscribe

        # Actually subscribe
        dyndns_subscribe(domain=domain)

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
            domain_list_cache = {}

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
    if not force:
        _assert_domain_exists(domain)

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

    operation_logger.start()

    ldap = _get_ldap_interface()
    try:
        ldap.remove("virtualdomain=" + domain + ",ou=domains")
    except Exception as e:
        raise YunohostError("domain_deletion_failed", domain=domain, error=e)
    finally:
        global domain_list_cache
        domain_list_cache = {}

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

    logger.success(m18n.n("domain_deleted"))


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
    _assert_domain_exists(new_main_domain)

    operation_logger.related_to.append(("domain", new_main_domain))
    operation_logger.start()

    # Apply changes to ssl certs
    try:
        write_to_file("/etc/yunohost/current_host", new_main_domain)
        global domain_list_cache
        domain_list_cache = {}
        _set_hostname(new_main_domain)
    except Exception as e:
        logger.warning(str(e), exc_info=1)
        raise YunohostError("main_domain_change_failed")

    # Generate SSOwat configuration file
    app_ssowatconf()

    # Regen configurations
    if os.path.exists("/etc/yunohost/installed"):
        regen_conf()

    logger.success(m18n.n("main_domain_changed"))


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
    Question.operation_logger = operation_logger
    config = DomainConfigPanel(domain)
    return config.set(key, value, args, args_file, operation_logger=operation_logger)


class DomainConfigPanel(ConfigPanel):
    entity_type = "domain"
    save_path_tpl = f"{DOMAIN_SETTINGS_DIR}/{{entity}}.yml"
    save_mode = "diff"

    def _apply(self):
        if (
            "default_app" in self.future_values
            and self.future_values["default_app"] != self.values["default_app"]
        ):
            from yunohost.app import app_ssowatconf, app_map

            if "/" in app_map(raw=True)[self.entity]:
                raise YunohostValidationError(
                    "app_make_default_location_already_used",
                    app=self.future_values["default_app"],
                    domain=self.entity,
                    other_app=app_map(raw=True)[self.entity]["/"]["id"],
                )

            super()._apply()
            app_ssowatconf()

    def _get_toml(self):

        toml = super()._get_toml()

        toml["feature"]["xmpp"]["xmpp"]["default"] = (
            1 if self.entity == _get_maindomain() else 0
        )

        # Optimize wether or not to load the DNS section,
        # e.g. we don't want to trigger the whole _get_registary_config_section
        # when just getting the current value from the feature section
        filter_key = self.filter_key.split(".") if self.filter_key != "" else []
        if not filter_key or filter_key[0] == "dns":
            from yunohost.dns import _get_registrar_config_section
            toml["dns"]["registrar"] = _get_registrar_config_section(self.entity)

            # FIXME: Ugly hack to save the registar id/value and reinject it in _load_current_values ...
            self.registar_id = toml["dns"]["registrar"]["registrar"]["value"]
            del toml["dns"]["registrar"]["registrar"]["value"]

        return toml

    def _load_current_values(self):

        # TODO add mechanism to share some settings with other domains on the same zone
        super()._load_current_values()

        # FIXME: Ugly hack to save the registar id/value and reinject it in _load_current_values ...
        if hasattr(self, "registrar_id"):
            self.values["registrar"] = self.registar_id


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


def domain_cert_install(
    domain_list, force=False, no_checks=False, self_signed=False
):
    from yunohost.certificate import certificate_install

    return certificate_install(domain_list, force, no_checks, self_signed)


def domain_cert_renew(
    domain_list, force=False, no_checks=False, email=False
):
    from yunohost.certificate import certificate_renew

    return certificate_renew(domain_list, force, no_checks, email)


def domain_dns_conf(domain):
    return domain_dns_suggest(domain)


def domain_dns_suggest(domain):
    from yunohost.dns import domain_dns_suggest

    return domain_dns_suggest(domain)


def domain_dns_push(domain, dry_run, force, purge):
    from yunohost.dns import domain_dns_push

    return domain_dns_push(domain, dry_run, force, purge)
