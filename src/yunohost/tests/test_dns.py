import pytest

import yaml
import os

from moulinette.utils.filesystem import read_toml

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.dns import (
    DOMAIN_REGISTRAR_LIST_PATH,
    _get_dns_zone_for_domain,
    _get_registrar_config_section
)


def setup_function(function):

    clean()


def teardown_function(function):

    clean()


def clean():
    pass


# DNS utils testing
def test_get_dns_zone_from_domain_existing():
    assert _get_dns_zone_for_domain("yunohost.org") == "yunohost.org"
    assert _get_dns_zone_for_domain("donate.yunohost.org") == "yunohost.org"
    assert _get_dns_zone_for_domain("fr.wikipedia.org") == "wikipedia.org"
    assert _get_dns_zone_for_domain("www.fr.wikipedia.org") == "wikipedia.org"
    assert _get_dns_zone_for_domain("non-existing-domain.yunohost.org") == "yunohost.org"
    assert _get_dns_zone_for_domain("yolo.nohost.me") == "nohost.me"
    assert _get_dns_zone_for_domain("foo.yolo.nohost.me") == "nohost.me"
    assert _get_dns_zone_for_domain("yolo.test") == "test"
    assert _get_dns_zone_for_domain("foo.yolo.test") == "test"


# Domain registrar testing
def test_registrar_list_integrity():
    assert read_toml(DOMAIN_REGISTRAR_LIST_PATH)


def test_magic_guess_registrar_weird_domain():
    assert _get_registrar_config_section("yolo.test")["explanation"]["value"] is None


def test_magic_guess_registrar_ovh():
    assert _get_registrar_config_section("yolo.yunohost.org")["explanation"]["value"] == "ovh"


def test_magic_guess_registrar_yunodyndns():
    assert _get_registrar_config_section("yolo.nohost.me")["explanation"]["value"] == "yunohost"


#def domain_dns_suggest(domain):
#    return yunohost.dns.domain_dns_conf(domain)
#
#
#def domain_dns_push(domain, dry_run):
#    import yunohost.dns
#    return yunohost.dns.domain_registrar_push(domain, dry_run)
