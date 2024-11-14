import pytest

from moulinette.utils.filesystem import read_toml

from yunohost.domain import domain_add, domain_remove
from yunohost.dns import (
    DOMAIN_REGISTRAR_LIST_PATH,
    _get_dns_zone_for_domain,
    _get_registrar_config_section,
    _build_dns_conf,
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
    assert (
        _get_dns_zone_for_domain("non-existing-domain.yunohost.org") == "yunohost.org"
    )
    assert _get_dns_zone_for_domain("yolo.nohost.me") == "yolo.nohost.me"
    assert _get_dns_zone_for_domain("foo.yolo.nohost.me") == "yolo.nohost.me"
    assert _get_dns_zone_for_domain("bar.foo.yolo.nohost.me") == "yolo.nohost.me"

    assert _get_dns_zone_for_domain("yolo.test") == "yolo.test"
    assert _get_dns_zone_for_domain("foo.yolo.test") == "yolo.test"

    assert _get_dns_zone_for_domain("yolo.tld") == "yolo.tld"
    assert _get_dns_zone_for_domain("foo.yolo.tld") == "yolo.tld"


# Domain registrar testing
def test_registrar_list_integrity():
    assert read_toml(DOMAIN_REGISTRAR_LIST_PATH)


def test_magic_guess_registrar_weird_domain():
    assert _get_registrar_config_section("yolo.tld")["registrar"]["default"] is None


def test_magic_guess_registrar_ovh():
    assert (
        _get_registrar_config_section("yolo.yunohost.org")["registrar"]["default"]
        == "ovh"
    )


def test_magic_guess_registrar_yunodyndns():
    assert (
        _get_registrar_config_section("yolo.nohost.me")["registrar"]["default"]
        == "yunohost"
    )


@pytest.fixture
def example_domain():
    domain_add("example.tld")
    yield "example.tld"
    domain_remove("example.tld")


def test_domain_dns_suggest(example_domain):
    assert _build_dns_conf(example_domain)


# def domain_dns_push(domain, dry_run):
#    import yunohost.dns
#    return yunohost.dns.domain_registrar_push(domain, dry_run)
