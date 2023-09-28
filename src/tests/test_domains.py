import pytest
import os
import time
import random

from moulinette.core import MoulinetteError

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.domain import (
    DOMAIN_SETTINGS_DIR,
    _get_maindomain,
    domain_add,
    domain_remove,
    domain_list,
    domain_main_domain,
    domain_config_get,
    domain_config_set,
)

TEST_DOMAINS = ["example.tld", "sub.example.tld", "other-example.com"]
TEST_DYNDNS_DOMAIN = (
    "ci-test-"
    + "".join(chr(random.randint(ord("a"), ord("z"))) for x in range(12))
    + random.choice([".noho.st", ".ynh.fr", ".nohost.me"])
)
TEST_DYNDNS_PASSWORD = "astrongandcomplicatedpassphrasethatisverysecure"


def setup_function(function):
    # Save domain list in variable to avoid multiple calls to domain_list()
    domains = domain_list()["domains"]

    # First domain is main domain
    if not TEST_DOMAINS[0] in domains:
        domain_add(TEST_DOMAINS[0])
    else:
        # Reset settings if any
        os.system(f"rm -rf {DOMAIN_SETTINGS_DIR}/{TEST_DOMAINS[0]}.yml")

    if not _get_maindomain() == TEST_DOMAINS[0]:
        domain_main_domain(TEST_DOMAINS[0])

    # Clear other domains
    for domain in domains:
        if (
            domain not in TEST_DOMAINS or domain == TEST_DOMAINS[2]
        ) and domain != TEST_DYNDNS_DOMAIN:
            # Clean domains not used for testing
            domain_remove(domain)
        elif domain in TEST_DOMAINS:
            # Reset settings if any
            os.system(f"rm -rf {DOMAIN_SETTINGS_DIR}/{domain}.yml")

    # Create classical second domain of not exist
    if TEST_DOMAINS[1] not in domains:
        domain_add(TEST_DOMAINS[1])

    # Third domain is not created

    clean()


def teardown_function(function):
    clean()


def clean():
    pass


# Domains management testing
def test_domain_add():
    assert TEST_DOMAINS[2] not in domain_list()["domains"]
    domain_add(TEST_DOMAINS[2])
    assert TEST_DOMAINS[2] in domain_list()["domains"]


def test_domain_add_and_remove_dyndns():
    time.sleep(35)  # Dynette blocks requests that happen too frequently
    assert TEST_DYNDNS_DOMAIN not in domain_list()["domains"]
    domain_add(TEST_DYNDNS_DOMAIN, dyndns_recovery_password=TEST_DYNDNS_PASSWORD)
    assert TEST_DYNDNS_DOMAIN in domain_list()["domains"]
    domain_remove(TEST_DYNDNS_DOMAIN, dyndns_recovery_password=TEST_DYNDNS_PASSWORD)
    assert TEST_DYNDNS_DOMAIN not in domain_list()["domains"]


def test_domain_dyndns_recovery():
    # time.sleep(35)
    assert TEST_DYNDNS_DOMAIN not in domain_list()["domains"]
    # add domain without recovery password
    domain_add(TEST_DYNDNS_DOMAIN)
    assert TEST_DYNDNS_DOMAIN in domain_list()["domains"]
    # set the recovery password with config panel
    domain_config_set(TEST_DYNDNS_DOMAIN, "dns.registrar.recovery_password", TEST_DYNDNS_PASSWORD)
    # remove domain without unsubscribing
    domain_remove(TEST_DYNDNS_DOMAIN, ignore_dyndns=True)
    assert TEST_DYNDNS_DOMAIN not in domain_list()["domains"]
    # readding domain with bad password should fail
    with pytest.raises(YunohostValidationError):
        domain_add(
            TEST_DYNDNS_DOMAIN, dyndns_recovery_password="wrong" + TEST_DYNDNS_PASSWORD
        )
    assert TEST_DYNDNS_DOMAIN not in domain_list()["domains"]
    # readding domain with password should work
    domain_add(TEST_DYNDNS_DOMAIN, dyndns_recovery_password=TEST_DYNDNS_PASSWORD)
    assert TEST_DYNDNS_DOMAIN in domain_list()["domains"]
    # remove the dyndns domain
    domain_remove(TEST_DYNDNS_DOMAIN, dyndns_recovery_password=TEST_DYNDNS_PASSWORD)
    assert TEST_DYNDNS_DOMAIN not in domain_list()["domains"]


def test_domain_add_existing_domain():
    with pytest.raises(MoulinetteError):
        assert TEST_DOMAINS[1] in domain_list()["domains"]
        domain_add(TEST_DOMAINS[1])


def test_domain_remove():
    assert TEST_DOMAINS[1] in domain_list()["domains"]
    domain_remove(TEST_DOMAINS[1])
    assert TEST_DOMAINS[1] not in domain_list()["domains"]


def test_main_domain():
    current_main_domain = _get_maindomain()
    assert domain_main_domain()["current_main_domain"] == current_main_domain


def test_main_domain_change_unknown():
    with pytest.raises(YunohostValidationError):
        domain_main_domain(TEST_DOMAINS[2])


def test_change_main_domain():
    assert _get_maindomain() != TEST_DOMAINS[1]
    domain_main_domain(TEST_DOMAINS[1])
    assert _get_maindomain() == TEST_DOMAINS[1]


# Domain settings testing
def test_domain_config_get_default():
    assert domain_config_get(TEST_DOMAINS[0], "feature.xmpp.xmpp") == 1
    assert domain_config_get(TEST_DOMAINS[1], "feature.xmpp.xmpp") == 0


def test_domain_config_get_export():
    assert domain_config_get(TEST_DOMAINS[0], export=True)["xmpp"] == 1
    assert domain_config_get(TEST_DOMAINS[1], export=True)["xmpp"] == 0


def test_domain_config_set():
    assert domain_config_get(TEST_DOMAINS[1], "feature.xmpp.xmpp") == 0
    domain_config_set(TEST_DOMAINS[1], "feature.xmpp.xmpp", "yes")
    assert domain_config_get(TEST_DOMAINS[1], "feature.xmpp.xmpp") == 1


def test_domain_configs_unknown():
    with pytest.raises(YunohostError):
        domain_config_get(TEST_DOMAINS[2], "feature.xmpp.xmpp.xmpp")
