import pytest

import yaml
import os

from moulinette.core import MoulinetteError

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.dns import get_dns_zone_from_domain
from yunohost.domain import (
    DOMAIN_SETTINGS_DIR,
    REGISTRAR_LIST_PATH,
    _get_maindomain,
    domain_add,
    domain_remove,
    domain_list,
    domain_main_domain,
    domain_setting,
    domain_dns_conf,
    domain_registrar_set,
    domain_registrar_catalog
)

TEST_DOMAINS = [
    "example.tld",
    "sub.example.tld",
    "other-example.com"
]

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
        if domain not in TEST_DOMAINS or domain == TEST_DOMAINS[2]:
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

def test_domain_add_existing_domain():
    with pytest.raises(MoulinetteError) as e_info:
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
    with pytest.raises(YunohostValidationError) as e_info:
        domain_main_domain(TEST_DOMAINS[2])

def test_change_main_domain():
    assert _get_maindomain() != TEST_DOMAINS[1]
    domain_main_domain(TEST_DOMAINS[1])
    assert _get_maindomain() ==  TEST_DOMAINS[1]

# Domain settings testing
def test_domain_setting_get_default_xmpp_main_domain():
    assert TEST_DOMAINS[0] in domain_list()["domains"]
    assert domain_setting(TEST_DOMAINS[0], "xmpp") == True

def test_domain_setting_get_default_xmpp():
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False

def test_domain_setting_get_default_ttl():
    assert domain_setting(TEST_DOMAINS[1], "ttl") == 3600

def test_domain_setting_set_int():
    domain_setting(TEST_DOMAINS[1], "ttl", "10")
    assert domain_setting(TEST_DOMAINS[1], "ttl") == 10

def test_domain_setting_set_bool_true():
    domain_setting(TEST_DOMAINS[1], "xmpp", "True")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == True
    domain_setting(TEST_DOMAINS[1], "xmpp", "true")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == True
    domain_setting(TEST_DOMAINS[1], "xmpp", "t")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == True
    domain_setting(TEST_DOMAINS[1], "xmpp", "1")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == True
    domain_setting(TEST_DOMAINS[1], "xmpp", "yes")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == True
    domain_setting(TEST_DOMAINS[1], "xmpp", "y")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == True

def test_domain_setting_set_bool_false():
    domain_setting(TEST_DOMAINS[1], "xmpp", "False")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False
    domain_setting(TEST_DOMAINS[1], "xmpp", "false")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False
    domain_setting(TEST_DOMAINS[1], "xmpp", "f")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False
    domain_setting(TEST_DOMAINS[1], "xmpp", "0")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False
    domain_setting(TEST_DOMAINS[1], "xmpp", "no")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False
    domain_setting(TEST_DOMAINS[1], "xmpp", "n")
    assert domain_setting(TEST_DOMAINS[1], "xmpp") == False

def test_domain_settings_unknown():
    with pytest.raises(YunohostValidationError) as e_info:
        domain_setting(TEST_DOMAINS[2], "xmpp", "False")

# DNS utils testing
def test_get_dns_zone_from_domain_existing():
    assert get_dns_zone_from_domain("donate.yunohost.org") == "yunohost.org"

def test_get_dns_zone_from_domain_not_existing():
    assert get_dns_zone_from_domain("non-existing-domain.yunohost.org") == "yunohost.org"

# Domain registrar testing
def test_registrar_list_yaml_integrity():
    yaml.load(open(REGISTRAR_LIST_PATH, 'r'))

def test_domain_registrar_catalog():
    domain_registrar_catalog()

def test_domain_registrar_catalog_full():
    domain_registrar_catalog(None, True)

def test_domain_registrar_catalog_registrar():
    domain_registrar_catalog("ovh")
