#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
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

import base64

import pytest
from yunohost.dns import (
    DOMAIN_REGISTRAR_LIST_PATH,
    _build_dns_conf,
    _get_dns_zone_for_domain,
    _get_registrar_config_section,
    _normalize_txt_content,
)
from yunohost.domain import domain_add, domain_remove
from yunohost.utils.file_utils import read_toml


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


def test_normalize_txt_content():
    # A split DKIM key and its flat form must normalize the same, otherwise
    # 'domain dns push' keeps proposing the very same record
    key = base64.b64encode(b"x" * 1000).decode()
    value = f"v=DKIM1; h=sha256; k=rsa; p={key}"
    flat = f'"{value}"'

    # A character-string is limited to 255 chars, so registrars cut there
    chunks = [value[i : i + 255] for i in range(0, len(value), 255)]
    assert len(chunks) > 1
    split = " ".join(f'"{c}"' for c in chunks)

    assert _normalize_txt_content(split) == flat
    assert _normalize_txt_content(flat) == flat

    # Shorter, non-split values are left untouched
    assert _normalize_txt_content('"v=spf1 a mx -all"') == '"v=spf1 a mx -all"'
    assert _normalize_txt_content('"v=DMARC1; p=none"') == '"v=DMARC1; p=none"'

    # Some registrars return values without the surrounding quotes
    assert _normalize_txt_content("v=spf1 a mx -all") == '"v=spf1 a mx -all"'

    # An escaped quote is not a chunk boundary
    assert _normalize_txt_content(r'"say \" ok"') == r'"say \" ok"'


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
