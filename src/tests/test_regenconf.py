import os

from .conftest import message
from yunohost.domain import domain_add, domain_remove, domain_list
from yunohost.regenconf import (
    regen_conf,
    manually_modified_files,
    _get_conf_hashes,
    _force_clear_hashes,
)

TEST_DOMAIN = "secondarydomain.test"
TEST_DOMAIN_NGINX_CONFIG = "/etc/nginx/conf.d/%s.conf" % TEST_DOMAIN
TEST_DOMAIN_DNSMASQ_CONFIG = "/etc/dnsmasq.d/%s" % TEST_DOMAIN
SSHD_CONFIG = "/etc/ssh/sshd_config"


def setup_function(function):

    _force_clear_hashes([TEST_DOMAIN_NGINX_CONFIG])
    clean()


def teardown_function(function):

    clean()
    _force_clear_hashes([TEST_DOMAIN_NGINX_CONFIG])


def clean():

    assert os.system("pgrep slapd >/dev/null") == 0
    assert os.system("pgrep nginx >/dev/null") == 0

    if TEST_DOMAIN in domain_list()["domains"]:
        domain_remove(TEST_DOMAIN)
        assert not os.path.exists(TEST_DOMAIN_NGINX_CONFIG)

    os.system("rm -f %s" % TEST_DOMAIN_NGINX_CONFIG)

    assert os.system("nginx -t 2>/dev/null") == 0

    assert not os.path.exists(TEST_DOMAIN_NGINX_CONFIG)
    assert TEST_DOMAIN_NGINX_CONFIG not in _get_conf_hashes("nginx")
    assert TEST_DOMAIN_NGINX_CONFIG not in manually_modified_files()

    regen_conf(["ssh"], force=True)


def test_add_domain():

    domain_add(TEST_DOMAIN)

    assert TEST_DOMAIN in domain_list()["domains"]

    assert os.path.exists(TEST_DOMAIN_NGINX_CONFIG)

    assert TEST_DOMAIN_NGINX_CONFIG in _get_conf_hashes("nginx")
    assert TEST_DOMAIN_NGINX_CONFIG not in manually_modified_files()


def test_add_and_edit_domain_conf():

    domain_add(TEST_DOMAIN)

    assert os.path.exists(TEST_DOMAIN_NGINX_CONFIG)
    assert TEST_DOMAIN_NGINX_CONFIG in _get_conf_hashes("nginx")
    assert TEST_DOMAIN_NGINX_CONFIG not in manually_modified_files()

    os.system("echo ' ' >> %s" % TEST_DOMAIN_NGINX_CONFIG)

    assert TEST_DOMAIN_NGINX_CONFIG in manually_modified_files()


def test_add_domain_conf_already_exists():

    os.system("echo ' ' >> %s" % TEST_DOMAIN_NGINX_CONFIG)

    domain_add(TEST_DOMAIN)

    assert os.path.exists(TEST_DOMAIN_NGINX_CONFIG)
    assert TEST_DOMAIN_NGINX_CONFIG in _get_conf_hashes("nginx")
    assert TEST_DOMAIN_NGINX_CONFIG not in manually_modified_files()


def test_ssh_conf_unmanaged():

    _force_clear_hashes([SSHD_CONFIG])

    assert SSHD_CONFIG not in _get_conf_hashes("ssh")

    regen_conf()

    assert SSHD_CONFIG in _get_conf_hashes("ssh")


def test_ssh_conf_unmanaged_and_manually_modified(mocker):

    _force_clear_hashes([SSHD_CONFIG])
    os.system("echo ' ' >> %s" % SSHD_CONFIG)

    assert SSHD_CONFIG not in _get_conf_hashes("ssh")

    regen_conf()

    assert SSHD_CONFIG in _get_conf_hashes("ssh")
    assert SSHD_CONFIG in manually_modified_files()

    with message(mocker, "regenconf_need_to_explicitly_specify_ssh"):
        regen_conf(force=True)

    assert SSHD_CONFIG in _get_conf_hashes("ssh")
    assert SSHD_CONFIG in manually_modified_files()

    regen_conf(["ssh"], force=True)

    assert SSHD_CONFIG in _get_conf_hashes("ssh")
    assert SSHD_CONFIG not in manually_modified_files()


def test_stale_hashes_get_removed_if_empty():
    """
    This is intended to test that if a file gets removed and is indeed removed,
    we don't keep a useless empty hash corresponding to an old file.
    In this case, we test this using the dnsmasq conf file (we don't do this
    using the nginx conf file because it's already force-removed during
    domain_remove())
    """

    domain_add(TEST_DOMAIN)

    assert os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
    assert TEST_DOMAIN_DNSMASQ_CONFIG in _get_conf_hashes("dnsmasq")

    domain_remove(TEST_DOMAIN)

    assert not os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
    assert TEST_DOMAIN_DNSMASQ_CONFIG not in _get_conf_hashes("dnsmasq")


def test_stale_hashes_if_file_manually_deleted():
    """
    Same as other test, but manually delete the file in between and check
    behavior
    """

    domain_add(TEST_DOMAIN)

    assert os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
    assert TEST_DOMAIN_DNSMASQ_CONFIG in _get_conf_hashes("dnsmasq")

    os.remove(TEST_DOMAIN_DNSMASQ_CONFIG)

    assert not os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)

    regen_conf(names=["dnsmasq"])

    assert not os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
    assert TEST_DOMAIN_DNSMASQ_CONFIG in _get_conf_hashes("dnsmasq")

    domain_remove(TEST_DOMAIN)

    assert not os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
    assert TEST_DOMAIN_DNSMASQ_CONFIG not in _get_conf_hashes("dnsmasq")


# This test only works if you comment the part at the end of the regen-conf in
# dnsmasq that auto-flag /etc/dnsmasq.d/foo.bar as "to be removed" (using touch)
# ... But we want to keep it because they also possibly flag files that were
# never known by the regen-conf (e.g. if somebody adds a
# /etc/dnsmasq.d/my.custom.extension)
# Ideally we could use a system that's able to properly state 'no file in this
# folder should exist except the ones excplicitly defined by regen-conf' but
# that's too much work for the scope of this commit.
#
# ... Anyway, the proper way to write these tests would be to use a dummy
# regen-conf hook just for tests but meh I'm lazy
#
# def test_stale_hashes_if_file_manually_modified():
#    """
#    Same as other test, but manually delete the file in between and check
#    behavior
#    """
#
#    domain_add(TEST_DOMAIN)
#
#    assert os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
#    assert TEST_DOMAIN_DNSMASQ_CONFIG in _get_conf_hashes("dnsmasq")
#
#    os.system("echo '#pwet' > %s" % TEST_DOMAIN_DNSMASQ_CONFIG)
#
#    assert os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
#    assert open(TEST_DOMAIN_DNSMASQ_CONFIG).read().strip() == "#pwet"
#
#    regen_conf(names=["dnsmasq"])
#
#    assert os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
#    assert open(TEST_DOMAIN_DNSMASQ_CONFIG).read().strip() == "#pwet"
#    assert TEST_DOMAIN_DNSMASQ_CONFIG in _get_conf_hashes("dnsmasq")
#
#    domain_remove(TEST_DOMAIN)
#
#    assert os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
#    assert open(TEST_DOMAIN_DNSMASQ_CONFIG).read().strip() == "#pwet"
#    assert TEST_DOMAIN_DNSMASQ_CONFIG in _get_conf_hashes("dnsmasq")
#
#    regen_conf(names=["dnsmasq"], force=True)
#
#    assert not os.path.exists(TEST_DOMAIN_DNSMASQ_CONFIG)
#    assert TEST_DOMAIN_DNSMASQ_CONFIG not in _get_conf_hashes("dnsmasq")
