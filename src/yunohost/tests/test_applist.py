import os
import pytest
import requests
import requests_mock
import glob

from moulinette.core import MoulinetteError

from yunohost.app import app_fetchlist, app_listlists, _using_legacy_applist_system, _migrate_applist_system, _register_new_applist

LOCAL_OFFICIAL_APP_LIST = "/var/cache/yunohost/repo/yunohost.json"
URL_OFFICIAL_APP_LIST = "https://app.yunohost.org/official.json"
REPO_PATH = '/var/cache/yunohost/repo'


def setup_function(function):

    # Clear all applist
    files = glob.glob(REPO_PATH+"/*")
    for f in files:
        os.remove(f)

    # Clear applist crons
    files = glob.glob("/etc/cron.d/yunohost-applist-*")
    for f in files:
        os.remove(f)


def teardown_function(function):
    pass

###############################################################################
#   Test applist_list                                                         #
###############################################################################

def test_applist_list_empty():
    """
    Calling app_listlists() with no registered list should return empty dict
    """

    assert app_listlists() == {}

###############################################################################
#   Test applist register                                                     #
###############################################################################

def test_applist_list_register_standard():
    """
    Register a new list (no conflicts with existing list)
    """

    # Assume we're starting with an empty app list
    assert app_listlists() == {}

    # Register a new dummy list
    _register_new_applist("https://lol.com/applist.json", "dummy")

    applist_dict = app_listlists()
    assert applist_dict["dummy"] == "https://lol.com/applist.json"


def test_applist_list_register_conflict_name():
    """
    Register a new list (no conflicts with existing list)
    """

    # Register a new dummy list
    _register_new_applist("https://lol.com/applist.json", "dummy")

    applist_dict = app_listlists()
    assert applist_dict["dummy"] == "https://lol.com/applist.json"

def test_applist_list_register_conflict_url():

    pass

###############################################################################
#   Test migration from legacy applist system                                 #
###############################################################################


def add_legacy_cron(name, url):
    with open("/etc/cron.d/yunohost-applist-%s" % name, "w") as f:
        f.write('00 00 * * * root yunohost app fetchlist -u %s -n %s > /dev/null 2>&1\n' % (url, name))


def test_applist_check_using_legacy_system_testFalse():
    """
    If no legacy cron job is there, the check should return False
    """
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert _using_legacy_applist_system() is False


def test_applist_check_using_legacy_system_testTrue():
    """
    If there's a legacy cron job, the check should return True
    """
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    add_legacy_cron("yunohost", "https://app.yunohost.org/official.json")
    assert _using_legacy_applist_system() is True


def test_applist_system_migration():
    """
    Test that legacy cron jobs get migrated correctly when calling applist
    """

    # Start with no legacy cron, no applist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}

    # Add a few legacy crons
    add_legacy_cron("yunohost", "https://app.yunohost.org/official.json")
    add_legacy_cron("dummy", "https://swiggitty.swaggy.lol/yolo.json")

    # Migrate
    assert _using_legacy_applist_system() is True
    _migrate_applist_system()
    assert _using_legacy_applist_system() is False

    # No legacy cron job should remain, and we should have the new .url now
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []

    # Check they are in app_listlists anyway
    applist_dict = app_listlists()
    assert applist_dict["yunohost"] == "https://app.yunohost.org/official.json"
    assert applist_dict["dummy"] == "https://swiggitty.swaggy.lol/yolo.json"


def test_applist_system_migration_badcron():
    """
    Test the migration on a bad legacy cron (no url found inside cron job)
    """

    # Start with no legacy cron, no applist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}

    # Add a "bad" legacy cron
    add_legacy_cron("wtflist", "ftp://the.fuck.is.this")

    # Migrate
    assert _using_legacy_applist_system() is True
    _migrate_applist_system()
    assert _using_legacy_applist_system() is False

    # No legacy cron should remain, but it should be backuped in /etc/yunohost
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert not os.path.exists(REPO_PATH+"/wtflist.url")
    assert os.path.exists("/etc/yunohost/wtflist.oldlist.bkp")

    # Applist should still be empty
    assert app_listlists() == {}


def test_applist_system_migration_conflict():
    """
    Test migration of conflicting cron job (in terms of url)
    """

    # Start with no legacy cron, no applist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}

    # Add a few legacy crons
    add_legacy_cron("yunohost", "https://app.yunohost.org/official.json")
    add_legacy_cron("dummy", "https://app.yunohost.org/official.json")

    # Migrate
    assert _using_legacy_applist_system() is True
    _migrate_applist_system()
    assert _using_legacy_applist_system() is False

    # No legacy cron job should remain, and we should have the new .url now
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []

    # Only dummy should be listed (bc of alphabetical order during migration)
    applist_dict = app_listlists()
    assert applist_dict["dummy"] == "https://app.yunohost.org/official.json"
    assert "yunohost" not in applist_dict.keys()



