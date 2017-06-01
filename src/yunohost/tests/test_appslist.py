import os
import pytest
import requests
import requests_mock
import glob
import time

from moulinette.core import MoulinetteError

from yunohost.app import app_fetchlist, app_removelist, app_listlists, _using_legacy_appslist_system, _migrate_appslist_system, _register_new_appslist

URL_OFFICIAL_APP_LIST = "https://app.yunohost.org/official.json"
REPO_PATH = '/var/cache/yunohost/repo'
APPSLISTS_JSON = '/etc/yunohost/appslists.json'


def setup_function(function):

    # Clear all appslist
    files = glob.glob(REPO_PATH+"/*")
    for f in files:
        os.remove(f)

    # Clear appslist crons
    files = glob.glob("/etc/cron.d/yunohost-applist-*")
    for f in files:
        os.remove(f)

    if os.path.exists("/etc/cron.daily/yunohost-fetch-appslists"):
        os.remove("/etc/cron.daily/yunohost-fetch-appslists")

    if os.path.exists(APPSLISTS_JSON):
        os.remove(APPSLISTS_JSON)


def teardown_function(function):
    pass


def cron_job_is_there():
    r = os.system("run-parts -v --test /etc/cron.daily/ | grep yunohost-fetch-appslists")
    return r == 0


###############################################################################
#   Test listing of appslists and registering of appslists                      #
###############################################################################


def test_appslist_list_empty():
    """
    Calling app_listlists() with no registered list should return empty dict
    """

    assert app_listlists() == {}


def test_appslist_list_register():
    """
    Register a new list
    """

    # Assume we're starting with an empty app list
    assert app_listlists() == {}

    # Register a new dummy list
    _register_new_appslist("https://lol.com/appslist.json", "dummy")

    appslist_dict = app_listlists()
    assert "dummy" in appslist_dict.keys()
    assert appslist_dict["dummy"]["url"] == "https://lol.com/appslist.json"

    assert cron_job_is_there()


def test_appslist_list_register_conflict_name():
    """
    Attempt to register a new list with conflicting name
    """

    _register_new_appslist("https://lol.com/appslist.json", "dummy")
    with pytest.raises(MoulinetteError):
        _register_new_appslist("https://lol.com/appslist2.json", "dummy")

    appslist_dict = app_listlists()

    assert "dummy" in appslist_dict.keys()
    assert "dummy2" not in appslist_dict.keys()


def test_appslist_list_register_conflict_url():
    """
    Attempt to register a new list with conflicting url
    """

    _register_new_appslist("https://lol.com/appslist.json", "dummy")
    with pytest.raises(MoulinetteError):
        _register_new_appslist("https://lol.com/appslist.json", "plopette")

    appslist_dict = app_listlists()

    assert "dummy" in appslist_dict.keys()
    assert "plopette" not in appslist_dict.keys()


###############################################################################
#   Test fetching of appslists                                                 #
###############################################################################


def test_appslist_fetch():
    """
    Do a fetchlist and test the .json got updated.
    """
    assert app_listlists() == {}

    _register_new_appslist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        # Mock the server response with a valid (well, empty, yep) json
        m.register_uri("GET", URL_OFFICIAL_APP_LIST, text='{ }')

        official_lastUpdate = app_listlists()["yunohost"]["lastUpdate"]
        app_fetchlist()
        new_official_lastUpdate = app_listlists()["yunohost"]["lastUpdate"]

    assert new_official_lastUpdate > official_lastUpdate


def test_appslist_fetch_single_appslist():
    """
    Register several lists but only fetch one. Check only one got updated.
    """

    assert app_listlists() == {}
    _register_new_appslist(URL_OFFICIAL_APP_LIST, "yunohost")
    _register_new_appslist("https://lol.com/appslist.json", "dummy")

    time.sleep(1)

    with requests_mock.Mocker() as m:

        # Mock the server response with a valid (well, empty, yep) json
        m.register_uri("GET", URL_OFFICIAL_APP_LIST, text='{ }')

        official_lastUpdate = app_listlists()["yunohost"]["lastUpdate"]
        dummy_lastUpdate = app_listlists()["dummy"]["lastUpdate"]
        app_fetchlist(name="yunohost")
        new_official_lastUpdate = app_listlists()["yunohost"]["lastUpdate"]
        new_dummy_lastUpdate = app_listlists()["dummy"]["lastUpdate"]

    assert new_official_lastUpdate > official_lastUpdate
    assert new_dummy_lastUpdate == dummy_lastUpdate


def test_appslist_fetch_unknownlist():
    """
    Attempt to fetch an unknown list
    """

    assert app_listlists() == {}

    with pytest.raises(MoulinetteError):
        app_fetchlist(name="swag")


def test_appslist_fetch_url_but_no_name():
    """
    Do a fetchlist with url given, but no name given
    """

    with pytest.raises(MoulinetteError):
        app_fetchlist(url=URL_OFFICIAL_APP_LIST)


def test_appslist_fetch_badurl():
    """
    Do a fetchlist with a bad url
    """

    app_fetchlist(url="https://not.a.valid.url/plop.json", name="plop")


def test_appslist_fetch_badfile():
    """
    Do a fetchlist and mock a response with a bad json
    """
    assert app_listlists() == {}

    _register_new_appslist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST, text='{ not json lol }')

        app_fetchlist()


def test_appslist_fetch_404():
    """
    Do a fetchlist and mock a 404 response
    """
    assert app_listlists() == {}

    _register_new_appslist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST, status_code=404)

        app_fetchlist()


def test_appslist_fetch_sslerror():
    """
    Do a fetchlist and mock an SSL error
    """
    assert app_listlists() == {}

    _register_new_appslist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST,
                       exc=requests.exceptions.SSLError)

        app_fetchlist()


def test_appslist_fetch_timeout():
    """
    Do a fetchlist and mock a timeout
    """
    assert app_listlists() == {}

    _register_new_appslist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST,
                       exc=requests.exceptions.ConnectTimeout)

        app_fetchlist()


###############################################################################
#   Test remove of appslist                                                    #
###############################################################################


def test_appslist_remove():
    """
    Register a new appslist, then remove it
    """

    # Assume we're starting with an empty app list
    assert app_listlists() == {}

    # Register a new dummy list
    _register_new_appslist("https://lol.com/appslist.json", "dummy")
    app_removelist("dummy")

    # Should end up with no list registered
    assert app_listlists() == {}


def test_appslist_remove_unknown():
    """
    Attempt to remove an unknown list
    """

    with pytest.raises(MoulinetteError):
        app_removelist("dummy")


###############################################################################
#   Test migration from legacy appslist system                                 #
###############################################################################


def add_legacy_cron(name, url):
    with open("/etc/cron.d/yunohost-applist-%s" % name, "w") as f:
        f.write('00 00 * * * root yunohost app fetchlist -u %s -n %s > /dev/null 2>&1\n' % (url, name))


def test_appslist_check_using_legacy_system_testFalse():
    """
    If no legacy cron job is there, the check should return False
    """
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert _using_legacy_appslist_system() is False


def test_appslist_check_using_legacy_system_testTrue():
    """
    If there's a legacy cron job, the check should return True
    """
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    add_legacy_cron("yunohost", "https://app.yunohost.org/official.json")
    assert _using_legacy_appslist_system() is True


def test_appslist_system_migration():
    """
    Test that legacy cron jobs get migrated correctly when calling app_listlists
    """

    # Start with no legacy cron, no appslist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}
    assert not os.path.exists("/etc/cron.daily/yunohost-fetch-appslists")

    # Add a few legacy crons
    add_legacy_cron("yunohost", "https://app.yunohost.org/official.json")
    add_legacy_cron("dummy", "https://swiggitty.swaggy.lol/yolo.json")

    # Migrate
    assert _using_legacy_appslist_system() is True
    _migrate_appslist_system()
    assert _using_legacy_appslist_system() is False

    # No legacy cron job should remain
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []

    # Check they are in app_listlists anyway
    appslist_dict = app_listlists()
    assert "yunohost" in appslist_dict.keys()
    assert appslist_dict["yunohost"]["url"] == "https://app.yunohost.org/official.json"
    assert "dummy" in appslist_dict.keys()
    assert appslist_dict["dummy"]["url"] == "https://swiggitty.swaggy.lol/yolo.json"

    assert cron_job_is_there()


def test_appslist_system_migration_badcron():
    """
    Test the migration on a bad legacy cron (no url found inside cron job)
    """

    # Start with no legacy cron, no appslist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}
    assert not os.path.exists("/etc/cron.daily/yunohost-fetch-appslists")

    # Add a "bad" legacy cron
    add_legacy_cron("wtflist", "ftp://the.fuck.is.this")

    # Migrate
    assert _using_legacy_appslist_system() is True
    _migrate_appslist_system()
    assert _using_legacy_appslist_system() is False

    # No legacy cron should remain, but it should be backuped in /etc/yunohost
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert os.path.exists("/etc/yunohost/wtflist.oldlist.bkp")

    # Appslist should still be empty
    assert app_listlists() == {}


def test_appslist_system_migration_conflict():
    """
    Test migration of conflicting cron job (in terms of url)
    """

    # Start with no legacy cron, no appslist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}
    assert not os.path.exists("/etc/cron.daily/yunohost-fetch-appslists")

    # Add a few legacy crons
    add_legacy_cron("yunohost", "https://app.yunohost.org/official.json")
    add_legacy_cron("dummy", "https://app.yunohost.org/official.json")

    # Migrate
    assert _using_legacy_appslist_system() is True
    _migrate_appslist_system()
    assert _using_legacy_appslist_system() is False

    # No legacy cron job should remain
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []

    # Only one among "dummy" and "yunohost" should be listed
    appslist_dict = app_listlists()
    assert (len(appslist_dict.keys()) == 1)
    assert ("dummy" in appslist_dict.keys()) or ("yunohost" in appslist_dict.keys())

    assert cron_job_is_there()
