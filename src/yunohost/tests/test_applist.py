import os
import pytest
import requests
import requests_mock
import glob
import time

from moulinette.core import MoulinetteError

from yunohost.app import app_fetchlist, app_removelist, app_listlists, _using_legacy_applist_system, _migrate_applist_system, _register_new_applist

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

    if os.path.exists("/etc/cron.daily/yunohost-fetch-applists"):
        os.remove("/etc/cron.daily/yunohost-fetch-applists")


def teardown_function(function):
    pass


###############################################################################
#   Test listing of applists and registering of applists                      #
###############################################################################


def test_applist_list_empty():
    """
    Calling app_listlists() with no registered list should return empty dict
    """

    assert app_listlists() == {}


def test_applist_list_register():
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
    with pytest.raises(MoulinetteError):
        _register_new_applist("https://lol.com/applist.json", "dummy2")

    applist_dict = app_listlists()

    assert "dummy" in applist_dict.keys()
    assert "dummy2" not in applist_dict.keys()


def test_applist_list_register_conflict_url():
    """
    Register two lists with url conflicts
    """

    _register_new_applist("https://lol.com/applist.json", "dummy")
    with pytest.raises(MoulinetteError):
        _register_new_applist("https://lol.com/applist.json", "plopette")

    applist_dict = app_listlists()

    assert "dummy" in applist_dict.keys()
    assert "plopette" not in applist_dict.keys()


###############################################################################
#   Test fetching of applists                                                 #
###############################################################################


def test_applist_fetch():
    """
    Do a fetchlist and test yunohost.json got updated.
    """
    assert app_listlists() == {}

    _register_new_applist(URL_OFFICIAL_APP_LIST, "yunohost")
    # Put some dummy content in the json
    with open(REPO_PATH+"/yunohost.json", "w") as f:
        f.write("Dummy content")

    with requests_mock.Mocker() as m:

        # Mock the server response with a valid (well, empty, yep) json
        m.register_uri("GET", URL_OFFICIAL_APP_LIST, text='{ }')

        official_json_ctime = os.path.getctime(REPO_PATH+"/yunohost.json")
        app_fetchlist()
        new_official_json_ctime = os.path.getctime(REPO_PATH+"/yunohost.json")

    assert new_official_json_ctime > official_json_ctime


def test_applist_fetch_single_applist():
    """
    Register several list but only fetch one
    """

    assert app_listlists() == {}
    _register_new_applist(URL_OFFICIAL_APP_LIST, "yunohost")
    _register_new_applist("https://lol.com/applist.json", "dummy")
    # Put some dummy content in the json
    with open(REPO_PATH+"/yunohost.json", "w") as f:
        f.write("Dummy content")
    with open(REPO_PATH+"/dummy.json", "w") as f:
        f.write("Dummy content")

    time.sleep(1)

    with requests_mock.Mocker() as m:

        # Mock the server response with a valid (well, empty, yep) json
        m.register_uri("GET", URL_OFFICIAL_APP_LIST, text='{ }')

        official_json_ctime = os.path.getctime(REPO_PATH+"/yunohost.json")
        dummy_json_ctime = os.path.getctime(REPO_PATH+"/dummy.json")
        app_fetchlist(name="yunohost")
        new_official_json_ctime = os.path.getctime(REPO_PATH+"/yunohost.json")
        new_dummy_json_ctime = os.path.getctime(REPO_PATH+"/dummy.json")

    assert new_official_json_ctime > official_json_ctime
    assert new_dummy_json_ctime == dummy_json_ctime


def test_applist_fetch_customurl_noname():
    """
    Do a fetchlist with a custom url but no name
    """

    with pytest.raises(MoulinetteError):
        app_fetchlist(url=URL_OFFICIAL_APP_LIST)


def test_applist_fetch_unknownlist():
    """
    Do a fetchlist with a name of list that does not exists
    """

    assert app_listlists() == {}

    with pytest.raises(MoulinetteError):
        app_fetchlist(name="swag")


def test_applist_fetch_badurl():
    """
    Do a fetchlist with a bad url
    """

    with pytest.raises(MoulinetteError):
        app_fetchlist(url="https://not.a.valid.url/plop.json", name="plop")


def test_applist_fetch_badfile():
    """
    Do a fetchlist and mock a response with a bad bada 404 or something
    """
    assert app_listlists() == {}

    _register_new_applist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST, text='{ not json lol }')

        with pytest.raises(MoulinetteError):
            app_fetchlist()


def test_applist_fetch_404():
    """
    Do a fetchlist and mock a 404 response
    """
    assert app_listlists() == {}

    _register_new_applist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST, status_code=404)

        with pytest.raises(MoulinetteError):
            app_fetchlist()


def test_applist_fetch_timeout():
    """
    Do a fetchlist and mock a timeout
    """
    assert app_listlists() == {}

    _register_new_applist(URL_OFFICIAL_APP_LIST, "yunohost")

    with requests_mock.Mocker() as m:

        m.register_uri("GET", URL_OFFICIAL_APP_LIST,
                       exc=requests.exceptions.ConnectTimeout)

        with pytest.raises(MoulinetteError):
            app_fetchlist()


###############################################################################
#   Test remove of applist                                                    #
###############################################################################


def test_applist_remove():
    """
    Attempt to remove an unknown list
    """

    # Assume we're starting with an empty app list
    assert app_listlists() == {}

    # Register a new dummy list
    _register_new_applist("https://lol.com/applist.json", "dummy")
    app_removelist("dummy")

    # Should end up with no list registered
    assert app_listlists() == {}


def test_applist_remove_unknown():
    """
    Register a new list then remove it
    """

    with pytest.raises(MoulinetteError):
        app_removelist("dummy")


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
    assert not os.path.exists("/etc/cron.daily/yunohost-fetch-applists")

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
    
    assert os.path.exists("/etc/cron.daily/yunohost-fetch-applists")


def test_applist_system_migration_badcron():
    """
    Test the migration on a bad legacy cron (no url found inside cron job)
    """

    # Start with no legacy cron, no applist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}
    assert not os.path.exists("/etc/cron.daily/yunohost-fetch-applists")

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
    
    assert os.path.exists("/etc/cron.daily/yunohost-fetch-applists")


def test_applist_system_migration_conflict():
    """
    Test migration of conflicting cron job (in terms of url)
    """

    # Start with no legacy cron, no applist registered
    assert glob.glob("/etc/cron.d/yunohost-applist-*") == []
    assert app_listlists() == {}
    assert not os.path.exists("/etc/cron.daily/yunohost-fetch-applists")

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
    
    assert os.path.exists("/etc/cron.daily/yunohost-fetch-applists")
