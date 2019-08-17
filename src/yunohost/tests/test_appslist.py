import os
import pytest
import requests
import requests_mock
import glob
import shutil

from moulinette import m18n
from moulinette.utils.filesystem import read_json, write_to_json, write_to_yaml, mkdir

from yunohost.utils.error import YunohostError
from yunohost.app import (_initialize_appslists_system,
                          _read_appslist_list,
                          _update_appslist,
                          _actual_appslist_api_url,
                          _load_appslist,
                          logger,
                          APPSLISTS_CACHE,
                          APPSLISTS_CONF,
                          APPSLISTS_CRON_PATH,
                          APPSLISTS_API_VERSION,
                          APPSLISTS_DEFAULT_URL)

APPSLISTS_DEFAULT_URL_FULL = _actual_appslist_api_url(APPSLISTS_DEFAULT_URL)
CRON_FOLDER, CRON_NAME = APPSLISTS_CRON_PATH.rsplit("/", 1)

DUMMY_APPLIST = """{
   "foo": {"id": "foo", "level": 4},
   "bar": {"id": "bar", "level": 7}
}
"""

class AnyStringWith(str):
    def __eq__(self, other):
        return self in other

def setup_function(function):

    # Clear applist cache
    shutil.rmtree(APPSLISTS_CACHE, ignore_errors=True)

    # Clear appslist cron
    if os.path.exists(APPSLISTS_CRON_PATH):
        os.remove(APPSLISTS_CRON_PATH)

    # Clear appslist conf
    if os.path.exists(APPSLISTS_CONF):
        os.remove(APPSLISTS_CONF)


def teardown_function(function):

    # Clear applist cache
    # Otherwise when using apps stuff after running the test,
    # we'll still have the dummy unusable list
    shutil.rmtree(APPSLISTS_CACHE, ignore_errors=True)


def cron_job_is_there():
    r = os.system("run-parts -v --test %s | grep %s" % (CRON_FOLDER, CRON_NAME))
    return r == 0

#
# ################################################
#


def test_appslist_init(mocker):

    # Cache is empty
    assert not glob.glob(APPSLISTS_CACHE + "/*")
    # Conf doesn't exist yet
    assert not os.path.exists(APPSLISTS_CONF)
    # Conf doesn't exist yet
    assert not os.path.exists(APPSLISTS_CRON_PATH)

    # Initialize ...
    mocker.spy(m18n, "n")
    _initialize_appslists_system()
    m18n.n.assert_any_call('appslist_init_success')

    # Then there's a cron enabled
    assert cron_job_is_there()

    # And a conf with at least one list
    assert os.path.exists(APPSLISTS_CONF)
    appslist_list = _read_appslist_list()
    assert len(appslist_list)

    # Cache is expected to still be empty though
    # (if we did update the appslist during init,
    # we couldn't differentiate easily exceptions
    # related to lack of network connectivity)
    assert not glob.glob(APPSLISTS_CACHE + "/*")


def test_appslist_emptylist():

    # Initialize ...
    _initialize_appslists_system()

    # Let's imagine somebody removed the default applist because uh idk they dont want to use our default applist
    os.system("rm %s" % APPSLISTS_CONF)
    os.system("touch %s" % APPSLISTS_CONF)

    appslist_list = _read_appslist_list()
    assert not len(appslist_list)


def test_appslist_update_success(mocker):

    # Initialize ...
    _initialize_appslists_system()

    # Cache is empty
    assert not glob.glob(APPSLISTS_CACHE + "/*")

    # Update
    with requests_mock.Mocker() as m:

        _actual_appslist_api_url,
        # Mock the server response with a dummy applist
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)

        mocker.spy(m18n, "n")
        _update_appslist()
        m18n.n.assert_any_call("appslist_updating")
        m18n.n.assert_any_call("appslist_update_success")

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPSLISTS_CACHE + "/*")

    app_dict = _load_appslist()
    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()


def test_appslist_update_404(mocker):

    # Initialize ...
    _initialize_appslists_system()

    with requests_mock.Mocker() as m:

        # 404 error
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL,
                       status_code=404)

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_appslist()
            m18n.n.assert_any_call("appslist_failed_to_download")

def test_appslist_update_timeout(mocker):

    # Initialize ...
    _initialize_appslists_system()

    with requests_mock.Mocker() as m:

        # Timeout
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL,
                       exc=requests.exceptions.ConnectTimeout)

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_appslist()
            m18n.n.assert_any_call("appslist_failed_to_download")


def test_appslist_update_sslerror(mocker):

    # Initialize ...
    _initialize_appslists_system()

    with requests_mock.Mocker() as m:

        # SSL error
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL,
                       exc=requests.exceptions.SSLError)

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_appslist()
            m18n.n.assert_any_call("appslist_failed_to_download")


def test_appslist_update_corrupted(mocker):

    # Initialize ...
    _initialize_appslists_system()

    with requests_mock.Mocker() as m:

        # Corrupted json
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL,
                       text=DUMMY_APPLIST[:-2])

        with pytest.raises(YunohostError):
            mocker.spy(m18n, "n")
            _update_appslist()
            m18n.n.assert_any_call("appslist_failed_to_download")


def test_appslist_load_with_empty_cache(mocker):

    # Initialize ...
    _initialize_appslists_system()

    # Cache is empty
    assert not glob.glob(APPSLISTS_CACHE + "/*")

    # Update
    with requests_mock.Mocker() as m:

        # Mock the server response with a dummy applist
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)

        # Try to load the applist
        # This should implicitly trigger an update in the background
        mocker.spy(m18n, "n")
        app_dict = _load_appslist()
        m18n.n.assert_any_call("appslist_obsolete_cache")
        m18n.n.assert_any_call("appslist_update_success")


    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPSLISTS_CACHE + "/*")

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()


def test_appslist_load_with_conflicts_between_lists(mocker):

    # Initialize ...
    _initialize_appslists_system()

    conf = [{"id": "default", "url": APPSLISTS_DEFAULT_URL},
            {"id": "default2", "url": APPSLISTS_DEFAULT_URL.replace("yunohost.org", "yolohost.org")}]

    write_to_yaml(APPSLISTS_CONF, conf)

    # Update
    with requests_mock.Mocker() as m:

        # Mock the server response with a dummy applist
        # + the same applist for the second list
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL.replace("yunohost.org", "yolohost.org"), text=DUMMY_APPLIST)

        # Try to load the applist
        # This should implicitly trigger an update in the background
        mocker.spy(logger, "warning")
        app_dict = _load_appslist()
        logger.warning.assert_any_call(AnyStringWith("Duplicate"))

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPSLISTS_CACHE + "/*")

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()


def test_appslist_load_with_oudated_api_version(mocker):

    # Initialize ...
    _initialize_appslists_system()

    # Update
    with requests_mock.Mocker() as m:

        mocker.spy(m18n, "n")
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)
        _update_appslist()

    # Cache shouldn't be empty anymore empty
    assert glob.glob(APPSLISTS_CACHE + "/*")

    # Tweak the cache to replace the from_api_version with a different one
    for cache_file in glob.glob(APPSLISTS_CACHE + "/*"):
        cache_json = read_json(cache_file)
        assert cache_json["from_api_version"] == APPSLISTS_API_VERSION
        cache_json["from_api_version"] = 0
        write_to_json(cache_file, cache_json)

    # Update
    with requests_mock.Mocker() as m:

        # Mock the server response with a dummy applist
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)

        mocker.spy(m18n, "n")
        app_dict = _load_appslist()
        m18n.n.assert_any_call("appslist_update_success")

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()

    # Check that we indeed have the new api number in cache
    for cache_file in glob.glob(APPSLISTS_CACHE + "/*"):
        cache_json = read_json(cache_file)
        assert cache_json["from_api_version"] == APPSLISTS_API_VERSION



def test_appslist_migrate_legacy_explicitly():

    open("/etc/yunohost/appslists.json", "w").write('{"yunohost": {"yolo":"swag"}}')
    mkdir(APPSLISTS_CACHE, 0o750, parents=True)
    open(APPSLISTS_CACHE+"/yunohost_old.json", "w").write('{"foo":{}, "bar": {}}')
    open(APPSLISTS_CRON_PATH, "w").write("# Some old cron")

    from yunohost.tools import _get_migration_by_name
    migration = _get_migration_by_name("futureproof_appslist_system")

    with requests_mock.Mocker() as m:

        # Mock the server response with a dummy applist
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)
        migration.migrate()

    # Old conf shouldnt be there anymore (got renamed to .old)
    assert not os.path.exists("/etc/yunohost/appslists.json")
    # Old cache should have been removed
    assert not os.path.exists(APPSLISTS_CACHE+"/yunohost_old.json")
    # Cron should have been changed
    assert "/bin/bash" in open(APPSLISTS_CRON_PATH, "r").read()
    assert cron_job_is_there()

    # Reading the appslist should work
    app_dict = _load_appslist()
    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()


def test_appslist_migrate_legacy_implicitly():

    open("/etc/yunohost/appslists.json", "w").write('{"yunohost": {"yolo":"swag"}}')
    mkdir(APPSLISTS_CACHE, 0o750, parents=True)
    open(APPSLISTS_CACHE+"/yunohost_old.json", "w").write('{"old_foo":{}, "old_bar": {}}')
    open(APPSLISTS_CRON_PATH, "w").write("# Some old cron")

    with requests_mock.Mocker() as m:
        m.register_uri("GET", APPSLISTS_DEFAULT_URL_FULL, text=DUMMY_APPLIST)
        app_dict = _load_appslist()

    assert "foo" in app_dict.keys()
    assert "bar" in app_dict.keys()

    # Old conf shouldnt be there anymore (got renamed to .old)
    assert not os.path.exists("/etc/yunohost/appslists.json")
    # Old cache should have been removed
    assert not os.path.exists(APPSLISTS_CACHE+"/yunohost_old.json")
    # Cron should have been changed
    assert "/bin/bash" in open(APPSLISTS_CRON_PATH, "r").read()
    assert cron_job_is_there()

