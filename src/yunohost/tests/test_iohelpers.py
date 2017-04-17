import os
import pytest
import requests
import requests_mock
import glob
import time
import pwd
from stat import *

from moulinette.core import MoulinetteError

from yunohost.io import download_text, download_json, set_permissions

# TODO:
#read_from_file
#read_from_json
#write_to_file
#append_to_file
#write_to_json
#remove_file
#run_shell_commands


# We define a dummy context with test folders and files

TEST_URL = "https://some.test.url/yolo.txt"
TMP_TEST_DIR = "/tmp/test_iohelpers"
TMP_TEST_FILE = "%s/foofile" % TMP_TEST_DIR
NON_ROOT_USER = "admin"
NON_ROOT_GROUP = "mail"

def setup_function(function):
    os.system("rm -rf %s" % TMP_TEST_DIR)
    os.system("mkdir %s" % TMP_TEST_DIR)
    os.system("touch %s" % TMP_TEST_FILE)


def teardown_function(function):
    os.seteuid(0)
    os.system("rm -rf /tmp/test_iohelpers/")


# Helper to try stuff as non-root
def switch_to_non_root_user():
    nonrootuser = pwd.getpwnam(NON_ROOT_USER).pw_uid
    os.seteuid(nonrootuser)


###############################################################################
#   Test permission change                                                    #
###############################################################################


def get_permissions(file_path):
    return (pwd.getpwuid(os.stat(file_path).st_uid).pw_name,
	    pwd.getpwuid(os.stat(file_path).st_gid).pw_name,
            oct(os.stat(file_path)[ST_MODE])[-3:])


def test_setpermissions_file():

    # Check we're at the default permissions
    assert get_permissions(TMP_TEST_FILE) == ("root", "root", "644")

    # Change the permissions
    set_permissions(TMP_TEST_FILE, NON_ROOT_USER, NON_ROOT_GROUP, 0111)

    # Check the permissions got changed
    assert get_permissions(TMP_TEST_FILE) == (NON_ROOT_USER, NON_ROOT_GROUP, "111")

    # Change the permissions again
    set_permissions(TMP_TEST_FILE, "root", "root", 0777)

    # Check the permissions got changed
    assert get_permissions(TMP_TEST_FILE) == ("root", "root", "777")


def test_setpermissions_directory():

    # Check we're at the default permissions
    assert get_permissions(TMP_TEST_DIR) == ("root", "root", "755")

    # Change the permissions
    set_permissions(TMP_TEST_DIR, NON_ROOT_USER, NON_ROOT_GROUP, 0111)

    # Check the permissions got changed
    assert get_permissions(TMP_TEST_DIR) == (NON_ROOT_USER, NON_ROOT_GROUP, "111")

    # Change the permissions again
    set_permissions(TMP_TEST_DIR, "root", "root", 0777)

    # Check the permissions got changed
    assert get_permissions(TMP_TEST_DIR) == ("root", "root", "777")


def test_setpermissions_permissiondenied():

    switch_to_non_root_user()

    with pytest.raises(MoulinetteError):
        set_permissions(TMP_TEST_FILE, NON_ROOT_USER, NON_ROOT_GROUP, 0111)


def test_setpermissions_badfile():

    with pytest.raises(MoulinetteError):
        set_permissions("/foo/bar/yolo", NON_ROOT_USER, NON_ROOT_GROUP, 0111)


def test_setpermissions_baduser():

    with pytest.raises(MoulinetteError):
        set_permissions(TMP_TEST_FILE, "foo", NON_ROOT_GROUP, 0111)


def test_setpermissions_badgroup():

    with pytest.raises(MoulinetteError):
        set_permissions(TMP_TEST_FILE, NON_ROOT_USER, "foo", 0111)


###############################################################################
#   Test download                                                             #
###############################################################################


def test_download():

    with requests_mock.Mocker() as m:
        m.register_uri("GET", TEST_URL, text='some text')

        fetched_text = download_text(TEST_URL)

    assert fetched_text == "some text"


def test_download_badurl():

    with pytest.raises(MoulinetteError):
        fetched_text = download_text(TEST_URL)


def test_download_404():

    with requests_mock.Mocker() as m:
        m.register_uri("GET", TEST_URL, status_code=404)

        with pytest.raises(MoulinetteError):
            fetched_text = download_text(TEST_URL)


def test_download_sslerror():

    with requests_mock.Mocker() as m:
        m.register_uri("GET", TEST_URL, exc=requests.exceptions.SSLError)

        with pytest.raises(MoulinetteError):
            fetched_text = download_text(TEST_URL)


def test_download_timeout():

    with requests_mock.Mocker() as m:
        m.register_uri("GET", TEST_URL, exc=requests.exceptions.ConnectTimeout)

        with pytest.raises(MoulinetteError):
            fetched_text = download_text(TEST_URL)


def test_download_json():

    with requests_mock.Mocker() as m:
        m.register_uri("GET", TEST_URL, text='{ "foo":"bar" }')

        fetched_json = download_json(TEST_URL)

    assert "foo" in fetched_json.keys()
    assert fetched_json["foo"] == "bar"


def test_download_json_badjson():

    with requests_mock.Mocker() as m:
        m.register_uri("GET", TEST_URL, text='{ not json lol }')

        with pytest.raises(MoulinetteError):
            download_json(TEST_URL)

