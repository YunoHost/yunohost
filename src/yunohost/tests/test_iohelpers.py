import os
import pytest
import requests
import requests_mock
import glob
import time

from moulinette.core import MoulinetteError

from yunohost.io import download_text

#read_from_file
#read_from_json
#write_to_file
#append_to_file
#write_to_json
#remove_file
#set_permissions
#download_text
#download_json
#run_shell_commands


def setup_function(function):
    pass


def teardown_function(function):
    pass


###############################################################################
#   Test download                                                             #
###############################################################################

TEST_URL = "https://some.test.url/yolo.txt"

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

