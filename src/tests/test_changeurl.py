import pytest
import time
import requests
import os

from .conftest import get_test_apps_dir

from yunohost.app import app_install, app_change_url, app_remove, app_map
from yunohost.domain import _get_maindomain

from yunohost.utils.error import YunohostError

# Get main domain
maindomain = ""


def setup_function(function):
    global maindomain
    maindomain = _get_maindomain()


def teardown_function(function):
    app_remove("change_url_app")


def install_changeurl_app(path):
    app_install(
        os.path.join(get_test_apps_dir(), "change_url_app_ynh"),
        args="domain={}&path={}".format(maindomain, path),
        force=True,
    )


def check_changeurl_app(path):
    appmap = app_map(raw=True)

    assert path in appmap[maindomain].keys()

    assert appmap[maindomain][path]["id"] == "change_url_app"

    r = requests.get(
        "https://127.0.0.1%s/" % path, headers={"domain": maindomain}, verify=False
    )
    assert r.status_code == 200


def test_appchangeurl():
    install_changeurl_app("/changeurl")
    check_changeurl_app("/changeurl")

    app_change_url("change_url_app", maindomain, "/newchangeurl")

    # For some reason the nginx reload can take some time to propagate ...?
    time.sleep(2)

    check_changeurl_app("/newchangeurl")


def test_appchangeurl_sameurl():
    install_changeurl_app("/changeurl")
    check_changeurl_app("/changeurl")

    with pytest.raises(YunohostError):
        app_change_url("change_url_app", maindomain, "changeurl")
