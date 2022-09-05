import pytest
import os

from yunohost.authenticators.ldap_admin import Authenticator as LDAPAuth
from yunohost.tools import tools_rootpw

from moulinette import m18n
from moulinette.core import MoulinetteError


def setup_function(function):

    if os.system("systemctl is-active slapd") != 0:
        os.system("systemctl start slapd && sleep 3")

    tools_rootpw("yunohost", check_strength=False)


def test_authenticate():
    LDAPAuth().authenticate_credentials(credentials="yunohost")


def test_authenticate_with_wrong_password():
    with pytest.raises(MoulinetteError) as exception:
        LDAPAuth().authenticate_credentials(credentials="bad_password_lul")

    translation = m18n.n("invalid_password")
    expected_msg = translation.format()
    assert expected_msg in str(exception)


def test_authenticate_server_down(mocker):
    os.system("systemctl stop slapd && sleep 3")

    # Now if slapd is down, moulinette tries to restart it
    mocker.patch("os.system")
    mocker.patch("time.sleep")
    with pytest.raises(MoulinetteError) as exception:
        LDAPAuth().authenticate_credentials(credentials="yunohost")

    translation = m18n.n("ldap_server_down")
    expected_msg = translation.format()
    assert expected_msg in str(exception)


def test_authenticate_change_password():

    LDAPAuth().authenticate_credentials(credentials="yunohost")

    tools_rootpw("plopette", check_strength=False)

    with pytest.raises(MoulinetteError) as exception:
        LDAPAuth().authenticate_credentials(credentials="yunohost")

    translation = m18n.n("invalid_password")
    expected_msg = translation.format()
    assert expected_msg in str(exception)

    LDAPAuth().authenticate_credentials(credentials="plopette")
