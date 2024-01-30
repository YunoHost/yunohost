import base64
import time
import requests
from pathlib import Path
import os

from .conftest import message, raiseYunohostError, get_test_apps_dir

from yunohost.domain import _get_maindomain, domain_add, domain_remove, domain_list
from yunohost.user import user_create, user_list, user_delete
from yunohost.authenticators.ldap_ynhuser import Authenticator, SESSION_FOLDER, short_hash
from yunohost.app import app_install, app_remove, app_setting, app_ssowatconf
from yunohost.permission import user_permission_list, user_permission_update


# Get main domain
maindomain = open("/etc/yunohost/current_host").read().strip()
dummy_password = "test123Ynh"


def setup_function(function):
    Authenticator.invalidate_all_sessions_for_user("alice")
    assert number_of_active_session_for_user("alice") == 0
    Authenticator.invalidate_all_sessions_for_user("bob")
    assert number_of_active_session_for_user("bob") == 0


def teardown_function(function):
    pass


def setup_module(module):

    assert os.system("systemctl is-active yunohost-portal-api >/dev/null") == 0

    if "alice" not in user_list()["users"]:
        user_create("alice", maindomain, dummy_password, fullname="Alice White", admin=True)
    if "bob" not in user_list()["users"]:
        user_create("bob", maindomain, dummy_password, fullname="Bob Marley")

    app_install(
        os.path.join(get_test_apps_dir(), "hellopy_ynh"),
        args=f"domain={maindomain}&init_main_permission=visitors",
        force=True,
    )



def teardown_module(module):
    if "alice" in user_list()["users"]:
        user_delete("alice")
    if "bob" in user_list()["users"]:
        user_delete("bob")

    app_remove("hellopy")


def login(session, logged_as):
    login_endpoint = f"https://{maindomain}/yunohost/portalapi/login"
    r = session.post(
        login_endpoint,
        data={"credentials": f"{logged_as}:{dummy_password}"},
        headers={
            "X-Requested-With": "",
        },
        verify=False,
    )

    return r


def logout(session):
    logout_endpoint = f"https://{maindomain}/yunohost/portalapi/logout"
    r = session.get(
        logout_endpoint,
        headers={
            "X-Requested-With": "",
        },
        verify=False,
    )
    return r


def number_of_active_session_for_user(user):
    return len(list(Path(SESSION_FOLDER).glob(f"{short_hash(user)}*")))


def request(webpath, logged_as=None, session=None, inject_auth=None):
    webpath = webpath.rstrip("/")

    headers = {}
    if inject_auth:
        b64loginpassword = base64.b64encode((inject_auth[0] + ":" + inject_auth[1]).encode()).decode()
        headers["Authorization"] = f"Basic {b64loginpassword}"

    # Anonymous access
    if session:
        r = session.get(webpath, verify=False, allow_redirects=False, headers=headers)
    elif not logged_as:
        r = requests.get(webpath, verify=False, allow_redirects=False, headers=headers)
    # Login as a user using dummy password
    else:
        with requests.Session() as session:
            r = login(session, logged_as)
            # We should have some cookies related to authentication now
            assert session.cookies
            r = session.get(webpath, verify=False, allow_redirects=False, headers=headers)

    return r


def test_api_public_as_anonymous():

    # FIXME : should list apps only if the domain option is enabled

    r = request(f"https://{maindomain}/yunohost/portalapi/public")
    assert r.status_code == 200 and "apps" in r.json()


def test_api_me_as_anonymous():

    r = request(f"https://{maindomain}/yunohost/portalapi/me")
    assert r.status_code == 401


def test_api_login_and_logout():

    with requests.Session() as session:
        r = login(session, "alice")

        assert "yunohost.portal" in session.cookies
        assert r.status_code == 200

        assert number_of_active_session_for_user("alice") == 1

        r = logout(session)

        assert number_of_active_session_for_user("alice") == 0

def test_api_login_nonexistinguser():

    with requests.Session() as session:
        r = login(session, "nonexistent")

        assert r.status_code == 401


def test_api_public_and_me_logged_in():

    r = request(f"https://{maindomain}/yunohost/portalapi/public", logged_as="alice")
    assert r.status_code == 200 and "apps" in r.json()
    r = request(f"https://{maindomain}/yunohost/portalapi/me", logged_as="alice")
    assert r.status_code == 200 and r.json()["username"] == "alice"

    assert number_of_active_session_for_user("alice") == 2


def test_api_session_expired():

    with requests.Session() as session:
        r = login(session, "alice")

        assert "yunohost.portal" in session.cookies
        assert r.status_code == 200

        r = request(f"https://{maindomain}/yunohost/portalapi/me", session=session)
        assert r.status_code == 200 and r.json()["username"] == "alice"

        for file in Path(SESSION_FOLDER).glob(f"{short_hash('alice')}*"):
            os.utime(str(file), (0, 0))

        r = request(f"https://{maindomain}/yunohost/portalapi/me", session=session)
        assert number_of_active_session_for_user("alice") == 0
        assert r.status_code == 401


def test_public_routes_not_blocked_by_ssowat():

    r = request(f"https://{maindomain}/yunohost/api/whatever")
    # Getting code 405, Method not allowed, which means the API does answer,
    # meaning it's not blocked by ssowat
    # Or : on the CI, the yunohost-api is likely to be down (to save resources)
    assert r.status_code in [405, 502]

    os.system("mkdir -p /var/www/.well-known/acme-challenge-public")
    Path("/var/www/.well-known/acme-challenge-public/toto").touch()
    r = request(f"http://{maindomain}/.well-known/acme-challenge/toto")
    assert r.status_code == 200

    r = request(f"http://{maindomain}/.well-known/acme-challenge/nonexistent")
    assert r.status_code == 404


def test_permission_propagation_on_ssowat():

    res = user_permission_list(full=True)["permissions"]
    assert "visitors" in res["hellopy.main"]["allowed"]
    assert "all_users" in res["hellopy.main"]["allowed"]

    r = request(f"https://{maindomain}/")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{maindomain}/", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    r = request(f"https://{maindomain}/", logged_as="bob")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    user_permission_update(
        "hellopy.main", remove=["visitors", "all_users"], add="alice"
    )

    r = request(f"https://{maindomain}/")
    assert r.status_code == 302
    assert r.headers['Location'].startswith(f"https://{maindomain}/yunohost/sso?r=")

    r = request(f"https://{maindomain}/", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "Hello world!"

    # Bob can't even login because doesnt has access to any app on the domain
    # (that's debattable tho)
    with requests.Session() as session:
        r = login(session, "bob")
        assert not session.cookies


def test_sso_basic_auth_header():

    r = request(f"https://{maindomain}/show-auth")
    assert r.status_code == 200 and r.content.decode().strip() == "User: None\nPwd: None"

    r = request(f"https://{maindomain}/show-auth", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == "User: alice\nPwd: -"

    app_setting("hellopy", "auth_header", value="basic-with-password")
    app_ssowatconf()

    r = request(f"https://{maindomain}/show-auth", logged_as="alice")
    assert r.status_code == 200 and r.content.decode().strip() == f"User: alice\nPwd: {dummy_password}"


def test_sso_basic_auth_header_spoofing():

    r = request(f"https://{maindomain}/show-auth")
    assert r.status_code == 200 and r.content.decode().strip() == "User: None\nPwd: None"

    r = request(f"https://{maindomain}/show-auth", inject_auth=("foo", "bar"))
    assert r.status_code == 200 and r.content.decode().strip() == "User: None\nPwd: None"

    app_setting("hellopy", "protect_against_basic_auth_spoofing", value="false")
    app_ssowatconf()

    r = request(f"https://{maindomain}/show-auth", inject_auth=("foo", "bar"))
    assert r.status_code == 200 and r.content.decode().strip() == "User: foo\nPwd: bar"





# accès à l'api portal
    # -> test des routes
    #    apps publique (seulement si activé ?)
    #    /me
    #    /update


# accès aux trucs précédent meme avec une app installée sur la racine ?
# ou une app par défaut ?

# accès à un deuxième "domain principal"

# accès à un app sur un sous-domaine
# pas loggué -> redirect vers sso sur domaine principal
# se logger sur API sur domain principal, puis utilisation du cookie sur le sous-domaine

