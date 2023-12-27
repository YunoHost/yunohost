import time
import requests
from pathlib import Path
import os

from .conftest import message, raiseYunohostError, get_test_apps_dir

from yunohost.domain import _get_maindomain, domain_add, domain_remove, domain_list
from yunohost.user import user_create, user_list, user_delete
from yunohost.authenticators.ldap_ynhuser import Authenticator, SESSION_FOLDER, short_hash

# Get main domain
maindomain = open("/etc/yunohost/current_host").read().strip()
dummy_password = "test123Ynh"


def setup_function(function):
    Authenticator.invalidate_all_sessions_for_user("alice")
    assert number_of_active_session_for_user("alice") == 0


def teardown_function(function):
    pass


def setup_module(module):

    assert os.system("systemctl is-active yunohost-portal-api >/dev/null") == 0

    user_create("alice", maindomain, dummy_password, fullname="Alice White", admin=True)


def teardown_module(module):
    if "alice" in user_list()["users"]:
        user_delete("alice")


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

    return len(list(Path(SESSION_FOLDER).glob(f"{short_hash('alice')}*")))


def request(webpath, logged_as=None, session=None):
    webpath = webpath.rstrip("/")

    # Anonymous access
    if session:
        r = session.get(webpath, verify=False)
    elif not logged_as:
        r = requests.get(webpath, verify=False)
    # Login as a user using dummy password
    else:
        with requests.Session() as session:
            r = login(session, logged_as)
            # We should have some cookies related to authentication now
            assert session.cookies
            r = session.get(webpath, verify=False)

    # If we can't access it, we got redirected to the SSO
    # with `r=<base64_callback_url>` for anonymous access because they're encouraged to log-in,
    # and `msg=access_denied` if we are logged but not allowed for this url
    # with `r=
    #sso_url = f"https://{maindomain}/yunohost/sso/"
    #if not logged_as:
    #    sso_url += "?r="
    #else:
    #    sso_url += "?msg=access_denied"

    return r


def test_api_public_as_anonymous():

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

    Path("/var/www/.well-known/acme-challenge-public/toto").touch()
    r = request(f"http://{maindomain}/.well-known/acme-challenge/toto")
    assert r.status_code == 200

    r = request(f"http://{maindomain}/.well-known/acme-challenge/nonexistent")
    assert r.status_code == 404


# app privée pour alice
# - pas d'accès si pas loggué
#     -> redirection ?
# - accès si loggué si alice
# - pas d'accès même si loggué en tant que bob

# accès à l'api portal
    # -> test des routes
    #    apps publique (seulement si activé ?)
    #    /me
    #    /update


# accès à une url autorisée mais qui 502 ?

# dummy app qui montre le header remote_user / authentication ?

# accès aux trucs précédent meme avec une app installée sur la racine ?
# ou une app par défaut ?

# accès à un deuxième "domain principal"

# accès à un app sur un sous-domaine
# pas loggué -> redirect vers sso sur domaine principal
# se logger sur API sur domain principal, puis utilisation du cookie sur le sous-domaine

