# encoding: utf-8

import pwd


# user list + root + admin
def ssh_user_list(auth):
    # couldn't resued user_list because it's not customisable enough :(
    user_attrs = {
        'uid': 'username',
        'cn': 'fullname',
        'mail': 'mail',
        'loginShell': 'shell',
        'homeDirectory': 'home_path',
    }

    root_unix = pwd.getpwnam("root")
    root = {
        'username': 'root',
        'fullname': '',
        'mail': '',
        # TODO ssh-allow using ssh_root_login_status
        'ssh_allowed': True,
        'shell': root_unix.pw_shell,
        'home_path': root_unix.pw_dir,
    }

    admin_unix = pwd.getpwnam("root")
    admin = {
        'username': 'admin',
        'fullname': '',
        'mail': '',
        'ssh_allowed': admin_unix.pw_shell.strip() != "/bin/false",
        'shell': admin_unix.pw_shell,
        'home_path': admin_unix.pw_dir,
    }

    query = '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))'
    users = {}

    ldap_result = auth.search('ou=users,dc=yunohost,dc=org', query, user_attrs.keys())

    for user in ldap_result:
        entry = {}

        for key, value in user.items():
            if key == "loginShell":
                if value[0].strip() == "/bin/false":
                    entry["ssh_allowed"] = False
                else:
                    entry["ssh_allowed"] = True

            entry[user_attrs[key]] = value[0]

        uid = entry[user_attrs['uid']]
        users[uid] = entry

    return {
        'root': root,
        'admin': admin,
        'users': users,
    }


def ssh_user_allow_ssh(auth, username):
    pass


def ssh_user_disallow_ssh(auth, username):
    pass


def ssh_root_login_status(auth):
    pass


def ssh_root_login_enable(auth):
    pass


def ssh_root_login_disable(auth):
    pass


def ssh_key_list(auth, username):
    pass


# dsa | ecdsa | ed25519 | rsa | rsa1
# this is the list of valid algo according to the man page
# according to internet ™ rsa seems the one to use for maximum compatibility
# and is still very strong
#
# QUESTION: should we forbid certains algos known to be BAD?
def ssh_key_add(auth, username, algo="default"):
    pass


def ssh_key_import(auth, username, public, private, name=None):
    pass


def ssh_key_remove(auth, username, key):
    pass


def ssh_authorized_keys_list(auth, username):
    pass


def ssh_authorized_keys_add(auth, username, key):
    pass


def ssh_authorized_keys_remove(auth, username, key):
    pass


# TODO
# arguments in actionmap
