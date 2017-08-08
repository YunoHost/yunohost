# (auth, username list) + root + admin
def ssh_user_list(auth):
    pass


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


def ssh_key_add(auth, username, algo="default"):
    pass


def ssh_key_import(auth, username, public, private):
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
