# (username list) + root + admin
def ssh_user_list():
    pass


def ssh_user_enable_ssh(username):
    pass


def ssh_user_disable_ssh(username):
    pass


def ssh_root_login_status():
    pass


def ssh_root_login_enable():
    pass


def ssh_root_login_disable():
    pass


def ssh_key_list(username):
    pass


def ssh_key_add(username, algo="default"):
    pass


def ssh_key_import(username, public, private):
    pass


def ssh_key_remove(username, key):
    pass


def ssh_authorized_keys_list(username):
    pass


def ssh_authorized_keys_add(username, key):
    pass


def ssh_authorized_keys_remove(username, key):
    pass


# TODO
# auth on critical commands
# arguments in actionmap
