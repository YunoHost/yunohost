# encoding: utf-8

import os
import re
import pwd
import subprocess

from moulinette.utils.filesystem import read_file, write_to_file, rm


SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

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
    # TODO escape input using https://www.python-ldap.org/doc/html/ldap-filter.html
    # TODO it would be good to support different kind of shells

    if not _get_user(auth, username):
        raise Exception("User with username '%s' doesn't exists" % username)

    auth.update('uid=%s,ou=users' % username, {'loginShell': '/bin/bash'})


def ssh_user_disallow_ssh(auth, username):
    # TODO escape input using https://www.python-ldap.org/doc/html/ldap-filter.html
    # TODO it would be good to support different kind of shells

    if not _get_user(auth, username) :
        raise Exception("User with username '%s' doesn't exists" % username)

    auth.update('uid=%s,ou=users' % username, {'loginShell': '/bin/false'})


# XXX should we support all the options?
def ssh_root_login_status(auth):
    # this is the content of "man sshd_config"
    # PermitRootLogin
    #     Specifies whether root can log in using ssh(1).  The argument must be
    #     “yes”, “without-password”, “forced-commands-only”, or “no”.  The
    #     default is “yes”.
    sshd_config_content = read_file(SSHD_CONFIG_PATH)

    if re.search("^ *PermitRootLogin +(no|forced-commands-only) *$",
                 sshd_config_content, re.MULTILINE):
        return {"PermitRootLogin": False}

    return {"PermitRootLogin": True}


def ssh_root_login_enable(auth):
    sshd_config_content = read_file(SSHD_CONFIG_PATH)
    # TODO rollback to old config if service reload failed
    # sshd_config_content_backup = sshd_config_content

    if re.search("^ *PermitRootLogin +(no|forced-commands-only|yes|without-password) *$",
                 sshd_config_content, re.MULTILINE):

        sshd_config_content = re.sub("^ *PermitRootLogin +(yes|without-password) *$",
                                     "PermitRootLogin yes",
                                     sshd_config_content,
                                     flags=re.MULTILINE)

    else:
        sshd_config_content += "\nPermitRootLogin yes\n"

    write_to_file(SSHD_CONFIG_PATH, sshd_config_content)

    subprocess.check_call("service sshd reload", shell=True)


def ssh_root_login_disable(auth):
    sshd_config_content = read_file(SSHD_CONFIG_PATH)
    # TODO rollback to old config if service reload failed
    # sshd_config_content_backup = sshd_config_content

    if re.search("^ *PermitRootLogin +(no|forced-commands-only|yes|without-password) *$",
                 sshd_config_content, re.MULTILINE):

        sshd_config_content = re.sub("^ *PermitRootLogin +(yes|without-password) *$",
                                     "PermitRootLogin no",
                                     sshd_config_content,
                                     flags=re.MULTILINE)

    else:
        sshd_config_content += "\nPermitRootLogin no\n"

    write_to_file(SSHD_CONFIG_PATH, sshd_config_content)

    subprocess.check_call("service sshd reload", shell=True)


# XXX should we display private key too?
def ssh_key_list(auth, username):
    # TODO escape input using https://www.python-ldap.org/doc/html/ldap-filter.html
    user = _get_user(auth, username, attrs=["homeDirectory"])

    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    user_home_directory = user["homeDirectory"][0]
    ssh_dir = os.path.join(user_home_directory, ".ssh")

    if not os.path.exists(ssh_dir):
        return {"keys": {}}

    keys = {}

    for i in os.listdir(ssh_dir):
        if i.endswith(".pub"):
            # remove ".pub" from name
            keys[".".join(i.split(".")[:-1])] = {
                "pub": read_file(os.path.join(ssh_dir, i))
            }

    return {
        "keys": keys,
    }


# dsa | ecdsa | ed25519 | rsa | rsa1
# this is the list of valid algo according to the man page
# according to internet ™ rsa seems the one to use for maximum compatibility
# and is still very strong
#
# QUESTION: should we forbid certains algos known to be BAD?
def ssh_key_add(auth, username, algo, name=None):
    all_keys_name = ssh_key_list(auth, username)["keys"].keys()

    user = _get_user(auth, username, ["homeDirectory"])
    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    if name is None:
        name = "id_{}".format(algo)

        if name in all_keys_name:
            # caping to 100 to void infinite loop and because people that won't
            # be satisfied by this solution will be the super absolute edge
            # case and will probably never happen
            for i in range(1, 100):
                if name + str(i) not in all_keys_name:
                    name += str(i)
                    break
            # this else will be executed if the for loop is never "break"
            else:
                raise Exception("No available name for you new ssh key, please provide one using the -n command line option")


    if not name.startswith("id_"):
        name = "id_" + name

    if name.endswith(".pub"):
        name = name[:-len(".pub")]

    if name in all_keys_name:
        raise Exception("a key with this name already exists")

    if not os.path.exists(os.path.join(user["homeDirectory"][0], ".ssh")):
        os.makedirs(os.path.exists(os.path.join(user["homeDirectory"][0], ".ssh")))

    key_path = os.path.join(user["homeDirectory"][0], ".ssh", name)

    # -t --> algo
    # -f --> output file
    # -N --> passphrase, here make it empty
    subprocess.check_call("ssh-keygen -t {} -f {} -N ''".format(algo, key_path), shell=True)


def ssh_key_import(auth, username, public, private, name):
    all_keys_name = ssh_key_list(auth, username)["keys"].keys()

    user = _get_user(auth, username, ["homeDirectory"])
    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    if not name.startswith("id_"):
        name = "id_" + name

    if name.endswith(".pub"):
        # remove ".pub"
        name = ".".join(name.split(".")[:-1])

    if name in all_keys_name:
        raise Exception("a key with this name already exists")

    if not os.path.exists(os.path.join(user["homeDirectory"][0], ".ssh")):
        os.makedirs(os.path.exists(os.path.join(user["homeDirectory"][0], ".ssh")))

    key_path = os.path.join(user["homeDirectory"][0], ".ssh", name)

    write_to_file(key_path, private)
    write_to_file(key_path + ".pub", public)


def ssh_key_remove(auth, username, name):
    all_keys_name = ssh_key_list(auth, username)["keys"].keys()

    user = _get_user(auth, username, ["homeDirectory"])
    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    if name.endswith(".pub"):
        # remove ".pub"
        name = ".".join(name.split(".")[:-1])

    if name not in all_keys_name and "id_" + name in all_keys_name:
        name = "id_" + name

    if name not in all_keys_name:
        raise Exception("This key doesn't exists")

    key_path = os.path.join(user["homeDirectory"][0], ".ssh", name)

    rm(key_path)
    rm(key_path + ".pub")


def ssh_authorized_keys_list(auth, username):
    pass


def ssh_authorized_keys_add(auth, username, key):
    pass


def ssh_authorized_keys_remove(auth, username, key):
    pass


def _get_user(auth, username, attrs=None):
    # FIXME handle root and admin
    user = auth.search('ou=users,dc=yunohost,dc=org',
                       '(&(objectclass=person)(uid=%s))' % username,
                       attrs)

    assert len(user) in (0, 1)

    if not user:
        return None

    return user[0]
