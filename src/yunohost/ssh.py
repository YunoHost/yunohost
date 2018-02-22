# encoding: utf-8

import os

from moulinette.utils.filesystem import read_file, write_to_file, chown, chmod, mkdir

from yunohost.user import _get_user_for_ssh


def ssh_authorized_keys_list(auth, username):
    user = _get_user_for_ssh(auth, username, ["homeDirectory"])
    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    authorized_keys_file = os.path.join(user["homeDirectory"][0], ".ssh", "authorized_keys")

    if not os.path.exists(authorized_keys_file):
        return []

    keys = []
    last_comment = ""
    for line in read_file(authorized_keys_file).split("\n"):
        # empty line
        if not line.strip():
            continue

        if line.lstrip().startswith("#"):
            last_comment = line.lstrip().lstrip("#").strip()
            continue

        # assuming a key per non empty line
        key = line.strip()
        keys.append({
            "key": key,
            "name": last_comment,
        })

        last_comment = ""

    return {"keys": keys}


def ssh_authorized_keys_add(auth, username, key, comment):
    user = _get_user_for_ssh(auth, username, ["homeDirectory", "uid"])
    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    authorized_keys_file = os.path.join(user["homeDirectory"][0], ".ssh", "authorized_keys")

    if not os.path.exists(authorized_keys_file):
        # ensure ".ssh" exists
        mkdir(os.path.join(user["homeDirectory"][0], ".ssh"),
              force=True, parents=True, uid=user["uid"][0])

        # create empty file to set good permissions
        write_to_file(authorized_keys_file, "")
        chown(authorized_keys_file, uid=user["uid"][0])
        chmod(authorized_keys_file, 0600)

    authorized_keys_content = read_file(authorized_keys_file)

    authorized_keys_content += "\n"
    authorized_keys_content += "\n"

    if comment and comment.strip():
        if not comment.lstrip().startswith("#"):
            comment = "# " + comment
        authorized_keys_content += comment.replace("\n", " ").strip()
        authorized_keys_content += "\n"

    authorized_keys_content += key.strip()
    authorized_keys_content += "\n"

    write_to_file(authorized_keys_file, authorized_keys_content)


def ssh_authorized_keys_remove(auth, username, key):
    user = _get_user(auth, username, ["homeDirectory", "uid"])
    if not user:
        raise Exception("User with username '%s' doesn't exists" % username)

    authorized_keys_file = os.path.join(user["homeDirectory"][0], ".ssh", "authorized_keys")

    if not os.path.exists(authorized_keys_file):
        raise Exception("this key doesn't exists ({} dosesn't exists)".format(authorized_keys_file))

    authorized_keys_content = read_file(authorized_keys_file)

    if key not in authorized_keys_content:
        raise Exception("Key '{}' is not present in authorized_keys".format(key))

    # don't delete the previous comment because we can't verify if it's legit

    # this regex approach failed for some reasons and I don't know why :(
    # authorized_keys_content = re.sub("{} *\n?".format(key),
    #                                  "",
    #                                  authorized_keys_content,
    #                                  flags=re.MULTILINE)

    authorized_keys_content = authorized_keys_content.replace(key, "")

    write_to_file(authorized_keys_file, authorized_keys_content)
