def storage_disk_list(with_info=False, human_readable=False):
    from yunohost.disk import disk_list

    return disk_list(with_info=with_info, human_readable=human_readable)


def storage_disk_info(name, human_readable=False):
    from yunohost.disk import disk_info

    return disk_info(name, human_readable=human_readable)
