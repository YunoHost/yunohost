def storage_disk_list(**kargs):
    from yunohost.disk import disk_list

    return disk_list(**kargs)


def storage_disk_info(name, **kargs):
    from yunohost.disk import disk_info

    return disk_info(name, **kargs)
