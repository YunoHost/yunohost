import re

IGNORE_DISKS = "sr", "md", "dm-", "loop", "zd", "pmem"
# regex: ^((sr)|(md)|...)
IGNORE_DISK_RE = re.compile(rf"""^({"|".join([f'({it})' for it in IGNORE_DISKS])})""")


def filter_device(device):
    """
    Returns True if device has parents (e.g. USB device) and its name is not amongst
    """
    return device.parent is not None and not IGNORE_DISK_RE.match(device.sys_name)
