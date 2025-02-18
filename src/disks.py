from logging import getLogger

import dbus
from _dbus_bindings import PROPERTIES_IFACE

logger = getLogger("yunohost.storage")


__all__ = ["info", "list"]


UDISK_DRIVE_PATH = "/org/freedesktop/UDisks2/drives/"
UDISK_DRIVE_IFC = "org.freedesktop.UDisks2.Drive"


def _humaize(byte_size):
    suffixes = "kMGTPEZYRQ"

    byte_size = float(byte_size)

    if byte_size < 1024:
        return f"{byte_size}B"

    for i, s in enumerate(suffixes, start=2):
        unit = 1024**i
        if byte_size <= unit:
            return f"{(1024 * (byte_size / unit)):.1f} {s}B"


def _query_udisks():
    bus = dbus.SystemBus()
    manager = dbus.Interface(
        bus.get_object("org.freedesktop.UDisks2", "/org/freedesktop/UDisks2"),
        "org.freedesktop.DBus.ObjectManager",
    )

    for name, dev in manager.GetManagedObjects().items():
        if name.startswith(UDISK_DRIVE_PATH):
            yield name.removeprefix(UDISK_DRIVE_PATH), dev[UDISK_DRIVE_IFC]


def _disk_infos(name: str, drive: dict, human_readable=False):
    result = {
        "name": name,
        "model": drive["Model"],
        "serial": drive["Serial"],
        "removable": bool(drive["MediaRemovable"]),
        "size": _humaize(drive["Size"]) if human_readable else drive["Size"],
    }

    if connection_bus := drive["ConnectionBus"]:
        result["connection_bus"] = connection_bus

    if (rotation_rate := drive["RotationRate"]) == -1:
        result.update(
            {
                "type": "HDD",
                "rpm": "Unknown",
            }
        )
    elif rotation_rate == 0:
        result["type"] = "SSD"
    else:
        result.update(
            {
                "type": "HDD",
                "rpm": rotation_rate,
            }
        )

    return result


def list(with_info=False, human_readable=False):
    if not with_info:
        return [name for name, _ in _query_udisks()]

    result = {}

    for name, drive in _query_udisks():
        result[name] = _disk_infos(name, drive, human_readable)

    if human_readable and not result:
        return "No external media found"

    return result


def info(name, human_readable=False):
    bus = dbus.SystemBus()
    drive = dbus.Interface(
        bus.get_object(
            "org.freedesktop.UDisks2", f"/org/freedesktop/UDisks2/drives/{name}"
        ),
        PROPERTIES_IFACE,
    ).GetAll("org.freedesktop.UDisks2.Drive")

    return _disk_infos(name, drive, human_readable)
