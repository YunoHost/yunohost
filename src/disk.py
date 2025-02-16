import enum

from sdbus import sd_bus_open_system
from yunohost.utils.system import binary_to_human
from yunohost.utils.udisks2_interfaces import Udisks2Manager

UDISK_DRIVE_PATH = "/org/freedesktop/UDisks2/drives/"
UDISK_DRIVE_IFC = "org.freedesktop.UDisks2.Drive"
UDISK_DRIVE_ATA_IFC = "org.freedesktop.UDisks2.Drive.Ata"
UDISK_DRIVE_NVME_IFC = "org.freedesktop.UDisks2.Manager.NVMe"


class DiskState(enum.StrEnum):
    """https://github.com/storaged-project/udisks/issues/1352#issuecomment-2678874537"""
    @staticmethod
    def _generate_next_value_(name, start, count, last_values):
        return name.upper()

    SANE = enum.auto()
    CRITICAL = enum.auto()
    UNKNOWN = enum.auto()

    @staticmethod
    def parse(drive: dict):
        if (failing := drive.get("smart_failing")) is not None:
            # ATA disk, see https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Drive.Ata.html#gdbus-property-org-freedesktop-UDisks2-Drive-Ata.SmartFailing
            return DiskState.SANE if not failing else DiskState.CRITICAL
        elif (failing := drive.get("Ssmart_critical_warning")) is not None:
            # NVME; see https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.NVMe.Controller.html#gdbus-property-org-freedesktop-UDisks2-NVMe-Controller.SmartCriticalWarning
            return DiskState.SANE if not failing else DiskState.CRITICAL
        return DiskState.UNKNOWN



def _disk_infos(name: str, drive: dict, human_readable=False):
    result = {
        "name": name,
        "model": drive["model"],
        "serial": drive["serial"],
        "removable": bool(drive["media_removable"]),
        "size": binary_to_human(drive["size"]) if human_readable else drive["size"],
        "smartStatus": DiskState.parse(drive),
    }

    if "connection_bus" in drive:
        result["connectionBus"] = drive["connection_bus"]

    if (rotation_rate := drive["rotation_rate"]) == -1:
        result.update(
            {
                "type": "HDD",
                "rpm": "Unknown" if human_readable else None,
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


def disk_list(with_info=False, human_readable=False):
    bus = sd_bus_open_system()
    disks = Udisks2Manager(bus).get_disks()
    if not with_info:
        return list(disks.keys())

    result = [
        _disk_infos(name, disk.props, human_readable) for name, disk in disks.items()
    ]

    return {"disks": result}


def disk_info(name, human_readable=False):
    bus = sd_bus_open_system()
    disk = Udisks2Manager(bus).get_disks().get(name)

    if not disk:
        return f"Unknown disk with name {name}" if human_readable else None

    return _disk_infos(name, disk.props, human_readable)
