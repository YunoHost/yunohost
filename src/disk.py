#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import enum

from sdbus import sd_bus_open_system
from yunohost.utils.system import binary_to_human
from yunohost.utils.udisks2_interfaces import Udisks2Manager


class DiskState(enum.StrEnum):
    """https://github.com/storaged-project/udisks/issues/1352#issuecomment-2678874537"""

    @staticmethod
    def _generate_next_value_(name, start, count, last_values):
        return name.upper()

    SANE = enum.auto()
    CRITICAL = enum.auto()
    UNKNOWN = enum.auto()

    @staticmethod
    def parse(drive: dict) -> "DiskState":
        match drive:
            case {"smart_failing": failing}:
                # ATA disk, see https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Drive.Ata.html#gdbus-property-org-freedesktop-UDisks2-Drive-Ata.SmartFailing
                return DiskState.SANE if not failing else DiskState.CRITICAL
            case {"smart_critical_warning": failing}:
                # NVME; see https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.NVMe.Controller.html#gdbus-property-org-freedesktop-UDisks2-NVMe-Controller.SmartCriticalWarning
                return DiskState.SANE if not failing else DiskState.CRITICAL
            case _:
                return DiskState.UNKNOWN


def _disk_infos(name: str, drive: dict, **kwargs):
    human_readable = kwargs.get("human_readable", False)
    human_readable_size = kwargs.get("human_readable_size", human_readable)
    result = {
        "name": name,
        "model": drive["model"],
        "serial": drive["serial"],
        "removable": bool(drive["media_removable"]),
        "size": (
            binary_to_human(drive["size"]) if human_readable_size else drive["size"]
        ),
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


def disk_list(**kwargs):
    bus = sd_bus_open_system()
    disks = Udisks2Manager(bus).get_disks()

    with_info = kwargs.get("with_info", False)

    if not with_info:
        return list(disks.keys())

    result = [_disk_infos(name, disk.props, **kwargs) for name, disk in disks.items()]

    return {"disks": result}


def disk_info(name, **kwargs):
    bus = sd_bus_open_system()
    disk = Udisks2Manager(bus).get_disks().get(name)

    human_readable = kwargs.get("human_readable", False)

    if not disk:
        return f"Unknown disk with name {name}" if human_readable else None

    return _disk_infos(name, disk.props, **kwargs)
