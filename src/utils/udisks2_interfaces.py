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
from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from typing import Any, Dict, List, Tuple, Optional

from sdbus import (
    DbusInterfaceCommon,
    DbusObjectManagerInterface,
    DbusPropertyEmitsChangeFlag,
    DbusUnprivilegedFlag,
    SdBus,
    dbus_method,
    dbus_property,
)
from sdbus.utils import (
    parse,
)
from sdbus.utils import parse_get_managed_objects as sdbus_parse_get_managed_objects
from sortedcollections import ValueSortedDict

UDISKS2_SERVICE_NAME = "org.freedesktop.UDisks2"
UDISKS2_BASE_PATH = "/org/freedesktop/UDisks2"
UDISKS2_DRIVE_PATH = f"{UDISKS2_BASE_PATH}/drives"

UDISKS2_DRIVE_IFC = "org.freedesktop.UDisks2.Drive"
UDISKS2_DRIVE_ATA_IFC = "org.freedesktop.UDisks2.Drive.Ata"
UDISKS2_DRIVE_NVME_IFC = "org.freedesktop.UDisks2.NVMe.Controller"


def _get_class_from_interfaces(_1, interface_names_iter, _2):
    if UDISKS2_DRIVE_ATA_IFC in interface_names_iter:
        return AtaDisk
    if UDISKS2_DRIVE_NVME_IFC in interface_names_iter:
        return NvmeDisk
    elif UDISKS2_DRIVE_IFC in interface_names_iter:
        return Disk
    return None


def parse_get_managed_objects(
    interfaces, managed_objects_data, on_unknown_interface, on_unknown_member
):
    with patch(f"{parse.__name__}._get_class_from_interfaces") as f:
        f.side_effect = _get_class_from_interfaces
        return sdbus_parse_get_managed_objects(
            interfaces, managed_objects_data, on_unknown_interface, on_unknown_member
        )


class GetDisksMixin(DbusInterfaceCommon):
    def __init__(
        self, service_name: str, object_path: str, bus: Optional[SdBus] = None
    ):
        super().__init__(service_name, object_path, bus)
        self._object_manager = DbusObjectManagerInterface(
            UDISKS2_SERVICE_NAME, UDISKS2_BASE_PATH, bus
        )

    def get_disks(self) -> dict[str, DiskResult]:
        result = ValueSortedDict(lambda it: it.props["sort_key"])

        for object_path, (iface, props) in parse_get_managed_objects(
            (Disk, AtaDisk, NvmeDisk),
            self._object_manager.get_managed_objects(),
            on_unknown_interface="none",
            on_unknown_member="ignore",
        ).items():
            if (
                object_path.startswith(UDISKS2_DRIVE_PATH)  # This is a drive
                and not props["optical"]  # This is not a CD player
            ):
                value = DiskResult(object_path, iface, props)
                result[value.name] = value

        return result


class DiskResult:
    def __init__(self, object_path: str, iface: type[Disk], props: dict[str, Any]):
        self._object_path = object_path
        self._iface = iface
        self.name = object_path.removeprefix(f"{UDISKS2_DRIVE_PATH}/")
        self.props = props


"""
The following interfaces were generated using the `python -m sdbus gen-from-file` command.
See: https://python-sdbus.readthedocs.io/en/latest/code_generator.html
Udisks2's dbus interface descriptors are available at:
https://github.com/storaged-project/udisks/blob/2.10.x-branch/data/org.freedesktop.UDisks2.xml
"""


class Udisks2Manager(
    GetDisksMixin,
    interface_name="org.freedesktop.UDisks2.Manager",
):
    def __init__(self, bus: SdBus):
        super().__init__(UDISKS2_SERVICE_NAME, f"{UDISKS2_BASE_PATH}/Manager", bus)

    @dbus_method(
        input_signature="s",
        result_signature="(bs)",
        flags=DbusUnprivilegedFlag,
    )
    def can_format(self, type: str) -> Tuple[bool, str]:
        raise NotImplementedError

    @dbus_method(
        input_signature="s",
        result_signature="(bts)",
        flags=DbusUnprivilegedFlag,
    )
    def can_resize(self, type: str) -> Tuple[bool, int, str]:
        raise NotImplementedError

    @dbus_method(
        input_signature="s",
        result_signature="(bs)",
        flags=DbusUnprivilegedFlag,
    )
    def can_check(self, type: str) -> Tuple[bool, str]:
        raise NotImplementedError

    @dbus_method(
        input_signature="s",
        result_signature="(bs)",
        flags=DbusUnprivilegedFlag,
    )
    def can_repair(self, type: str) -> Tuple[bool, str]:
        raise NotImplementedError

    @dbus_method(
        input_signature="ha{sv}",
        result_signature="o",
        flags=DbusUnprivilegedFlag,
    )
    def loop_setup(self, fd: int, options: Dict[str, Tuple[str, Any]]) -> str:
        raise NotImplementedError

    @dbus_method(
        input_signature="aossta{sv}",
        result_signature="o",
        flags=DbusUnprivilegedFlag,
    )
    def mdraid_create(
        self,
        blocks: List[str],
        level: str,
        name: str,
        chunk: int,
        options: Dict[str, Tuple[str, Any]],
    ) -> str:
        raise NotImplementedError

    @dbus_method(
        input_signature="sb",
        flags=DbusUnprivilegedFlag,
    )
    def enable_module(self, name: str, enable: bool) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        result_signature="ao",
        flags=DbusUnprivilegedFlag,
    )
    def get_block_devices(self, options: Dict[str, Tuple[str, Any]]) -> List[str]:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}a{sv}",
        result_signature="ao",
        flags=DbusUnprivilegedFlag,
    )
    def resolve_device(
        self, devspec: Dict[str, Tuple[str, Any]], options: Dict[str, Tuple[str, Any]]
    ) -> List[str]:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def version(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="as",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def supported_filesystems(self) -> List[str]:
        raise NotImplementedError

    @dbus_property(
        property_signature="as",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def supported_encryption_types(self) -> List[str]:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def default_encryption_type(self) -> str:
        raise NotImplementedError


class Disk(
    DbusInterfaceCommon,
    interface_name="org.freedesktop.UDisks2.Drive",
):
    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def eject(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def set_configuration(
        self, value: Dict[str, Tuple[str, Any]], options: Dict[str, Tuple[str, Any]]
    ) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def power_off(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def vendor(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def model(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def revision(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def serial(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def wwn(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def id(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="a{sv}",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def configuration(self) -> Dict[str, Tuple[str, Any]]:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def media(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="as",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def media_compatibility(self) -> List[str]:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def media_removable(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def media_available(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def media_change_detected(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def size(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def time_detected(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def time_media_detected(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def optical(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def optical_blank(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="u",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def optical_num_tracks(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="u",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def optical_num_audio_tracks(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="u",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def optical_num_data_tracks(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="u",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def optical_num_sessions(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def rotation_rate(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def connection_bus(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def seat(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def removable(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def ejectable(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def sort_key(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def can_power_off(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def sibling_id(self) -> str:
        raise NotImplementedError


class AtaController(
    DbusInterfaceCommon,
    interface_name="org.freedesktop.UDisks2.Drive.Ata",
):
    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_update(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        result_signature="a(ysqiiixia{sv})",
        flags=DbusUnprivilegedFlag,
    )
    def smart_get_attributes(
        self, options: Dict[str, Tuple[str, Any]]
    ) -> List[
        Tuple[int, str, int, int, int, int, int, int, Dict[str, Tuple[str, Any]]]
    ]:
        raise NotImplementedError

    @dbus_method(
        input_signature="sa{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_selftest_start(
        self, type: str, options: Dict[str, Tuple[str, Any]]
    ) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_selftest_abort(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="ba{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_set_enabled(
        self, value: bool, options: Dict[str, Tuple[str, Any]]
    ) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        result_signature="y",
        flags=DbusUnprivilegedFlag,
    )
    def pm_get_state(self, options: Dict[str, Tuple[str, Any]]) -> int:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def pm_standby(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def pm_wakeup(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def security_erase_unit(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_supported(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_enabled(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_updated(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_failing(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_power_on_seconds(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="d",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_temperature(self) -> float:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_num_attributes_failing(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_num_attributes_failed_in_the_past(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="x",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_num_bad_sectors(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_selftest_status(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_selftest_percent_remaining(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def pm_supported(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def pm_enabled(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def apm_supported(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def apm_enabled(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def aam_supported(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def aam_enabled(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def aam_vendor_recommended_value(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def write_cache_supported(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def write_cache_enabled(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def read_lookahead_supported(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def read_lookahead_enabled(self) -> bool:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def security_erase_unit_minutes(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def security_enhanced_erase_unit_minutes(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="b",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def security_frozen(self) -> bool:
        raise NotImplementedError


class NVMeController(
    DbusInterfaceCommon,
    interface_name="org.freedesktop.UDisks2.NVMe.Controller",
):
    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_update(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        result_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_get_attributes(
        self, options: Dict[str, Tuple[str, Any]]
    ) -> Dict[str, Tuple[str, Any]]:
        raise NotImplementedError

    @dbus_method(
        input_signature="sa{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_selftest_start(
        self, type: str, options: Dict[str, Tuple[str, Any]]
    ) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="a{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def smart_selftest_abort(self, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_method(
        input_signature="sa{sv}",
        flags=DbusUnprivilegedFlag,
    )
    def sanitize_start(self, action: str, options: Dict[str, Tuple[str, Any]]) -> None:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def state(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="q",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def controller_id(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="ay",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def subsystem_nqn(self) -> bytes:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def fguid(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def nvme_revision(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def unallocated_capacity(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_updated(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="as",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_critical_warning(self) -> List[str]:
        raise NotImplementedError

    @dbus_property(
        property_signature="t",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_power_on_hours(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="q",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_temperature(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_selftest_status(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def smart_selftest_percent_remaining(self) -> int:
        raise NotImplementedError

    @dbus_property(
        property_signature="s",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def sanitize_status(self) -> str:
        raise NotImplementedError

    @dbus_property(
        property_signature="i",
        flags=DbusPropertyEmitsChangeFlag,
    )
    def sanitize_percent_remaining(self) -> int:
        raise NotImplementedError


class AtaDisk(Disk, AtaController):
    pass


class NvmeDisk(Disk, NVMeController):
    pass
