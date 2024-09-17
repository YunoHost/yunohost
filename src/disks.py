from collections import OrderedDict
import dataclasses
from glob import glob
from typing import Optional

import pyudev
import psutil

from moulinette.utils.log import getActionLogger


from yunohost.utils.disks import filter_device


logger = getActionLogger("yunohost.storage")


@dataclasses.dataclass
class DiskParts:
    devname: str
    filesystem: str
    encrypted: bool
    mountpoint: str

    @staticmethod
    def from_parent_device(device: pyudev.Device, partitions):
        result = OrderedDict()
        for child_dev in sorted(
            filter(filter_device, device.children), key=lambda it: it.device_node
        ):
            encrypted_provider = glob(f"/sys/block/dm-*/slaves/{child_dev.sys_name}")
            if encrypted_provider:
                # retrive the dm-x part
                dm = encrypted_provider[0].split("/")[3]
                enc_dev = pyudev.Devices.from_name(device.context, "block", dm)
                # This work for LUKS, what about other partition mecanisms?
                partname = f"/dev/mapper/{enc_dev.properties['DM_NAME']}"
                encrypted = True
            else:
                partname = child_dev.device_node
                encrypted = False

            if partname not in partitions:
                logger.warning(
                    f"{child_dev.device_node} not found by 'psutil.disk_partitions'"
                )
                continue

            result[child_dev.sys_name] = DiskParts(
                devname=device.device_node,
                filesystem=partitions[partname].fstype,
                encrypted=encrypted,
                mountpoint=partitions[partname].mountpoint,
            )

        return result


@dataclasses.dataclass
class DiskInfos:
    devname: str
    model: str
    serial: str
    size: int
    links: list[str]
    partitions: Optional[list[DiskParts]]

    @staticmethod
    def from_device(device, partitions):
        try:
            dev_size = device.attributes.asint("size")
        except (AttributeError, UnicodeError, ValueError):
            dev_size = None

        dev_links = list(sorted(it for it in device.device_links))
        child_parts = DiskParts.from_parent_device(device, partitions)

        return DiskInfos(
            devname=device.device_node,
            model=device.get("ID_MODEL", None),
            serial=device.get("ID_SERIAL_SHORT", None),
            size=dev_size,
            links=dev_links,
            partitions=child_parts or None,
        )


def infos():
    context = pyudev.Context()
    partitions = {it.device: it for it in psutil.disk_partitions()}
    result = OrderedDict()

    for it in sorted(
        filter(filter_device, context.list_devices(subsystem="block", DEVTYPE="disk")),
        key=lambda it: it.device_node,
    ):
        result[it.sys_name] = dataclasses.asdict(
            DiskInfos.from_device(it, partitions), dict_factory=OrderedDict
        )

    return result
