import operator
from collections import OrderedDict
import dataclasses
from glob import glob
from typing import Optional, Any

import dbus

from moulinette.utils.log import getActionLogger

from yunohost.utils import bytearray_to_string

logger = getActionLogger("yunohost.storage")


UDISK_DRIVE_PATH = "/org/freedesktop/UDisks2/drives/"
UDISK_BLOCK_PATH = "/org/freedesktop/UDisks2/block_devices/"
UDISK_PART_TABLE_IFC = "org.freedesktop.UDisks2.PartitionTable"
UDISK_BLOCK_IFC = "org.freedesktop.UDisks2.Block"
UDISK_DRIVE_IFC = "org.freedesktop.UDisks2.Drive"
UDISK_ENCRYPTED_IFC = "org.freedesktop.UDisks2.Encrypted"
UDISK_FILESYSTEM_IFC = "org.freedesktop.UDisks2.Filesystem"


@dataclasses.dataclass
class DiskParts:
    devname: str
    filesystem: str
    encrypted: bool
    mountpoint: str


@dataclasses.dataclass
class DiskInfos:
    devname: str
    model: str
    serial: str
    size: int
    links: list[str]
    partitions: Optional[dict[str, DiskParts]]


def infos():
    result = OrderedDict()

    bus = dbus.SystemBus()
    manager = bus.get_object("org.freedesktop.UDisks2", "/org/freedesktop/UDisks2")

    drives = {}
    devices = {}
    partitions = {}

    for k, v in manager.get_dbus_method(
        "GetManagedObjects", "org.freedesktop.DBus.ObjectManager"
    )().items():
        if k.startswith(UDISK_DRIVE_PATH):
            # These are hard drives
            drives[k.removeprefix(UDISK_DRIVE_PATH)] = v
        elif UDISK_PART_TABLE_IFC in v:
            # These are block container partition tables (/dev/sda, /dev/sdb, etc.)
            devices[k.removeprefix(UDISK_BLOCK_PATH)] = v
        elif UDISK_BLOCK_IFC in v:
            # These are partitions (/dev/sda1, /dev/dm-1, etc.). Here, we try to
            # associate partitions with as much keys as possible to easier search
            # These will be, for instance sdb1 and /dev/sdb1, dm-1 and /dev/dm-1, etc.
            _dev = bytearray_to_string(v[UDISK_BLOCK_IFC]["Device"])
            _pref_dev = bytearray_to_string(v[UDISK_BLOCK_IFC]["PreferredDevice"])
            partitions[_dev] = partitions[_dev.split("/")[-1]] = v
            partitions[_pref_dev] = partitions[_pref_dev.split("/")[-1]] = v
            partitions[k.removeprefix(UDISK_BLOCK_PATH)] = v

    for key, device in sorted(devices.items(), key=operator.itemgetter(0)):
        drive = drives[device[UDISK_BLOCK_IFC]["Drive"].removeprefix(UDISK_DRIVE_PATH)][
            UDISK_DRIVE_IFC
        ]
        devname = bytearray_to_string(device[UDISK_BLOCK_IFC]["Device"])

        device_partitions = OrderedDict()

        for partition_key in map(
            lambda p: p.removeprefix(UDISK_BLOCK_PATH),
            sorted(device[UDISK_PART_TABLE_IFC]["Partitions"]),
        ):
            partition_obj = partitions[partition_key]
            partition_devname = bytearray_to_string(
                partition_obj[UDISK_BLOCK_IFC]["Device"]
            )
            encrypted = False

            if UDISK_ENCRYPTED_IFC in partition_obj:
                encrypted = True
                partition_obj = partitions[
                    partition_obj[UDISK_ENCRYPTED_IFC]["CleartextDevice"].removeprefix(
                        UDISK_BLOCK_PATH
                    )
                ]
            else:
                # If partition is a device mapper, it's not easy to associate the
                # virtual device with its underlying FS. If we can find an actual
                # partition (i.e. sda5) in /sys/block/dm-*/slaves/, we can then
                # search the FS using the corresponding dm-X in the partitions dict.
                mapper = glob(f"/sys/block/dm-*/slaves/{partition_key}")
                if mapper and (mapper_key := mapper[0].split("/")[3]) in partitions:
                    partition_obj = partitions[mapper_key]

            block = partition_obj[UDISK_BLOCK_IFC]

            if UDISK_FILESYSTEM_IFC in partition_obj:
                device_partitions[partition_key] = DiskParts(
                    devname=partition_devname,
                    filesystem=block["IdType"],
                    encrypted=encrypted,
                    mountpoint=bytearray_to_string(
                        partition_obj[UDISK_FILESYSTEM_IFC]["MountPoints"][0]
                    ),
                )

        result[key] = dataclasses.asdict(
            DiskInfos(
                devname=devname,
                model=drive["Model"],
                serial=drive["Serial"],
                size=drive["Size"],
                links=list(
                    sorted(
                        bytearray_to_string(it)
                        for it in device[UDISK_BLOCK_IFC]["Symlinks"]
                    )
                ),
                partitions=device_partitions or None,
            ),
            dict_factory=OrderedDict,
        )

    return result
