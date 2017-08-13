# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_part.py

    IM DOING STUFFS
"""
import os
import re
import json
import glob
import base64
import errno
import requests
import subprocess
import parted
import pyudev
import pexpect
import sys

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.domain import get_public_ip, _get_maindomain

logger = getActionLogger('yunohost.part')

class Mdadm(object):
    def __init__(self):
        pass

    def create(self, device, level, devices_list, name = None, chunk = None, force = False):
        errors = []
        can_continue = False

        args = ['--create', device]
        if chunk:
            args += ['-c', chunk]
        if name:
            args += ['-N', name]

        args += ['-l', level, '-n', str(len(devices_list))]
        args += devices_list
        self.child = pexpect.spawn('mdadm', args)
        #self.child.logfile = sys.stdout
        try:
            errors = self._parse_errors([])
            if self.child.after.strip() == 'Continue creating array?':
                can_continue = True
                if force:
                    self.child.sendline('Y')
                    self.child.expect('Y\r\n')
                    result = self._parse_errors([])
                    ret = self.child.wait()
                    return { 'warnings': errors, 'result': result, 'success': True if ret == 0 else False }
        except(pexpect.EOF):
            pass

        return { 'errors': errors, 'can_continue': can_continue }

    def _parse_errors(self, errors):
        if self.child.expect(['^mdadm:[^\r]+\r\n', pexpect.EOF, 'Continue creating array\? ']) == 0:
            error = self.child.after.strip()
            if self.child.expect(['\s+[^\r]+\r\n', pexpect.EOF]) == 0:
                error += ' - ' + self.child.after.strip()
            errors.append(error)
            return self._parse_errors(errors)
        return errors

class Fdisk(object):
    """Main program class"""

    def __init__(self, devpath):
        # Supported commands and corresponding handlers

        try:
            self.device = parted.getDevice(devpath)
        except parted.IOException as e:
            raise RuntimeError(e.message)

        try:
            self.disk = parted.newDisk(self.device)
            if self.disk.type != 'msdos':
                raise RuntimeError('Only MBR partitions are supported')
        except parted.DiskException:
            self.create_empty()


    def toggle_bootable(self, index):
        """toggle a bootable flag"""
        if not self.disk.partitions:
            raise RuntimeError('No partition is defined yet!')

        for p in self.disk.partitions:
            if p.number == index:
                #print('Found it !')
                if not p.getFlag(parted.PARTITION_BOOT):
                    p.setFlag(parted.PARTITION_BOOT)
                else:
                    p.unsetFlag(parted.PARTITION_BOOT)
                return True
        raise RuntimeError('No partition with index ' + index)

    def toggle_raid(self, index):
        """toggle a bootable flag"""
        if not self.disk.partitions:
            raise RuntimeError('No partition is defined yet!')

        for p in self.disk.partitions:
            if p.number == index:
                if not p.getFlag(parted.PARTITION_RAID):
                    p.setFlag(parted.PARTITION_RAID)
                else:
                    p.unsetFlag(parted.PARTITION_RAID)
                return True
        raise RuntimeError('No partition with index ' + index)

    def delete_partition(self, index):
        """delete a partition"""
        if not self.disk.partitions:
            raise RuntimeError('No partition is defined yet!')
        number = int(index)#self._ask_partition()
        for p in self.disk.partitions:
            if p.number == number:
                self.disk.deletePartition(p)
                return True
        raise RuntimeError('No partition with index ' + index)
                
    def add_partition(self, type, part_start, part_end):
        """add a new partition"""
        # Primary partitions count
        pri_count = len(self.disk.getPrimaryPartitions())
        # HDDs may contain only one extended partition
        ext_count = 1 if self.disk.getExtendedPartition() else 0
        # First logical partition number
        lpart_start = self.disk.maxPrimaryPartitionCount + 1
        # Number of spare partitions slots
        parts_avail = self.disk.maxPrimaryPartitionCount - (pri_count + ext_count)

        data = {
            'primary': pri_count,
            'extended': ext_count,
            'free': parts_avail,
            'first_logical': lpart_start
        }
        default = None
        options = set()

        geometry = self._get_largest_free_region()
        if not geometry:
            raise RuntimeError('No free sectors available')

        if not parts_avail and not ext_count:
            raise RuntimeError("""If you want to create more than four partitions, you must replace a
primary partition with an extended partition first.""")

        if parts_avail:
            default = 'p'
            options.add('p')
            if not ext_count:
                # If we have only one spare partition, suggest extended
                if pri_count >= 3:
                    default = 'e'
                options.add('e')
        if ext_count:
            # XXX: We do not observe disk.getMaxLogicalPartitions() constraint
            default = default or 'l'
            options.add('l')

        # fdisk doesn't display a menu if it has only one option, but we do
        choice = type#raw_input('Select (default {default:s}): '.format(default=default))
        if not choice:
            choice = default

        if not choice[0] in options:
            raise RuntimeError("Invalid partition type `{choice}'".format(choice=choice))

        try:
            partition = None
            ext_part = self.disk.getExtendedPartition()
            if choice[0] == 'p':
                # If there is an extended partition, we look for free region that is
                # completely outside of it.
                if ext_part:
                    try:
                        ext_part.geometry.intersect(geometry)
                        print 'No free sectors available'
                        return
                    except ArithmeticError:
                        # All ok
                        pass

                p = self._create_partition(geometry, part_start, part_end, type=parted.PARTITION_NORMAL)
            elif choice[0] == 'e':
                # Create extended partition in the largest free region
                p = self._create_partition(geometry, part_start, part_end, type=parted.PARTITION_EXTENDED)
            elif choice[0] == 'l':
                # Largest free region must be (at least partially) inside the
                # extended partition.
                try:
                    geometry = ext_part.geometry.intersect(geometry)
                except ArithmeticError:
                    print "No free sectors available"
                    return

                p = self._create_partition(geometry, part_start, part_end, type=parted.PARTITION_LOGICAL)

            if p:
                return self._format_partition(p)
        except RuntimeError as e:
            print e.message

    def create_empty(self):
        """create a new empty DOS partition table"""
        self.disk = parted.freshDisk(self.device, 'msdos')

    def print_partitions(self):
        """print the partition table"""
        device, disk = self.device, self.disk
        unit = device.sectorSize
        size = device.length * device.sectorSize
        cylinders, heads, sectors = device.hardwareGeometry
        data = {
            'path': device.path,
            'size': size,
            'size_human': humanize_sizeof(size),
            'heads': heads,
            'sectors': sectors,
            'cylinders': cylinders,
            'sectors_total': device.length,
            'unit': unit,
            'sector_size': device.sectorSize,
            'physical_sector_size': device.physicalSectorSize,
            # Try to guess minimum_io_size and optimal_io_size, should work under Linux
            'minimum_io_size': device.minimumAlignment.grainSize * device.sectorSize,
            'optimal_io_size': device.optimumAlignment.grainSize * device.sectorSize,
        }
        results = { 'device': data, 'partitions': {} }

        for p in disk.partitions:
            results['partitions'][p.number] = self._format_partition(p)

        return results


    def write(self):
        """write table to disk and exit"""
        self.disk.commit()

    def _parse_last_sector_expr(self, start, value, sector_size):
        """Parses fdisk(1)-style partition end exception"""
        import re

        # map fdisk units to PyParted ones
        known_units = {'K': 'KiB', 'M': 'MiB', 'G': 'GiB',
                       'KB': 'kB', 'MB': 'MB', 'GB': 'GB'}

        match = re.search('^\+(?P<num>\d+)(?P<unit>[KMG]?)$', value)
        if match:
            # num must be an integer; if not, raise ValueError
            num = int(match.group('num'))
            unit = match.group('unit')
            if not unit:
                # +sectors
                sector = start + num
                return sector
            elif unit in known_units.keys():
                # +size{K,M,G}
                sector = start + parted.sizeToSectors(num, known_units[unit], sector_size)
                return sector
        else:
            # must be an integer (sector); if not, raise ValueError
            sector = int(value)
            return sector

    def _create_partition(self, region, start, end, type=parted.PARTITION_NORMAL):
        """Creates the partition with geometry specified"""
        # libparted doesn't let setting partition number, so we skip it, too

        # We want our new partition to be optimally aligned
        # (you can use minimalAlignedConstraint, if you wish).
        alignment = self.device.optimalAlignedConstraint
        constraint = parted.Constraint(maxGeom=region).intersect(alignment)
        data = {
            'start': constraint.startAlign.alignUp(region, region.start),
            'end': constraint.endAlign.alignDown(region, region.end),
        }

        part_start = int(start)
        #check sur data['start']

        part_end = self._parse_last_sector_expr(part_start, end, self.device.sectorSize)#self._ask_value(
        #check sur data['end']

        try:
            geometry = parted.Geometry(device=self.device, start=part_start, end=part_end)
            #fs = parted.FileSystem(type='ntfs', geometry=geometry)

            partition = parted.Partition(
                disk=self.disk,
                type=type,
                geometry=geometry,
                fs=None
            )
            self.disk.addPartition(partition=partition, constraint=constraint)
        except (parted.PartitionException, parted.GeometryException, parted.CreateException) as e:
            # GeometryException accounts for incorrect start/end values (e.g. start < end),
            # CreateException is raised e.g. when the partition doesn't fit on the disk.
            # PartedException is a generic error (e.g. start/end values out of range)
            raise RuntimeError(e.message)

        return partition

    def _guess_system(self, partition):
        """Tries to guess partition type"""
        if not partition.fileSystem:
            if partition.getFlag(parted.PARTITION_SWAP):
                return 'Linux swap / Solaris'
            elif partition.getFlag(parted.PARTITION_RAID):
                return 'Linux raid autodetect'
            elif partition.getFlag(parted.PARTITION_LVM):
                return 'Linux LVM'
            else:
                return 'unknown'
        else:
            if partition.fileSystem.type in {'ext2', 'ext3', 'ext4', 'btrfs', 'reiserfs', 'xfs', 'jfs'}:
                return 'Linux'
            # If mkswap(1) was run on the partition, upper branch won't be executed
            elif partition.fileSystem.type.startswith('linux-swap'):
                return 'Linux swap / Solaris'
            elif partition.fileSystem.type == 'fat32':
                return 'W95 FAT32'
            elif partition.fileSystem.type == 'fat16':
                return 'W95 FAT16'
            elif partition.fileSystem.type == 'ntfs':
                return 'HPFS/NTFS/exFAT'
            else:
                return 'unknown'

    def _get_largest_free_region(self):
        """Finds largest free region on the disk"""
        # There are better ways to do it, but let's be straightforward
        max_size = -1
        region = None

        alignment = self.device.optimumAlignment

        for r in self.disk.getFreeSpaceRegions():
            # Heuristic: Ignore alignment gaps
            if r.length > max_size and r.length > alignment.grainSize:
                region = r
                max_size = r.length

        return region

    def _format_partition(self, p):
        size_kib = int(parted.formatBytes(p.geometry.length * self.device.sectorSize, 'KiB'));
        return {
            'path': p.path,
            'boot': p.getFlag(parted.PARTITION_BOOT),
            'raid': p.getFlag(parted.PARTITION_RAID),
            'start': p.geometry.start,
            'end': p.geometry.end,
            'blocks': size_kib,
            'id': p.number,
            'system': self._guess_system(p),
            'system_type': p.fileSystem.type if p.fileSystem else None,
            'size': humanize_sizeof(p.geometry.length * self.device.sectorSize),
            #'system_raw': p.fileSystem
        }

def humanize_sizeof(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

###
### Yunhost functions ###
###

def part_list_all(auth = None):
    try:
        context = pyudev.Context()
        devices = [device.device_node for device in context.list_devices(DEVTYPE='disk') if device['MAJOR'] == '8' or device['MAJOR'] == '3']
        return {'devices': [part_list(dev, auth) for dev in devices]}
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_list(devpath = None, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        return fdisk.print_partitions()
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_toggle_boot(devpath, index, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        ret = fdisk.toggle_bootable(int(index))
        fdisk.write()
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_toggle_raid(devpath, index, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        ret = fdisk.toggle_raid(int(index))
        fdisk.write()
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_create(devpath, type, start, size, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        ret = fdisk.add_partition(type, start, size)
        fdisk.write()
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_delete(devpath, index, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        ret = fdisk.delete_partition(index)
        fdisk.write()
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_type(devpath, index, type, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        ret = fdisk.change_type(index, type)
        fdisk.write()
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)

def part_fresh_disk(devpath, auth = None):
    try:
        fdisk = Fdisk(devpath=devpath)
        ret = fdisk.create_empty()
        fdisk.write()
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)


def part_raid_create(device, level, devices, force=False, auth = None):
    try:
        mdadm = Mdadm()
        ret = mdadm.create(device=device, level=level, devices_list=devices, force=force)
        return ret
    except Exception as e:
        raise MoulinetteError(errno.EIO, e.message)
