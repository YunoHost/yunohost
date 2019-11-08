#!/usr/bin/env python
import os
import psutil

from yunohost.diagnosis import Diagnoser

class SystemResourcesDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600 * 24
    dependencies = []

    def run(self):

        #
        # RAM
        #

        ram = psutil.virtual_memory()
        ram_total_abs_MB = ram.total / (1024**2)
        ram_available_abs_MB = ram.available / (1024**2)
        ram_available_percent = round(100 * ram.available / ram.total)
        item = dict(meta={"test": "ram"})
        infos = {"total_abs_MB": ram_total_abs_MB, "available_abs_MB": ram_available_abs_MB, "available_percent": ram_available_percent}
        if ram_available_abs_MB < 100 or ram_available_percent < 5:
            item["status"] = "ERROR"
            item["summary"] = ("diagnosis_ram_verylow", infos)
        elif ram_available_abs_MB < 200 or ram_available_percent < 10:
            item["status"] = "WARNING"
            item["summary"] = ("diagnosis_ram_low", infos)
        else:
            item["status"] = "SUCCESS"
            item["summary"] = ("diagnosis_ram_ok", infos)
        yield item

        #
        # Swap
        #

        swap = psutil.swap_memory()
        swap_total_abs_MB = swap.total / (1024*1024)
        item = dict(meta={"test": "swap"})
        infos = {"total_MB": swap_total_abs_MB}
        if swap_total_abs_MB <= 0:
            item["status"] = "ERROR"
            item["summary"] = ("diagnosis_swap_none", infos)
        elif swap_total_abs_MB <= 256:
            item["status"] = "WARNING"
            item["summary"] = ("diagnosis_swap_notsomuch", infos)
        else:
            item["status"] = "SUCCESS"
            item["summary"] = ("diagnosis_swap_ok", infos)
        yield item

        #
        # Disks usage
        #

        disk_partitions = psutil.disk_partitions()

        for disk_partition in disk_partitions:
            device = disk_partition.device
            mountpoint = disk_partition.mountpoint

            usage = psutil.disk_usage(mountpoint)
            free_abs_GB = usage.free / (1024 ** 3)
            free_percent = 100 - usage.percent

            item = dict(meta={"test": "diskusage", "mountpoint": mountpoint})
            infos = {"mountpoint": mountpoint, "device": device, "free_abs_GB": free_abs_GB, "free_percent": free_percent}
            if free_abs_GB < 1 or free_percent < 5:
                item["status"] = "ERROR"
                item["summary"] = ("diagnosis_diskusage_verylow", infos)
            elif free_abs_GB < 2 or free_percent < 10:
                item["status"] = "WARNING"
                item["summary"] = ("diagnosis_diskusage_low", infos)
            else:
                item["status"] = "SUCCESS"
                item["summary"] = ("diagnosis_diskusage_ok", infos)

            yield item


def main(args, env, loggers):
    return SystemResourcesDiagnoser(args, env, loggers).diagnose()
