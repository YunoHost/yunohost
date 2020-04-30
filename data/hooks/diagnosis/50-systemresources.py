#!/usr/bin/env python
import os
import psutil

from yunohost.diagnosis import Diagnoser

class SystemResourcesDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies = []

    def run(self):

        MB = 1024**2
        GB = MB*1024

        #
        # RAM
        #

        ram = psutil.virtual_memory()
        ram_available_percent = 100 * ram.available / ram.total
        item = dict(meta={"test": "ram"},
                    data={"total": human_size(ram.total),
                          "available": human_size(ram.available),
                          "available_percent": round_(ram_available_percent)})

        if ram.available < 100 * MB or ram_available_percent < 5:
            item["status"] = "ERROR"
            item["summary"] = "diagnosis_ram_verylow"
        elif ram.available < 200 * MB or ram_available_percent < 10:
            item["status"] = "WARNING"
            item["summary"] = "diagnosis_ram_low"
        else:
            item["status"] = "SUCCESS"
            item["summary"] = "diagnosis_ram_ok"
        yield item

        #
        # Swap
        #

        swap = psutil.swap_memory()
        item = dict(meta={"test": "swap"},
                    data={"total": human_size(swap.total), "recommended": "512 MiB"})
        if swap.total <= 1 * MB:
            item["status"] = "ERROR"
            item["summary"] = "diagnosis_swap_none"
        elif swap.total < 500 * MB:
            item["status"] = "WARNING"
            item["summary"] = "diagnosis_swap_notsomuch"
        else:
            item["status"] = "SUCCESS"
            item["summary"] = "diagnosis_swap_ok"
        yield item

        # FIXME : add a check that swapiness is low if swap is on a sdcard...

        #
        # Disks usage
        #

        disk_partitions = psutil.disk_partitions()

        for disk_partition in disk_partitions:
            device = disk_partition.device
            mountpoint = disk_partition.mountpoint

            usage = psutil.disk_usage(mountpoint)
            free_percent = round_(100 - usage.percent)

            item = dict(meta={"test": "diskusage", "mountpoint": mountpoint},
                        data={"device": device, "total": human_size(usage.total), "free": human_size(usage.free), "free_percent": free_percent})

            # Special checks for /boot partition because they sometimes are
            # pretty small and that's kind of okay... (for example on RPi)
            if mountpoint.startswith("/boot"):
                if usage.free < 10 * MB or free_percent < 10:
                    item["status"] = "ERROR"
                    item["summary"] = "diagnosis_diskusage_verylow"
                elif usage.free < 20 * MB or free_percent < 20:
                    item["status"] = "WARNING"
                    item["summary"] = "diagnosis_diskusage_low"
                else:
                    item["status"] = "SUCCESS"
                    item["summary"] = "diagnosis_diskusage_ok"
            else:
                if usage.free < 1 * GB or free_percent < 5:
                    item["status"] = "ERROR"
                    item["summary"] = "diagnosis_diskusage_verylow"
                elif usage.free < 2 * GB or free_percent < 10:
                    item["status"] = "WARNING"
                    item["summary"] = "diagnosis_diskusage_low"
                else:
                    item["status"] = "SUCCESS"
                    item["summary"] = "diagnosis_diskusage_ok"


            yield item


def human_size(bytes_):
    # Adapted from https://stackoverflow.com/a/1094933
    for unit in ['','ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(bytes_) < 1024.0:
            return "%s %sB" % (round_(bytes_), unit)
        bytes_ /= 1024.0
    return "%s %sB" % (round_(bytes_), 'Yi')


def round_(n):
    # round_(22.124) -> 22
    # round_(9.45) -> 9.4
    n = round(n, 1)
    if n > 10:
        n = int(round(n))
    return n

def main(args, env, loggers):
    return SystemResourcesDiagnoser(args, env, loggers).diagnose()
