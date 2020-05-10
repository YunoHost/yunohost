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
            item["status"] = "INFO"
            item["summary"] = "diagnosis_swap_none"
        elif swap.total < 450 * MB:
            item["status"] = "INFO"
            item["summary"] = "diagnosis_swap_notsomuch"
        else:
            item["status"] = "SUCCESS"
            item["summary"] = "diagnosis_swap_ok"
        item["details"] = ["diagnosis_swap_tip"]
        yield item

        # FIXME : add a check that swapiness is low if swap is on a sdcard...

        #
        # Disks usage
        #

        disk_partitions = sorted(psutil.disk_partitions(), key=lambda k: k.mountpoint)

        for disk_partition in disk_partitions:
            device = disk_partition.device
            mountpoint = disk_partition.mountpoint

            usage = psutil.disk_usage(mountpoint)
            free_percent = 100 - round_(usage.percent)

            item = dict(meta={"test": "diskusage", "mountpoint": mountpoint},
                        data={"device": device,
                              # N.B.: we do not use usage.total because we want
                              # to take into account the 5% security margin
                              # correctly (c.f. the doc of psutil ...)
                              "total": human_size(usage.used+usage.free),
                              "free": human_size(usage.free),
                              "free_percent": free_percent})

            # We have an additional absolute constrain on / and /var because
            # system partitions are critical, having them full may prevent
            # upgrades etc...
            if free_percent < 2.5 or (mountpoint in ["/", "/var"] and usage.free < 1 * GB):
                item["status"] = "ERROR"
                item["summary"] = "diagnosis_diskusage_verylow"
            elif free_percent < 5 or (mountpoint in ["/", "/var"] and usage.free < 2 * GB):
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
