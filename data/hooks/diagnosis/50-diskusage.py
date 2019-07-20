#!/usr/bin/env python
import os
import psutil

from yunohost.diagnosis import Diagnoser

class DiskUsageDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 3600 * 24

    def validate_args(self, args):
        # TODO / FIXME Ugh do we really need this arg system
        return {}

    def run(self):

        disk_partitions = psutil.disk_partitions()

        for disk_partition in disk_partitions:
            device = disk_partition.device
            mountpoint = disk_partition.mountpoint

            usage = psutil.disk_usage(mountpoint)
            free_Go = usage.free / (1024 ** 3)
            free_percent = 100 - usage.percent

            item = dict(meta={"mountpoint": mountpoint, "device": device})
            if free_Go < 1 or free_percent < 5:
                item["status"] = "ERROR"
                item["summary"] = ("diagnosis_diskusage_verylow", {"mountpoint": mountpoint, "device": device, "free_percent": free_percent})
            elif free_Go < 2 or free_percent < 10:
                item["status"] = "WARNING"
                item["summary"] = ("diagnosis_diskusage_low", {"mountpoint": mountpoint, "device": device, "free_percent": free_percent})
            else:
                item["status"] = "SUCCESS"
                item["summary"] = ("diagnosis_diskusage_ok", {"mountpoint": mountpoint, "device": device, "free_percent": free_percent})

            yield item

def main(args, env, loggers):
    return DiskUsageDiagnoser(args, env, loggers).diagnose()
