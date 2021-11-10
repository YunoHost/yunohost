#!/usr/bin/env python
import os
import psutil
import datetime
import re

from moulinette.utils.process import check_output

from yunohost.diagnosis import Diagnoser


class SystemResourcesDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies = []

    def run(self):

        MB = 1024 ** 2
        GB = MB * 1024

        #
        # RAM
        #

        ram = psutil.virtual_memory()
        ram_available_percent = 100 * ram.available / ram.total
        item = dict(
            meta={"test": "ram"},
            data={
                "total": human_size(ram.total),
                "available": human_size(ram.available),
                "available_percent": round_(ram_available_percent),
            },
        )

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
        item = dict(
            meta={"test": "swap"},
            data={"total": human_size(swap.total), "recommended": "512 MiB"},
        )
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

        # Ignore /dev/loop stuff which are ~virtual partitions ? (e.g. mounted to /snap/)
        disk_partitions = [
            d
            for d in disk_partitions
            if d.mountpoint in ["/", "/var"] or not d.device.startswith("/dev/loop")
        ]

        for disk_partition in disk_partitions:
            device = disk_partition.device
            mountpoint = disk_partition.mountpoint

            usage = psutil.disk_usage(mountpoint)
            free_percent = 100 - round_(usage.percent)

            item = dict(
                meta={"test": "diskusage", "mountpoint": mountpoint},
                data={
                    "device": device,
                    # N.B.: we do not use usage.total because we want
                    # to take into account the 5% security margin
                    # correctly (c.f. the doc of psutil ...)
                    "total": human_size(usage.used + usage.free),
                    "free": human_size(usage.free),
                    "free_percent": free_percent,
                },
            )

            # We have an additional absolute constrain on / and /var because
            # system partitions are critical, having them full may prevent
            # upgrades etc...
            if free_percent < 2.5 or (
                mountpoint in ["/", "/var"] and usage.free < 1 * GB
            ):
                item["status"] = "ERROR"
                item["summary"] = "diagnosis_diskusage_verylow"
            elif free_percent < 5 or (
                mountpoint in ["/", "/var"] and usage.free < 2 * GB
            ):
                item["status"] = "WARNING"
                item["summary"] = "diagnosis_diskusage_low"
            else:
                item["status"] = "SUCCESS"
                item["summary"] = "diagnosis_diskusage_ok"

            yield item

        #
        # Check for minimal space on / + /var
        # because some stupid VPS provider only configure a stupidly
        # low amount of disk space for the root partition
        # which later causes issue when it gets full...
        #

        main_disk_partitions = [
            d for d in disk_partitions if d.mountpoint in ["/", "/var"]
        ]
        main_space = sum(
            [psutil.disk_usage(d.mountpoint).total for d in main_disk_partitions]
        )
        if main_space < 10 * GB:
            yield dict(
                meta={"test": "rootfstotalspace"},
                data={"space": human_size(main_space)},
                status="ERROR",
                summary="diagnosis_rootfstotalspace_critical",
            )
        elif main_space < 14 * GB:
            yield dict(
                meta={"test": "rootfstotalspace"},
                data={"space": human_size(main_space)},
                status="WARNING",
                summary="diagnosis_rootfstotalspace_warning",
            )

        #
        # Recent kills by oom_reaper
        #

        kills_count = self.recent_kills_by_oom_reaper()
        if kills_count:
            kills_summary = "\n".join(
                ["%s (x%s)" % (proc, count) for proc, count in kills_count]
            )

            yield dict(
                meta={"test": "oom_reaper"},
                status="WARNING",
                summary="diagnosis_processes_killed_by_oom_reaper",
                data={"kills_summary": kills_summary},
            )

    def recent_kills_by_oom_reaper(self):
        if not os.path.exists("/var/log/kern.log"):
            return []

        def analyzed_kern_log():

            cmd = 'tail -n 10000 /var/log/kern.log | grep "oom_reaper: reaped process" || true'
            out = check_output(cmd)
            lines = out.split("\n") if out else []

            now = datetime.datetime.now()

            for line in reversed(lines):
                # Lines look like :
                # Aug 25 18:48:21 yolo kernel: [ 9623.613667] oom_reaper: reaped process 11509 (uwsgi), now anon-rss:0kB, file-rss:0kB, shmem-rss:328kB
                date_str = str(now.year) + " " + " ".join(line.split()[:3])
                date = datetime.datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
                diff = now - date
                if diff.days >= 1:
                    break
                process_killed = re.search(r"\(.*\)", line).group().strip("()")
                yield process_killed

        processes = list(analyzed_kern_log())
        kills_count = [
            (p, len([p_ for p_ in processes if p_ == p])) for p in set(processes)
        ]
        kills_count = sorted(kills_count, key=lambda p: p[1], reverse=True)

        return kills_count


def human_size(bytes_):
    # Adapted from https://stackoverflow.com/a/1094933
    for unit in ["", "ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(bytes_) < 1024.0:
            return "%s %sB" % (round_(bytes_), unit)
        bytes_ /= 1024.0
    return "%s %sB" % (round_(bytes_), "Yi")


def round_(n):
    # round_(22.124) -> 22
    # round_(9.45) -> 9.4
    n = round(n, 1)
    if n > 10:
        n = int(round(n))
    return n


def main(args, env, loggers):
    return SystemResourcesDiagnoser(args, env, loggers).diagnose()
