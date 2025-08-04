#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
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

import subprocess
import os
import logging

# FIXME: wtf ? what was that x_x
# Prevent to import subprocess only for common classes
# CalledProcessError = subprocess.CalledProcessError

logger = logging.getLogger("yunohost.utils.process")


def check_output(args, stderr=subprocess.STDOUT, shell=True, **kwargs) -> str:
    """Run command with arguments and return its output as a byte string

    Overwrite some of the arguments to capture standard error in the result
    and use shell by default before calling subprocess.check_output.

    """
    return (
        subprocess.check_output(args, stderr=stderr, shell=shell, **kwargs)
        .decode("utf-8")
        .strip()
    )


def call_async_output(args, callback, **kwargs) -> int | None:
    """Run command and provide its output asynchronously

    Run command with arguments and wait for it to complete to return the
    returncode attribute. The `callback` can be a method or a 2-tuple of
    methods - for stdout and stderr respectively - which must take one
    byte string argument. It will be called each time the command produces
    some output.

    The stdout and stderr additional arguments for the Popen constructor
    are not allowed as they are used internally.

    Keyword arguments:
        - args -- String or sequence of program arguments
        - callback -- Method or object to call with output as argument
        - kwargs -- Additional arguments for the Popen constructor

    Returns:
        Exit status of the command

    """
    from queue import Queue, Empty

    for a in ["stdout", "stderr"]:
        if a in kwargs:
            raise ValueError("%s argument not allowed, it will be overridden." % a)

    log_queue: Queue = Queue()

    kwargs["stdout"] = LogPipe(callback[0], log_queue)
    kwargs["stderr"] = LogPipe(callback[1], log_queue)
    stdinfo = LogPipe(callback[2], log_queue) if len(callback) >= 3 else None
    if stdinfo:
        kwargs["pass_fds"] = [stdinfo.fdWrite]
        if "env" not in kwargs:
            kwargs["env"] = os.environ
        kwargs["env"]["YNH_STDINFO"] = str(stdinfo.fdWrite)

    if "env" in kwargs and not all(isinstance(v, str) for v in kwargs["env"].values()):
        logger.warning(
            "While trying to call call_async_output: env contained non-string values, probably gonna cause issue in Popen(...)"
        )

    try:
        p = subprocess.Popen(args, **kwargs)

        while p.poll() is None:
            while True:
                try:
                    callback, message = log_queue.get(True, 0.1)
                except Empty:
                    break

                callback(message)
        while True:
            try:
                callback, message = log_queue.get_nowait()
            except Empty:
                break

            callback(message)
    finally:
        kwargs["stdout"].close()
        kwargs["stderr"].close()
        if stdinfo:
            stdinfo.close()

    return p.poll()


# cf https://stackoverflow.com/questions/9192539
# The API uses monkey.patch_all() and we have to switch to a proper greenlet
# thread for the LogPipe stuff to work properly (maybe we should also enable
# gevent on the CLI, idk...)
from gevent import monkey

if monkey.is_module_patched("threading"):
    from gevent import Greenlet
    from gevent.fileobject import FileObjectThread

    Thread = Greenlet
else:
    from threading import Thread

    FileObjectThread = os.fdopen


class LogPipe(Thread):
    # Adapted from https://codereview.stackexchange.com/a/17959
    def __init__(self, log_callback, queue):
        """Setup the object with a logger and a loglevel
        and start the thread
        """
        Thread.__init__(self)
        self.daemon = False
        self.log_callback = log_callback

        self.fdRead, self.fdWrite = os.pipe()
        self.pipeReader = FileObjectThread(self.fdRead, "rb")

        self.queue = queue

        self.start()

    def fileno(self):
        """Return the write file descriptor of the pipe"""
        return self.fdWrite

    def run(self):
        """Run the thread, logging everything."""
        for line in iter(self.pipeReader.readline, b""):
            self.queue.put((self.log_callback, line.decode("utf-8").strip("\n")))

        self.pipeReader.close()

    def close(self):
        """Close the write end of the pipe."""
        os.close(self.fdWrite)
