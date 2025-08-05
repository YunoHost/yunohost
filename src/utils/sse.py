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
import json
import os
import time
import logging
import psutil

from datetime import datetime
from pathlib import Path
from typing import IO, TypedDict, NotRequired, Any, Generator

RUNDIR = Path("/var/run/yunohost")
MOULINETTE_LOCK = RUNDIR / "moulinette_yunohost.lock"

LOG_BROKER_BACKEND_ENDPOINT = f"ipc://{RUNDIR}/log_broker_backend"
LOG_BROKER_FRONTEND_ENDPOINT = f"ipc://{RUNDIR}/log_broker_frontend"
SSE_HEARTBEAT_PERIOD = 10  # seconds


def ensure_rundir() -> None:
    RUNDIR.mkdir(exist_ok=True)
    os.chown(RUNDIR, 0, 0)
    RUNDIR.chmod(0o700)


ensure_rundir()


def start_log_broker() -> None:
    from multiprocessing import Process
    import zmq

    def server() -> None:
        ctx = zmq.Context()
        backend = ctx.socket(zmq.XSUB)
        backend.bind(LOG_BROKER_BACKEND_ENDPOINT)
        frontend = ctx.socket(zmq.XPUB)
        frontend.bind(LOG_BROKER_FRONTEND_ENDPOINT)

        try:
            zmq.proxy(frontend, backend)
        except KeyboardInterrupt:
            pass

        frontend.close()
        backend.close()
        ctx.term()

    p = Process(target=server)
    p.start()


class SSEEventBase(TypedDict):
    operation_id: NotRequired[str]
    ref_id: NotRequired[str | None]
    type: NotRequired[str]


class SSEEventMessage(SSEEventBase):
    # type : Literal["toast"] | Literal["msg"]
    timestamp: float
    level: str
    msg: str


class SSEEventOperationStart(SSEEventBase):
    # type : Literal["start"]
    timestamp: float
    title: str
    started_by: str


class SSEEventOperationEnd(SSEEventBase):
    # type : Literal["end"]
    timestamp: float
    success: bool
    errormsg: str


class SSEEventHistory(SSEEventBase):
    # type : Literal["recent_history"]
    title: str
    success: bool
    started_at: float
    started_by: str


class SSEEventHeartbeat(SSEEventBase):
    # type : Literal["heartbeat"]
    timestamp: float
    current_operation: str | None
    cmdline: str | None
    started_by: str | None


SSEEvent = (
    SSEEventMessage
    | SSEEventHistory
    | SSEEventMessage
    | SSEEventOperationStart
    | SSEEventOperationEnd
)


class SSELogStreamingHandler(logging.Handler):
    def __init__(self, operation_id: str, flash: bool = False) -> None:
        super().__init__()
        self.operation_id = operation_id
        self.flash = flash
        self.ref_id: str | None
        self.log_stream_cache: IO[str] | None

        from moulinette import Moulinette
        import zmq
        from ..log import OPERATIONS_PATH

        if Moulinette.interface.type == "api":
            from bottle import request

            self.ref_id = request.get_header("ref-id")
        else:
            from uuid import uuid4

            self.ref_id = str(uuid4())

        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.connect(LOG_BROKER_BACKEND_ENDPOINT)

        if not flash:
            # Since we're starting this operation, garbage all the previous streamcache
            for old_stream_cache in Path(OPERATIONS_PATH).glob(".*.logstreamcache"):
                old_stream_cache.unlink()

            # Start a new log stream cache, meant to be replayed for client opening
            # the SSE when an operation is already ongoing
            stream_file = (
                Path(OPERATIONS_PATH) / f"/.{self.operation_id}.logstreamcache"
            )
            self.log_stream_cache = stream_file.open("w")
        else:
            self.log_stream_cache = None

        # FIXME ? ... Boring hack because otherwise it seems we lose messages emitted while
        # the socket ain't properly connected to the other side
        time.sleep(1)

    def emit(self, record: logging.LogRecord) -> None:
        event: SSEEventMessage = {
            "type": "msg" if not self.flash else "toast",
            "timestamp": record.created,
            "level": record.levelname.lower(),
            "msg": self.format(record),
        }
        self._encode_and_pub(event)

    def emit_error_toast(self, error: str) -> None:
        event: SSEEvent = {
            "type": "toast",
            "timestamp": time.time(),
            "level": "error",
            "msg": error,
        }
        self._encode_and_pub(event)

    def emit_operation_start(self, time: datetime, title: str, started_by: str) -> None:
        event: SSEEventOperationStart = {
            "type": "start",
            "timestamp": time.timestamp(),
            "title": title,
            "started_by": started_by,
        }
        self._encode_and_pub(event)

    def emit_operation_end(self, time: datetime, success: bool, errormsg: str) -> None:
        event: SSEEventOperationEnd = {
            "type": "end",
            "success": success,
            "errormsg": errormsg,
            "timestamp": time.timestamp(),
        }
        self._encode_and_pub(event)

    def _encode_and_pub(self, event: SSEEvent) -> None:
        event["operation_id"] = self.operation_id
        event["ref_id"] = self.ref_id
        type = event.pop("type")

        payload = f"{type}:{json.dumps(event)}"

        if self.log_stream_cache:
            try:
                self.log_stream_cache.write(payload + "\n")
                self.log_stream_cache.flush()
            except Exception:
                # Not a huge deal if we can't write to the file for some reason...
                pass

        self.socket.send_multipart([b"", payload.encode()])

    def close(self, *args: Any, **kwargs: Any) -> None:
        super().close(*args, **kwargs)
        self.socket.close()
        self.context.term()
        if self.log_stream_cache:
            self.log_stream_cache.close()


def get_current_operation() -> (
    tuple[str, str, str, str] | tuple[None, None, None, None]
):
    from ..log import _guess_who_started_process

    try:
        pid = MOULINETTE_LOCK.read_text().split("\n")[0]
        lock_mtime = MOULINETTE_LOCK.stat().st_mtime
    except FileNotFoundError:
        return None, None, None, None

    try:
        process = psutil.Process(int(pid))
        process_open_files = process.open_files()
        process_command_line = (
            " ".join(process.cmdline()[1:]).replace("/usr/bin/", "") or "???"
        )
    except Exception:
        return None, None, None, None

    active_logs = [
        p.path.split("/")[-1]
        for p in process_open_files
        if p.mode == "w"  # type: ignore[attr-defined] # dunno why mypy doesnt recognize it ...
        and p.path.startswith("/var/log/yunohost/operations/")
        and p.path.endswith(".logstreamcache")
    ]
    if active_logs:
        operation_id = sorted(active_logs)[0][: -len(".logstreamcache")].strip(".")
    else:
        operation_id = f"lock-{lock_mtime}"

    started_by = _guess_who_started_process(process)

    return pid, operation_id, process_command_line, started_by


def sse_stream() -> Generator[str, None, None]:
    # We need zmq.green to uh have some sort of async ? (I think)
    import zmq.green as zmq

    from ..log import OPERATIONS_PATH, log_list

    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.subscribe("")
    sub.connect(LOG_BROKER_FRONTEND_ENDPOINT)

    # Set client-side auto-reconnect timeout, ms.
    yield "retry: 100\n\n"

    # Check if there's any ongoing operation right now
    _, current_operation_id, _, _ = get_current_operation()

    # Log list metadata is cached so it shouldnt be a bit deal to ask for "details" (which loads the metadata yaml for every operation)
    recent_operation_history = log_list(since_days_ago=2, limit=20, with_details=True)[
        "operation"
    ]
    for operation in reversed(recent_operation_history):
        if current_operation_id and operation["name"] == current_operation_id:
            continue

        history_event: SSEEventHistory = {
            "operation_id": operation["name"],
            "title": operation["description"],
            "success": operation["success"],
            "started_at": operation["started_at"].timestamp(),
            "started_by": operation["started_by"],
        }
        payload = json.dumps(history_event)
        yield "event: recent_history\n"
        yield f"data: {payload}\n\n"

    if current_operation_id:
        log_stream_cache = None
        try:
            log_stream_cache = open(
                f"{OPERATIONS_PATH}/.{current_operation_id}.logstreamcache"
            )
        except Exception:
            pass
        else:
            entries = [entry.strip() for entry in log_stream_cache.readlines()]
            for payload in entries:
                type, payload = payload.split(":", 1)
                yield f"event: {type}\n"
                yield f"data: {payload}\n\n"
        finally:
            if log_stream_cache:
                log_stream_cache.close()

    # Init heartbeat
    last_heartbeat: float = 0

    try:
        while True:
            if time.time() - last_heartbeat > SSE_HEARTBEAT_PERIOD:
                _, current_operation_id, cmdline, started_by = get_current_operation()
                event: SSEEventHeartbeat = {
                    "current_operation": current_operation_id,
                    "cmdline": cmdline,
                    "timestamp": time.time(),
                    "started_by": started_by,
                }
                payload = json.dumps(event)
                yield "event: heartbeat\n"
                yield f"data: {payload}\n\n"
                last_heartbeat = time.time()
            if sub.poll(10, zmq.POLLIN):
                _, payload = sub.recv_multipart()
                type, payload = payload.decode().split(":", 1)
                yield f"event: {type}\n"
                yield f"data: {payload}\n\n"
    finally:
        sub.close()
        ctx.term()
