import glob
import os
import json
import time
import psutil
from logging import Handler

LOG_BROKER_BACKEND_ENDPOINT = "ipc:///var/run/yunohost/log_broker_backend"
LOG_BROKER_FRONTEND_ENDPOINT = "ipc:///var/run/yunohost/log_broker_frontend"

if not os.path.isdir("/var/run/yunohost"):
    os.mkdir("/var/run/yunohost")
os.chown("/var/run/yunohost", 0, 0)
os.chmod("/var/run/yunohost", 0o700)

SSE_HEARTBEAT_PERIOD = 10  # seconds


def start_log_broker():

    from multiprocessing import Process

    def server():
        import zmq

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


class SSELogStreamingHandler(Handler):

    def __init__(self, operation_id, flash=False):
        super().__init__()
        self.operation_id = operation_id
        self.flash = flash

        from moulinette import Moulinette

        if Moulinette.interface.type == "api":
            from bottle import request

            self.ref_id = request.get_header("ref-id")
        else:
            from uuid import uuid4

            self.ref_id = str(uuid4())

        import zmq

        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.connect(LOG_BROKER_BACKEND_ENDPOINT)

        from yunohost.log import OPERATIONS_PATH

        if not flash:
            # Since we're starting this operation, garbage all the previous streamcache
            old_stream_caches = glob.iglob(OPERATIONS_PATH + ".*.logstreamcache")
            for old_stream_cache in old_stream_caches:
                os.remove(old_stream_cache)
            # Start a new log stream cache, meant to be replayed for client opening
            # the SSE when an operation is already ongoing
            self.log_stream_cache = open(
                OPERATIONS_PATH + f"/.{self.operation_id}.logstreamcache", "w"
            )
        else:
            self.log_stream_cache = None

        # FIXME ? ... Boring hack because otherwise it seems we lose messages emitted while
        # the socket ain't properly connected to the other side
        time.sleep(1)

    def emit(self, record):

        self._encode_and_pub(
            {
                "type": "msg" if not self.flash else "toast",
                "timestamp": record.created,
                "level": record.levelname.lower(),
                "msg": self.format(record),
            }
        )

    def emit_error_toast(self, error):
        self._encode_and_pub(
            {
                "type": "toast",
                "timestamp": time.time(),
                "level": "error",
                "msg": error,
            }
        )

    def emit_operation_start(self, time, title, started_by):

        self._encode_and_pub(
            {
                "type": "start",
                "timestamp": time.timestamp(),
                "title": title,
                "started_by": started_by,
            }
        )

    def emit_operation_end(self, time, success, errormsg):

        self._encode_and_pub(
            {
                "type": "end",
                "success": success,
                "errormsg": errormsg,
                "timestamp": time.timestamp(),
            }
        )

    def _encode_and_pub(self, data):

        data["operation_id"] = self.operation_id
        data["ref_id"] = self.ref_id
        type = data.pop("type")

        payload = type + ":" + json.dumps(data)

        if self.log_stream_cache:
            try:
                self.log_stream_cache.write(payload + "\n")
                self.log_stream_cache.flush()
            except Exception:
                # Not a huge deal if we can't write to the file for some reason...
                pass

        self.socket.send_multipart([b"", payload.encode()])

    def close(self, *args, **kwargs):
        super().close(*args, **kwargs)
        self.socket.close()
        self.context.term()
        if self.log_stream_cache:
            self.log_stream_cache.close()


def get_current_operation():
    try:
        with open("/var/run/moulinette_yunohost.lock") as f:
            pid = f.read().strip().split("\n")[0]
        lock_mtime = os.path.getmtime("/var/run/moulinette_yunohost.lock")
    except FileNotFoundError:
        return None, None, None

    try:
        process = psutil.Process(int(pid))
        process_open_files = process.open_files()
        process_command_line = (
            " ".join(process.cmdline()[1:]).replace("/usr/bin/", "") or "???"
        )
    except Exception:
        return None, None, None

    active_logs = [
        p.path.split("/")[-1]
        for p in process_open_files
        if p.mode == "w"
        and p.path.startswith("/var/log/yunohost/operations/")
        and p.path.endswith(".logstreamcache")
    ]
    if active_logs:
        operation_id = sorted(active_logs)[0][: -len(".logstreamcache")].strip(".")
    else:
        operation_id = f"lock-{lock_mtime}"

    return pid, operation_id, process_command_line


def sse_stream():

    # We need zmq.green to uh have some sort of async ? (I think)
    import zmq.green as zmq
    from yunohost.log import log_list, OPERATIONS_PATH

    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.subscribe("")
    sub.connect(LOG_BROKER_FRONTEND_ENDPOINT)

    # Set client-side auto-reconnect timeout, ms.
    yield "retry: 100\n\n"

    # Check if there's any ongoing operation right now
    _, current_operation_id, _ = get_current_operation()

    # Log list metadata is cached so it shouldnt be a bit deal to ask for "details" (which loads the metadata yaml for every operation)
    recent_operation_history = log_list(since_days_ago=2, limit=20, with_details=True)[
        "operation"
    ]
    for operation in reversed(recent_operation_history):
        if current_operation_id and operation["name"] == current_operation_id:
            continue
        data = {
            "operation_id": operation["name"],
            "title": operation["description"],
            "success": operation["success"],
            "started_at": operation["started_at"].timestamp(),
            "started_by": operation["started_by"],
        }
        payload = json.dumps(data)
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
    last_heartbeat = 0

    try:
        while True:
            if time.time() - last_heartbeat > SSE_HEARTBEAT_PERIOD:
                _, current_operation_id, cmdline = get_current_operation()
                data = {
                    "current_operation": current_operation_id,
                    "cmdline": cmdline,
                    "timestamp": time.time(),
                }
                payload = json.dumps(data)
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
