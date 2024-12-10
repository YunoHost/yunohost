import glob
import os
import base64
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

    def __init__(self, operation_id):
        super().__init__()
        self.operation_id = operation_id

        from moulinette import Moulinette
        if Moulinette.interface.type == "api":
            from bottle import request
            self.ref_id = request.get_header("ref_id")
        else:
            from uuid import uuid4
            self.ref_id = str(uuid4())

        import zmq
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.connect(LOG_BROKER_BACKEND_ENDPOINT)

        from yunohost.log import OPERATIONS_PATH

        # Since we're starting this operation, garbage all the previous streamcache
        old_stream_caches = glob.iglob(OPERATIONS_PATH + ".*.logstreamcache")
        for old_stream_cache in old_stream_caches:
            os.remove(old_stream_cache)
        # Start a new log stream cache, meant to be replayed for client opening
        # the SSE when an operation is already ongoing
        self.log_stream_cache = open(OPERATIONS_PATH + f"/.{self.operation_id}.logstreamcache", "w")

        # FIXME ? ... Boring hack because otherwise it seems we lose messages emitted while
        # the socket ain't properly connected to the other side
        time.sleep(1)

    def emit(self, record):

        self._encode_and_pub({
            "type": "msg",
            "timestamp": record.created,
            "level": record.levelname.lower(),
            "msg": self.format(record),
        })

    def emit_operation_start(self, time):

        self._encode_and_pub({
            "type": "start",
            "timestamp": time.timestamp(),
        })

    def emit_operation_end(self, time, success, errormsg):

        self._encode_and_pub({
            "type": "end",
            "success": success,
            "errormsg": errormsg,
            "timestamp": time.timestamp(),
        })

    def _encode_and_pub(self, data):

        data["operation_id"] = self.operation_id
        data["ref_id"] = self.ref_id

        payload = base64.b64encode(json.dumps(data).encode())

        try:
            self.log_stream_cache.write(payload.decode() + "\n")
            self.log_stream_cache.flush()
        except Exception:
            # Not a huge deal if we can't write to the file for some reason...
            pass

        self.socket.send_multipart([b'', payload])

    def close(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.socket.close()
        self.context.term()
        self.log_stream_cache.close()


def get_current_operation():
    try:
        with open("/var/run/moulinette_yunohost.lock") as f:
            pid = f.read().strip().split("\n")[0]
    except FileNotFoundError:
        return None

    try:
        process_open_files = psutil.Process(int(pid)).open_files()
    except Exception:
        return None

    active_logs = [
        p.path.split("/")[-1]
        for p in process_open_files
        if p.mode == "a" and p.path.startswith("/var/log/yunohost/operations/") and p.path.endswith(".log")
    ]
    if active_logs:
        main_active_log = sorted(active_logs)[0][:-len(".log")]
        return main_active_log
    else:
        return None


def sse_stream():

    # We need zmq.green to uh have some sort of async ? (I think)
    import zmq.green as zmq
    from yunohost.log import log_list, OPERATIONS_PATH

    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.subscribe('')
    sub.connect(LOG_BROKER_FRONTEND_ENDPOINT)

    # Set client-side auto-reconnect timeout, ms.
    yield 'retry: 100\n\n'

    # Check if there's any ongoing operation right now
    current_operation_id = get_current_operation()

    recent_operation_history = log_list(since_days_ago=2, limit=20)["operation"]
    for operation in reversed(recent_operation_history):
        if current_operation_id and operation["name"] == current_operation_id:
            continue
        data = {
            "type": "recent_history",
            "operation_id": operation["name"],
            "success": operation["success"],
            "started_at": operation["started_at"].timestamp(),
        }
        payload = base64.b64encode(json.dumps(data).encode()).decode()
        yield f'data: {payload}\n\n'

    if current_operation_id:
        try:
            log_stream_cache = open(f"{OPERATIONS_PATH}/.{current_operation_id}.logstreamcache")
        except Exception:
            pass
        else:
            os.system(f"cat {OPERATIONS_PATH}/.{current_operation_id}.logstreamcache")
            entries = [entry.strip() for entry in log_stream_cache.readlines()]
            for payload in entries:
                yield f'data: {payload}\n\n'
            log_stream_cache.close()

    # Init heartbeat
    last_heartbeat = 0

    try:
        while True:
            if time.time() - last_heartbeat > SSE_HEARTBEAT_PERIOD:
                data = {
                    "type": "heartbeat",
                    "current_operation": get_current_operation(),
                    "timestamp": time.time(),
                }
                payload = base64.b64encode(json.dumps(data).encode()).decode()
                yield f'data: {payload}\n\n'
                last_heartbeat = time.time()
            if sub.poll(10, zmq.POLLIN):
                _, msg = sub.recv_multipart()
                yield 'data: ' + str(msg.decode()) + '\n\n'
    finally:
        sub.close()
        ctx.term()
