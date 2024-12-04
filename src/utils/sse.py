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

        # FIXME ? ... Boring hack because otherwise it seems we lose messages emitted while
        # the socket ain't properly connected to the other side
        time.sleep(1)

    def emit(self, record):
        self._encode_and_pub({
            "type": "msg",
            "timestamp": record.created,
            "level": record.levelname,
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
        self.socket.send_multipart([b'', payload])

    def close(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.socket.close()
        self.context.term()


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

    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.subscribe('')
    sub.connect(LOG_BROKER_FRONTEND_ENDPOINT)

    # Set client-side auto-reconnect timeout, ms.
    yield 'retry: 100\n\n'

    last_heartbeat = 0

    try:
        while True:
            if time.time() - last_heartbeat > SSE_HEARTBEAT_PERIOD:
                data = {
                    "type": "heartbeat",
                    "current_operation": get_current_operation(),
                    "timestamp": time.time(),
                }
                yield 'data: ' + base64.b64encode(json.dumps(data).encode()).decode() + '\n\n'
                last_heartbeat = time.time()
            if sub.poll(10, zmq.POLLIN):
                _, msg = sub.recv_multipart()
                yield 'data: ' + str(msg.decode()) + '\n\n'
    finally:
        sub.close()
        ctx.term()
