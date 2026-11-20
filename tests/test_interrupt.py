"""Ctrl+C during a blocking sync request (0.6.0). Runs in a subprocess: the interrupt is
delivered to the main thread exactly as SIGINT would be (``_thread.interrupt_main``)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCRIPT = textwrap.dedent(r"""
    import _thread, json, select, socket, sys, threading, time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    sys.path.insert(0, sys.argv[1])
    import yumeclient

    disconnected = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path == "/fast":
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
                self.wfile.write(b"ok"); return
            if self.path == "/slow-headers":
                time.sleep(3)
                self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Length", "1000000"); self.end_headers()
            try:
                for _ in range(30):
                    self.wfile.write(b"x" * 1000); self.wfile.flush(); time.sleep(0.1)
                    # the client closing its end shows up as EOF on our read side
                    if select.select([self.connection], [], [], 0)[0] and not self.connection.recv(1, socket.MSG_PEEK):
                        disconnected.append(self.path); return
            except OSError:
                disconnected.append(self.path)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def interrupted(fn):
        threading.Timer(0.3, _thread.interrupt_main).start()
        start = time.perf_counter()
        try:
            fn()
        except KeyboardInterrupt:
            return round(time.perf_counter() - start, 3)
        return None

    out = {}
    with yumeclient.Session(timeout=10) as s:
        out["request"] = interrupted(lambda: s.get(base + "/slow-headers"))
        out["after_request"] = s.get(base + "/fast").text
        r = s.get(base + "/slow-body", stream=True)
        out["stream"] = interrupted(lambda: [None for _ in r.iter_bytes(4096)])
        out["stream_closed"] = r._stream is None or r._stream.closed
        r = s.get(base + "/slow-body", stream=True)
        out["read"] = interrupted(r.read)
        out["after_stream"] = s.get(base + "/fast").text
    time.sleep(0.3)
    out["disconnected"] = sorted(disconnected)
    print(json.dumps(out))
""")


def test_ctrl_c_interrupts_blocking_sync_calls():
    try:
        import yumeclient
        yumeclient.Session(timeout=5).close()
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"native library unavailable: {exc}")
    proc = subprocess.run([sys.executable, "-c", SCRIPT, ROOT], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    # the interrupt fires at 0.3 s; before 0.6.0 it surfaced only when the response arrived (3 s)
    for key in ("request", "stream", "read"):
        assert out[key] is not None and out[key] < 2.0, out  # server answers after 3 s; slow CI runners need headroom
    assert out["after_request"] == "ok" and out["after_stream"] == "ok"
    assert out["stream_closed"]
    assert out["disconnected"] == ["/slow-body", "/slow-body"], out  # the connections were closed


ATEXIT = textwrap.dedent(r"""
    import atexit, sys, threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    sys.path.insert(0, sys.argv[1])
    import yumeclient

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    session = yumeclient.Session(timeout=5)
    print("main", session.get(url).text, flush=True)
    # concurrent.futures refuses new work once interpreter shutdown began (before atexit)
    atexit.register(lambda: print("atexit", session.get(url).text, flush=True))
""")


def test_sync_request_from_atexit_handler():
    proc = subprocess.run([sys.executable, "-c", ATEXIT, ROOT], capture_output=True, text=True, timeout=60)
    assert proc.stdout.split() == ["main", "ok", "atexit", "ok"], proc.stdout + proc.stderr
