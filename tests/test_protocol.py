"""Protocol selection (0.6.0): conflicting options fail before any network I/O, and an
explicit HTTP version is never silently downgraded. Fully offline."""
from __future__ import annotations

import os
import socket
import ssl
import struct
import tempfile
import threading
import time

import pytest

import yumeclient
from yumeclient import ProtocolError, Session, SessionConfigurationError

from test_okhttp import H1Server
from test_wire import _PEM

JA3 = "771,4865-4866-4867,0-10-11-13-16-43-45-51,29-23,0"


@pytest.fixture(scope="module")
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    return True


class H2Server:
    """Minimal HTTP/2 server: answers every request stream with 200 "ok"."""

    def __init__(self):
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self._pem)
        self.ctx.set_alpn_protocols(["h2"])
        self.connections = 0
        self.streams = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    @staticmethod
    def _frame(kind: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
        return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", stream) + payload

    @staticmethod
    def _read(s, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError
            buf += chunk
        return buf

    def _serve(self, c):
        try:
            with self.ctx.wrap_socket(c, server_side=True) as s:
                self.connections += 1
                self._read(s, 24)  # client preface
                s.sendall(self._frame(4, 0, 0))
                while True:
                    head = self._read(s, 9)
                    length = int.from_bytes(head[:3], "big")
                    kind, flags = head[3], head[4]
                    stream = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
                    self._read(s, length)
                    if kind == 4 and not flags & 1:
                        s.sendall(self._frame(4, 1, 0))  # SETTINGS ACK
                    elif kind == 1:  # HEADERS (END_HEADERS assumed: small requests)
                        self.streams += 1
                        s.sendall(self._frame(1, 4, stream, b"\x88")  # :status 200 (static index 8)
                                  + self._frame(0, 1, stream, b"ok"))
                    elif kind == 7:
                        return
        except (OSError, ConnectionError, ssl.SSLError):
            pass

    def close(self):
        self.sock.close()
        os.unlink(self._pem)


@pytest.fixture()
def h2(native):
    s = H2Server()
    yield s
    s.close()


@pytest.fixture()
def h1(native):
    s = H1Server()
    yield s
    s.close()


# ---------------------------------------------------------------------------
# configuration conflicts (pure python, no network)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs, match", [
    (dict(force_http1=True, http_version="2"), "force_http1=True conflicts with http_version='2'"),
    (dict(force_http1=True, http_version="3"), "force_http1=True conflicts with http_version='3'"),
    (dict(disable_http3=True, http_version="3"), "conflicts with disable_http3"),
    (dict(keep_alpn=True), "keep_alpn=True needs"),
    (dict(http_version="3", proxy="http://127.0.0.1:1"), "requires socks5"),
    (dict(ja3_string=JA3, alpn_protocols=["h2"], http_version="1.1"), "conflicts with forced HTTP/1.1"),
    (dict(ja3_string=JA3, alpn_protocols=["h2", "http/1.1"], force_http1=True), "conflicts with forced HTTP/1.1"),
    (dict(ja3_string=JA3, alpn_protocols=["h2"], http_version="1.1", keep_alpn=True), "cannot select http/1.1"),
    (dict(ja3_string=JA3, alpn_protocols=["http/1.1"], http_version="2"), "h2 is not offered"),
    (dict(ja3_string=JA3, alpn_protocols=[]), "non-empty list"),
    (dict(http_version="h4"), "invalid http_version"),
])
def test_conflicting_protocol_options_fail_at_construction(kwargs, match):
    with pytest.raises(SessionConfigurationError, match=match):
        Session(**kwargs)


@pytest.mark.parametrize("kwargs", [
    dict(http_version="1.1"), dict(force_http1=True), dict(http_version="2"), dict(http_version="3"),
    dict(http_version="auto", disable_http3=True),
    dict(ja3_string=JA3, alpn_protocols=["http/1.1"], http_version="1.1"),
    dict(ja3_string=JA3, alpn_protocols=["h2", "http/1.1"], http_version="1.1", keep_alpn=True),
    dict(ja3_string=JA3, alpn_protocols=["h2"], http_version="2"),
    dict(ja3_string=JA3, alpn_protocols=["h2", "http/1.1"]),
])
def test_consistent_protocol_options_are_accepted(kwargs):
    Session(**kwargs).close()


@pytest.mark.parametrize("cls", [Session, yumeclient.AsyncSession])
def test_transport_options_are_fixed_per_session(cls):
    s = cls()
    for name, value in [("http_version", "1.1"), ("force_http1", True), ("proxy", "http://127.0.0.1:1"),
                        ("timeout", 3), ("client_identifier", "chrome_133"), ("verify", False)]:
        with pytest.raises(AttributeError, match="fixed for the lifetime of a session"):
            setattr(s, name, value)
    s.headers = {"X-Ok": "1"}  # default headers stay assignable
    s.user_attribute = 1  # unrelated attributes too
    assert s.headers["x-ok"] == "1"
    s._core.close()


def test_core_reassignment_is_validated_before_any_io(h1):
    with Session(verify=False, timeout=5) as s:
        s._core.force_http1, s._core.http_version = True, "2"
        with pytest.raises(SessionConfigurationError, match="conflicts"):
            s.get(f"https://127.0.0.1:{h1.port}/x")
    time.sleep(0.1)
    assert h1.requests == [] and h1.connections == []


# ---------------------------------------------------------------------------
# no silent downgrade
# ---------------------------------------------------------------------------

def test_http2_never_falls_back_to_http1(h1):
    with Session(verify=False, timeout=5, http_version="2") as s:
        with pytest.raises(ProtocolError, match='negotiated ALPN "http/1.1" instead of "h2"') as info:
            s.get(f"https://127.0.0.1:{h1.port}/x")
        assert info.value.kind == "protocol" and info.value.stage == "connect" and not info.value.retryable
        assert isinstance(info.value, yumeclient.ConnectError)
    time.sleep(0.2)
    assert h1.connections == ["http/1.1"]  # the handshake happened ...
    assert h1.requests == []  # ... but the request was never written


def test_auto_follows_the_server(h1):
    with Session(verify=False, timeout=5) as s:
        r = s.get(f"https://127.0.0.1:{h1.port}/x")
    assert r.used_protocol == "HTTP/1.1" == r.connection_info["http_protocol"]
    assert r.connection_info["alpn_negotiated"] == "http/1.1"


def test_http2_works_and_is_reported_consistently(h2):
    with Session(verify=False, timeout=5, http_version="2") as s:
        first = s.get(f"https://127.0.0.1:{h2.port}/a")
        second = s.get(f"https://127.0.0.1:{h2.port}/b")
    for r in (first, second):
        assert r.status_code == 200 and r.content == b"ok"
        assert r.used_protocol == "HTTP/2.0" == r.connection_info["http_protocol"] and r.http_version == "2"
        assert r.connection_info["alpn_negotiated"] == "h2"
    assert first.connection_info["connection_reused"] is False
    assert second.connection_info["connection_reused"] is True
    assert h2.connections == 1 and h2.streams == 2


def test_http2_plain_http_stays_http1(native):
    # no ALPN on plain TCP and no h2c: http:// is HTTP/1.1 under every http_version
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with Session(timeout=5, http_version="2") as s:
            r = s.get(f"http://127.0.0.1:{srv.server_address[1]}/")
        assert r.status_code == 200 and r.used_protocol == "HTTP/1.1"
    finally:
        srv.shutdown(); srv.server_close()
