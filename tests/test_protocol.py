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
import warnings

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
    """Minimal HTTP/2 server: answers every request stream with 200 "ok".
    ``frames`` records what clients sent: (type, flags, stream, payload)."""

    def __init__(self, port: int = 0, tls: bool = True):
        self.tls = tls  # False: HTTP/2 over cleartext with prior knowledge (h2c)
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self._pem)
        self.ctx.set_alpn_protocols(["h2"])
        self.connections = 0
        self.disconnected = 0  # connections the client closed (or that ended)
        self.streams = 0
        self.frames: list[tuple[int, int, int, bytes]] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", port))
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
            with (self.ctx.wrap_socket(c, server_side=True) if self.tls else c) as s:
                self.connections += 1
                self.preface = self._read(s, 24)  # client preface
                s.sendall(self._frame(4, 0, 0))
                while True:
                    head = self._read(s, 9)
                    length = int.from_bytes(head[:3], "big")
                    kind, flags = head[3], head[4]
                    stream = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
                    payload = self._read(s, length)
                    self.frames.append((kind, flags, stream, payload))
                    if kind == 4 and not flags & 1:
                        s.sendall(self._frame(4, 1, 0))  # SETTINGS ACK
                    elif kind == 1:  # HEADERS (END_HEADERS assumed: small requests)
                        self.streams += 1
                        self._respond(s, stream)
                    elif kind == 7:
                        return
        except (OSError, ConnectionError, ssl.SSLError):
            pass
        finally:
            self.disconnected += 1

    def _respond(self, s, stream: int) -> None:
        s.sendall(self._frame(1, 4, stream, b"\x88")  # :status 200 (static index 8)
                  + self._frame(0, 1, stream, b"ok"))

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
    # the handshake happened (the error names the negotiated ALPN) but the request was
    # never written; the server may miss the handshake end itself (the client closes
    # right away: a reset on Windows), so its connection list is not asserted exactly
    time.sleep(0.2)
    assert h1.connections in ([], ["http/1.1"])
    assert h1.requests == []


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


def test_closed_session_closes_its_http2_connections(h2):
    # session close never reached the tls-client transports: every closed session left
    # an open HTTP/2 connection (and a goroutine) until the server hung up
    before = yumeclient._debugStats()["goroutines"]
    for _ in range(5):
        with Session(verify=False, timeout=5, http_version="2") as s:
            assert s.get(f"https://127.0.0.1:{h2.port}/").status_code == 200
    deadline = time.monotonic() + 3
    while h2.disconnected < 5 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert h2.connections == 5 and h2.disconnected == 5
    assert yumeclient._debugStats()["goroutines"] <= before + 1


def test_plain_http_is_http1_unless_http2_is_required(native):
    # no ALPN on plain TCP: http:// is HTTP/1.1 under "auto", "1.1" and "3"
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
        for version in ("auto", "1.1", "3"):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with Session(timeout=5, http_version=version) as s:
                    r = s.get(f"http://127.0.0.1:{srv.server_address[1]}/")
            assert r.status_code == 200 and r.used_protocol == "HTTP/1.1", version
        # http_version="2" speaks h2c, which an HTTP/1.1 server refuses: an error, not HTTP/1.1
        with Session(timeout=5, http_version="2") as s:
            with pytest.raises(yumeclient.ProtocolError, match="cleartext"):
                s.get(f"http://127.0.0.1:{srv.server_address[1]}/")
    finally:
        srv.shutdown(); srv.server_close()


@pytest.mark.parametrize("identifier", ["chrome_133", "firefox_147", "okhttp4_android_13"])
def test_http2_prior_knowledge_on_plain_http(native, identifier):
    # http_version="2" on http:// was HTTP/1.1; now HTTP/2 with prior knowledge (h2c),
    # the profile's SETTINGS in the connection preface
    srv = H2Server(tls=False)
    try:
        with Session(client_identifier=identifier, timeout=5, http_version="2") as s:
            r = s.get(f"http://127.0.0.1:{srv.port}/a")
            r2 = s.get(f"http://127.0.0.1:{srv.port}/b")
        assert r.status_code == r2.status_code == 200
        assert r.used_protocol == "HTTP/2.0" and srv.connections == 1
        assert srv.preface == b"PRI * HTTP/2.0" + bytes([13, 10, 13, 10]) + b"SM" + bytes([13, 10, 13, 10])
        settings = next(p for kind, flags, _, p in srv.frames if kind == 4 and not flags & 1)
        sent = [(int.from_bytes(settings[i:i + 2], "big"), int.from_bytes(settings[i + 2:i + 6], "big"))
                for i in range(0, len(settings), 6)]
        with Session(client_identifier=identifier, verify=False, timeout=5, http_version="2") as s:
            tls_srv = H2Server()
            try:
                s.get(f"https://127.0.0.1:{tls_srv.port}/a")
            finally:
                tls_srv.close()
        tls_settings = next(p for kind, flags, _, p in tls_srv.frames if kind == 4 and not flags & 1)
        assert settings == tls_settings, sent  # same fingerprint as over TLS
    finally:
        srv.close()


def test_redirect_from_http_to_https_keeps_the_profile(native):
    # http:// requests ran on a separate client whose redirects to https:// went
    # through Go's default TLS stack: Go's ClientHello, verify=False ignored
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from test_wire import Sniffer, parse_hello
    sniffer = Sniffer()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(302); self.send_header("Location", f"https://127.0.0.1:{sniffer.port}/x")
            self.send_header("Content-Length", "0"); self.end_headers()
        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with Session(client_identifier="chrome_133", verify=False, timeout=5) as s:
            r = s.get(f"http://127.0.0.1:{srv.server_address[1]}/")
            s.get(f"https://127.0.0.1:{sniffer.port}/direct")
        assert r.status_code == 200 and [h.status_code for h in r.history] == [302]
        hellos = [parse_hello(h) for h in sniffer.hellos]
        assert len({h["ja4"] for h in hellos}) == 1, [h["ja4"] for h in hellos]
    finally:
        srv.shutdown(); srv.server_close()


def test_header_http2_refuses_is_an_invalid_request(native):
    # Connection/Upgrade/Transfer-Encoding are valid over HTTP/1.1 but not over
    # HTTP/2: refused before sending, the session keeps its connection
    srv = H2Server()
    try:
        with Session(verify=False, timeout=5) as s:
            url = f"https://localhost:{srv.port}/"
            assert s.get(url).used_protocol == "HTTP/2.0"
            with pytest.raises(yumeclient.InvalidRequestError) as info:
                s.get(url, headers={"Connection": "Upgrade", "Upgrade": "websocket"})
            assert info.value.kind == "invalid_request" and "Upgrade" in str(info.value)
            r = s.get(url)
        assert r.connection_info["connection_reused"]
        assert srv.connections == 1 and srv.streams == 2
    finally:
        srv.close()


@pytest.mark.parametrize("scheme,first", [("socks5h", 5), ("socks4", 4), ("socks5", 5)])
def test_plain_http_goes_through_socks_proxies(native, scheme, first):
    # http:// requests through socks5h:// or socks4:// went to the proxy as plaintext
    # HTTP-proxy requests ("GET http://..."): only socks5:// was known to that transport
    seen = []
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(4)

    def serve():
        try:
            c, _ = ls.accept()
            seen.append(c.recv(64))
            c.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        with Session(timeout=5, proxy=f"{scheme}://127.0.0.1:{ls.getsockname()[1]}") as s:
            with pytest.raises(yumeclient.RequestError):
                s.get("http://127.0.0.1:9/plain")
    finally:
        ls.close()
    assert seen and seen[0][0] == first, seen
