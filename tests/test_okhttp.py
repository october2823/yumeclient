"""okhttp4 HTTP layer (0.4.7), fully offline.

The expected request bytes below are what real okhttp 4.12.0 (BridgeInterceptor +
Http1ExchangeCodec) put on the wire for the same calls against the same kind of
local server; yumeclient's header_style="okhttp" must reproduce them byte for byte.
"""
from __future__ import annotations

import os
import socket
import ssl
import tempfile
import threading
import time

import pytest

import yumeclient
from yumeclient import Session, SessionConfigurationError
from yumeclient.profiles import default_headers, resolve_header_style

from test_wire import _PEM, parse_hello

CRLF = b"\r\n"


class H1Server:
    """TLS server (configurable ALPN) that records every request exactly as received,
    plus a TCP relay that records the client's TLS record sizes."""

    def __init__(self, alpn=("http/1.1",), plain=False):
        self.plain = plain
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self._pem)
        self.ctx.set_alpn_protocols(list(alpn))
        self.requests: list[bytes] = []
        self.connections: list[str | None] = []
        self.hellos: list[bytes] = []
        self.records: list[list[tuple[int, int]]] = []  # per relayed connection: (type, length)
        self._lock = threading.Lock()
        self.tls_sock, self.relay_sock = self._listen(), self._listen()
        self.port = self.tls_sock.getsockname()[1]
        self.relay_port = self.relay_sock.getsockname()[1]
        threading.Thread(target=self._accept, args=(self.tls_sock, self._serve), daemon=True).start()
        threading.Thread(target=self._accept, args=(self.relay_sock, self._relay), daemon=True).start()

    @staticmethod
    def _listen():
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(32); return s

    @staticmethod
    def _accept(ls, fn):
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=fn, args=(c,), daemon=True).start()

    @staticmethod
    def _reply(line0: bytes) -> bytes:
        def resp(*lines, body=b""):
            return CRLF.join(l.encode() for l in lines) + CRLF + CRLF + body
        if b" /r302" in line0:
            return resp("HTTP/1.1 302 Found", "Location: /after", "Content-Length: 0")
        if line0.startswith(b"HEAD"):
            return resp("HTTP/1.1 200 OK", "Content-Length: 2")
        return resp("HTTP/1.1 200 OK", "Content-Length: 2", "Set-Cookie: sid=abc; Path=/", body=b"{}")

    def _serve(self, c):
        try:
            s = c if self.plain else self.ctx.wrap_socket(c, server_side=True)
            with self._lock:
                self.connections.append(None if self.plain else s.selected_alpn_protocol())
            buf = b""
            while True:
                d = s.recv(65536)
                if not d:
                    return
                buf += d
                while CRLF + CRLF in buf:
                    head, rest = buf.split(CRLF + CRLF, 1)
                    cl = 0
                    for line in head.split(CRLF)[1:]:
                        k, _, v = line.partition(b":")
                        if k.strip().lower() == b"content-length":
                            cl = int(v.strip())
                    if len(rest) < cl:
                        break
                    body, buf = rest[:cl], rest[cl:]
                    with self._lock:
                        self.requests.append(head + CRLF + CRLF + body)
                    s.sendall(self._reply(head.split(CRLF, 1)[0]))
        except Exception:
            pass
        finally:
            c.close()

    def _relay(self, c):
        u = socket.create_connection(self.tls_sock.getsockname())
        recs: list[tuple[int, int]] = []
        with self._lock:
            self.records.append(recs)

        def up():
            buf = b""
            try:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    u.sendall(d)
                    buf += d
                    while len(buf) >= 5 and len(buf) >= 5 + int.from_bytes(buf[3:5], "big"):
                        n = int.from_bytes(buf[3:5], "big")
                        if not recs:
                            with self._lock:
                                self.hellos.append(bytes(buf[:5 + n]))
                        recs.append((buf[0], n))
                        buf = buf[5 + n:]
            except Exception:
                pass
            finally:
                try: u.shutdown(socket.SHUT_WR)
                except Exception: pass

        def down():
            try:
                while True:
                    d = u.recv(65536)
                    if not d:
                        break
                    c.sendall(d)
            except Exception:
                pass
            finally:
                c.close()

        threading.Thread(target=up, daemon=True).start()
        threading.Thread(target=down, daemon=True).start()

    def clear(self):
        with self._lock:
            self.requests.clear(); self.connections.clear(); self.hellos.clear(); self.records.clear()

    def close(self):
        for s in (self.tls_sock, self.relay_sock):
            s.close()
        os.unlink(self._pem)


@pytest.fixture(scope="module")
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    return True


@pytest.fixture()
def h1(native):
    s = H1Server()
    yield s
    s.close()


@pytest.fixture()
def h2only(native):
    s = H1Server(alpn=("h2",))
    yield s
    s.close()


def _okhttp(**kw):
    return Session(client_identifier="okhttp4_conscrypt", verify=False, timeout=10, **kw)


def _req(*lines: str, body: bytes = b"") -> bytes:
    return CRLF.join(l.encode() for l in lines) + CRLF + CRLF + body


# ---------------------------------------------------------------------------
# configuration (pure python)
# ---------------------------------------------------------------------------

def test_header_style_resolution():
    for ident in ("okhttp4_conscrypt", "conscrypt_android_latest", "okhttp4_android_7", "okhttp4_android_13"):
        assert resolve_header_style(ident) == "okhttp"
        assert default_headers(ident) == {}  # okhttp has no application default headers
        assert default_headers(ident, header_style="raw")["user-agent"] == "okhttp/4.12.0"
    for ident in ("chrome_152", "safari_ios_26_0", "firefox_147", "zalando_android_mobile"):
        assert resolve_header_style(ident) == "raw"
    assert resolve_header_style("chrome_152", "okhttp") == "okhttp"
    with pytest.raises(ValueError, match="header_style"):
        resolve_header_style("chrome_152", "curl")


def test_session_header_style_and_keep_alpn_validation():
    assert Session(client_identifier="okhttp4_conscrypt").header_style == "okhttp"
    assert Session(client_identifier="okhttp4_conscrypt").headers == {}
    assert Session(client_identifier="okhttp4_conscrypt", header_style="raw").headers["accept"] == "*/*"
    assert Session(client_identifier="chrome_152").header_style == "raw"
    assert Session(ja3_string="771,4865,0-10,29,0").header_style == "raw"
    with pytest.raises(SessionConfigurationError, match="header_style"):
        Session(header_style="curl")
    with pytest.raises(SessionConfigurationError, match="keep_alpn"):
        Session(client_identifier="okhttp4_conscrypt", keep_alpn=True)  # needs forced HTTP/1.1
    with pytest.raises(SessionConfigurationError, match="udp_proxy"):
        Session(client_identifier="okhttp4_conscrypt", http_version="1.1", keep_alpn=True, udp_proxy="socks5://127.0.0.1:1")
    Session(client_identifier="okhttp4_conscrypt", http_version="1.1", keep_alpn=True).close()
    Session(client_identifier="okhttp4_conscrypt", force_http1=True, keep_alpn=True).close()


# ---------------------------------------------------------------------------
# wire bytes = okhttp 4.12.0
# ---------------------------------------------------------------------------

def test_okhttp_request_bytes_match_real_okhttp(h1):
    host = f"localhost:{h1.port}"
    u = f"https://{host}"
    s = _okhttp()
    try:
        s.get(u + "/a?x=1")
        s.post(u + "/b", data=b'{"k":"v"}', headers={"x-app": "1", "user-agent": "MyApp/2.0 (Android 14)",
                                                     "Content-Type": "application/json"})
        s.post(u + "/r302", data=b"z=1", headers={"Content-Type": "application/x-www-form-urlencoded"})
        s.head(u + "/d")
        s.get(u + "/e", headers={"Range": "bytes=0-1"})
        s.put(u + "/f", data=b"")
        s.get(u + "/g", headers={"Accept-Encoding": "identity", "Host": "api.example.test",
                                 "X-Requested-With": "com.example.app"})
        s.get(u + "/h", headers={"content-type": "text/plain"})
    finally:
        s.close()
    ck = "Cookie: sid=abc"
    expected = [
        _req("GET /a?x=1 HTTP/1.1", f"Host: {host}", "Connection: Keep-Alive", "Accept-Encoding: gzip",
             "User-Agent: okhttp/4.12.0"),
        # application headers first, as given (lowercase stays lowercase), no okhttp UA when the app set one
        _req("POST /b HTTP/1.1", "x-app: 1", "user-agent: MyApp/2.0 (Android 14)", "Content-Type: application/json",
             "Content-Length: 9", f"Host: {host}", "Connection: Keep-Alive", "Accept-Encoding: gzip", ck,
             body=b'{"k":"v"}'),
        _req("POST /r302 HTTP/1.1", "Content-Type: application/x-www-form-urlencoded", "Content-Length: 3",
             f"Host: {host}", "Connection: Keep-Alive", "Accept-Encoding: gzip", ck, "User-Agent: okhttp/4.12.0",
             body=b"z=1"),
        # 302 follow-up: GET without body headers and without Referer (fhttp would add one)
        _req("GET /after HTTP/1.1", f"Host: {host}", "Connection: Keep-Alive", "Accept-Encoding: gzip", ck,
             "User-Agent: okhttp/4.12.0"),
        _req("HEAD /d HTTP/1.1", f"Host: {host}", "Connection: Keep-Alive", "Accept-Encoding: gzip", ck,
             "User-Agent: okhttp/4.12.0"),
        # Range: no transparent gzip
        _req("GET /e HTTP/1.1", "Range: bytes=0-1", f"Host: {host}", "Connection: Keep-Alive", ck,
             "User-Agent: okhttp/4.12.0"),
        # empty PUT body: Content-Length: 0, no implicit Content-Type
        _req("PUT /f HTTP/1.1", "Content-Length: 0", f"Host: {host}", "Connection: Keep-Alive",
             "Accept-Encoding: gzip", ck, "User-Agent: okhttp/4.12.0"),
        # application-set Accept-Encoding / Host stay where the application put them
        _req("GET /g HTTP/1.1", "Accept-Encoding: identity", "Host: api.example.test",
             "X-Requested-With: com.example.app", "Connection: Keep-Alive", ck, "User-Agent: okhttp/4.12.0"),
        # Content-Type on a body-less GET is an ordinary application header
        _req("GET /h HTTP/1.1", "content-type: text/plain", f"Host: {host}", "Connection: Keep-Alive",
             "Accept-Encoding: gzip", ck, "User-Agent: okhttp/4.12.0"),
    ]
    assert h1.requests == expected
    assert h1.connections == ["http/1.1"]  # okhttp keep-alive: every call on one connection


def test_cookie_slot_and_jar(h1):
    u = f"https://localhost:{h1.port}"
    s = _okhttp()
    try:
        s.get(u + "/set")                                  # Set-Cookie: sid=abc
        s.get(u + "/c", cookies={"pc": "1"}, headers={"x-a": "1"})
    finally:
        s.close()
    lines = h1.requests[-1].split(CRLF)
    names = [l.split(b":", 1)[0] for l in lines[1:] if l]
    assert names == [b"x-a", b"Host", b"Connection", b"Accept-Encoding", b"Cookie", b"User-Agent"]
    cookie = next(l for l in lines if l.startswith(b"Cookie: "))
    assert sorted(cookie[8:].split(b"; ")) == [b"pc=1", b"sid=abc"]


def test_fingerprint_reports_connection_and_wire_headers(h1):
    u = f"https://localhost:{h1.port}"
    s = _okhttp()
    try:
        first = s.get(u + "/1").fingerprint
        second = s.post(u + "/2", json={"a": 1}, headers={"x-app": "1"}).fingerprint
    finally:
        s.close()
    assert first["alpn_offered"] == ["h2", "http/1.1"] and first["alpn_negotiated"] == "http/1.1"
    assert first["http_protocol"] == "HTTP/1.1" and first["tls_version"] == "1.3"
    assert first["connection_reused"] is False and second["connection_reused"] is True
    wire = h1.requests[-1].split(CRLF + CRLF)[0].split(CRLF)[1:]
    assert [f"{k}: {v}".encode() for k, v in second["request_headers"]] == wire


# ---------------------------------------------------------------------------
# ALPN control
# ---------------------------------------------------------------------------

def test_auto_follows_server_alpn_with_full_offer(h1):
    # okhttp semantics: offer h2,http/1.1; the server picked http/1.1 -> HTTP/1.1
    s = _okhttp()
    try:
        r = s.get(f"https://localhost:{h1.relay_port}/x")
    finally:
        s.close()
    hello = parse_hello(h1.hellos[-1])
    assert hello["alpn"] == "h2" and hello["ja4"].startswith("t13d1513h2_")
    assert r.http_version == "1.1" and r.fingerprint["alpn_negotiated"] == "http/1.1"


def test_keep_alpn_keeps_the_hello_and_speaks_http1(h1):
    s = _okhttp(http_version="1.1", keep_alpn=True)
    try:
        r = s.get(f"https://localhost:{h1.relay_port}/x")
        r2 = s.get(f"https://localhost:{h1.relay_port}/y")
    finally:
        s.close()
    hello = parse_hello(h1.hellos[0])
    assert hello["alpn"] == "h2" and hello["ja4"] == "t13d1513h2_8daaf6152771_eca864cca44a"
    assert r.fingerprint["ja4"] == hello["ja4"] and r.fingerprint["alpn_offered"] == ["h2", "http/1.1"]
    assert r.http_version == "1.1" and r.fingerprint["alpn_negotiated"] == "http/1.1"
    assert r2.fingerprint["connection_reused"] is True and len(h1.hellos) == 1
    assert h1.requests[0].startswith(b"GET /x HTTP/1.1\r\nHost: ")


def test_keep_alpn_refuses_h2_before_sending_anything(h2only):
    s = _okhttp(http_version="1.1", keep_alpn=True)
    try:
        with pytest.raises(yumeclient.RequestError, match='selected ALPN "h2"'):
            s.get(f"https://localhost:{h2only.relay_port}/x")
    finally:
        s.close()
    time.sleep(0.2)
    assert h2only.connections == ["h2"] and h2only.requests == []
    assert parse_hello(h2only.hellos[0])["alpn"] == "h2"


def test_force_http1_without_keep_alpn_rewrites_the_offer(h1):
    s = _okhttp(http_version="1.1")
    try:
        r = s.get(f"https://localhost:{h1.relay_port}/x")
    finally:
        s.close()
    assert parse_hello(h1.hellos[0])["alpn"] == "http/1.1"
    assert r.fingerprint["ja4"].startswith("t13d1513h1_") and r.fingerprint["alpn_offered"] == ["http/1.1"]


# ---------------------------------------------------------------------------
# TLS record framing after the handshake
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kw", [{}, {"http_version": "1.1", "keep_alpn": True}])
def test_request_leaves_in_one_record(h1, kw):
    # Conscrypt/okhttp: head + body flushed once, records up to 16 KiB. Before 0.4.7 a
    # 3000-byte POST left as head (179) + 2389 + 645 (fhttp head flush + Go dynamic sizing)
    s = _okhttp(**kw)
    try:
        s.post(f"https://localhost:{h1.relay_port}/big", data=b"x" * 3000, headers={"Content-Type": "application/json"})
    finally:
        s.close()
    time.sleep(0.2)
    app = [n for t, n in h1.records[0][1:] if t == 23]  # [Finished, request, (close_notify)]
    assert len(h1.requests) == 1
    assert app[1] == len(h1.requests[0]) + 17  # one record: plaintext + content type + AEAD tag


def test_raw_style_is_unchanged(h1):
    s = _okhttp(header_style="raw")
    try:
        s.get(f"https://localhost:{h1.port}/a")
    finally:
        s.close()
    head = h1.requests[0].split(CRLF)
    assert head[1:4] == [b"user-agent: okhttp/4.12.0", b"accept: */*", b"accept-encoding: gzip"]
    assert not any(l.startswith(b"Connection:") for l in head)


def test_plain_http_gets_the_okhttp_layer_and_keep_alive(native):
    srv = H1Server(plain=True)
    host = f"127.0.0.1:{srv.port}"
    s = _okhttp()
    try:
        s.get(f"http://{host}/a", headers={"x-app": "1"})
        s.get(f"http://{host}/b")
    finally:
        s.close(); srv.close()
    assert srv.requests[0] == _req("GET /a HTTP/1.1", "x-app: 1", f"Host: {host}", "Connection: Keep-Alive",
                                   "Accept-Encoding: gzip", "User-Agent: okhttp/4.12.0")
    assert srv.requests[1].startswith(b"GET /b HTTP/1.1\r\nHost: ")
    assert len(srv.connections) == 1  # second call reused the connection


def test_conscrypt_profile_h2_settings_are_okhttps(h1):
    s = _okhttp()
    try:
        fp = s.get(f"https://localhost:{h1.port}/a").fingerprint
    finally:
        s.close()
    # okhttp Http2Connection: SETTINGS 4=16 MiB, WINDOW_UPDATE 16 MiB-65535, m,p,a,s
    assert fp["akamai_fingerprint"] == "4:16777216|16711681|0|m,p,a,s"
