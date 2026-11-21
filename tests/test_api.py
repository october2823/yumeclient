"""Offline-capable test suite: local HTTP server for wire-accurate checks,
native DLL smoke tests when the shared library is present."""
from __future__ import annotations

import asyncio
import inspect
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import yumeclient
from yumeclient import (ALL_IDENTIFIERS, AsyncSession, CookieJar, Profiles, Response,
                        Session, SessionConfigurationError, encode_multipart, find)
from yumeclient.profiles import ALL_CLIENT_OS, default_headers, validate_os


# ---------------------------------------------------------------------------
# local test server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "YumeTest/1.0"

    def log_message(self, *args): pass

    def _send(self, code: int = 200, body: bytes = b"{}", content_type: str = "application/json", headers: list[tuple[str, str]] | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or []): self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)

    def _echo(self):
        body = json.dumps({"method": self.command, "path": self.path,
                           "headers": {k.lower(): v for k, v in self.headers.items()},
                           "cookies": self._cookies()}).encode()
        self._send(body=body)

    def _cookies(self) -> dict[str, str]:
        out: dict[str, str] = {}
        raw = self.headers.get("Cookie", "")
        for pair in raw.split(";"):
            name, sep, value = pair.strip().partition("=")
            if sep: out[name] = value
        return out

    def do_GET(self):
        if self.path == "/echo": return self._echo()
        if self.path == "/set-cookie":
            return self._send(headers=[("Set-Cookie", "sid=test123; Path=/"), ("Set-Cookie", "tracker=abc; Path=/; Secure")])
        if self.path == "/redirect-cookie":
            return self._send(302, headers=[("Location", "/final-cookie"), ("Set-Cookie", "hop=y; Path=/")])
        if self.path == "/final-cookie":
            return self._send(headers=[("Set-Cookie", "final=1; Path=/")])
        if self.path == "/chain":
            return self._send(302, headers=[("Location", "/chain2"), ("Set-Cookie", "c1=1; Path=/")])
        if self.path == "/chain2":
            return self._send(302, headers=[("Location", "/echo"), ("Set-Cookie", "c2=2; Path=/")])
        if self.path == "/gzip":
            import gzip as _gzip
            return self._send(body=_gzip.compress(b'{"packed": true}'), headers=[("Content-Encoding", "gzip")])
        if self.path == "/loop":
            return self._send(302, headers=[("Location", "/loop")])
        if self.path.startswith("/chain/"):  # /chain/<n>: n redirects, then 200
            n = int(self.path.rsplit("/", 1)[1])
            return self._send(302, headers=[("Location", f"/chain/{n - 1}")]) if n else self._send(200, b"end")
        if self.path.startswith("/set/"):
            return self._send(headers=[("Set-Cookie", f"{self.path[5:]}=1; Path=/")])
        return self._echo()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length: self.rfile.read(length)
        if self.path.startswith("/r/"):  # /r/<code>: redirect to /echo
            return self._send(int(self.path[3:]), headers=[("Location", "/echo")])
        return self._echo()
    def do_HEAD(self): return self._send()
    def do_DELETE(self): return self._echo()
    def do_OPTIONS(self): return self._send()


@pytest.fixture(scope="module")
def server():
    class Server(ThreadingHTTPServer):
        request_queue_size = 128  # parallel tests open many connections at once
    httpd = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture(scope="module")
def native():
    try:
        session = Session(timeout=10)
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    session.close()
    return True


# ---------------------------------------------------------------------------
# profiles / defaults (pure python)
# ---------------------------------------------------------------------------

def test_profiles_are_upstream_v116_profiles():
    # 83 upstream v1.16.0 profiles + 10 extras implemented in the native adapter
    assert len(ALL_IDENTIFIERS) == 93
    assert Profiles.CHROME_152 == "chrome_152"
    assert find("chrome_15") == ["chrome_150", "chrome_150_PSK", "chrome_152", "chrome_152_PSK"]
    assert find("edge") == ["edge_99", "edge_101", "edge_131", "edge_latest"]
    with pytest.raises(SessionConfigurationError, match="chrome_152"):
        Session(client_identifier="chrome152")


def test_extra_profiles_headers(native):
    edge = default_headers("edge_131")
    assert '"Microsoft Edge";v="131"' in edge["sec-ch-ua"]
    assert edge["user-agent"].endswith("Edg/131.0.0.0")
    tor = default_headers("tor_145")
    assert "rv:128.0" in tor["user-agent"]
    safari = default_headers("safari_macos_18_0")
    assert "Version/18.0" in safari["user-agent"]
    assert default_headers("safari_macos_18_0", None)["user-agent"] == default_headers("safari_macos_18_0")["user-agent"]


def test_client_os_validation():
    assert validate_os(None, "chrome_152") == "windows"
    assert validate_os(None, "safari_ios_18_0") == "ios"
    assert validate_os(None, "okhttp4_android_13") == "android"
    assert validate_os(None, "safari_16_0") == "macos"
    assert validate_os("ANDROID", "chrome_152") == "android"
    with pytest.raises(ValueError, match="client_os"):
        validate_os("beos", "chrome_152")


def test_default_headers_per_profile_and_os():
    for identifier in ("chrome_152", "firefox_148", "safari_ios_26_0", "opera_91", "brave_146"):
        headers = default_headers(identifier)
        assert "user-agent" in headers and "accept" in headers and "accept-encoding" in headers
        assert "go-http-client" not in headers["user-agent"].lower()
    # okhttp profiles: no application defaults (the okhttp bridge adds UA/Accept-Encoding
    # on the wire); header_style="raw" keeps the old baseline
    assert default_headers("okhttp4_android_13") == {}
    raw = default_headers("okhttp4_android_13", header_style="raw")
    assert raw == {"user-agent": "okhttp/4.12.0", "accept": "*/*", "accept-encoding": "gzip"}
    chrome_win = default_headers("chrome_152", "windows")
    chrome_android = default_headers("chrome_152", "android")
    assert chrome_win["sec-ch-ua-mobile"] == "?0" and chrome_android["sec-ch-ua-mobile"] == "?1"
    assert chrome_win["sec-ch-ua-platform"] == '"Windows"' and chrome_android["sec-ch-ua-platform"] == '"Android"'
    assert "iphone" in default_headers("chrome_152", "ios")["user-agent"].lower()


def test_session_starts_with_default_headers_not_empty(native):
    session = Session()
    assert session.headers["user-agent"].startswith("Mozilla/5.0")
    assert len(session.headers) >= 8
    # override merges over defaults
    custom = Session(headers={"Accept": "application/json"})
    assert custom.headers["accept"] == "application/json"
    assert "user-agent" in custom.headers


def test_header_order_follows_dict_insertion():
    session = Session(headers={"X-Custom": "1"})
    # insertion order of defaults + override is what hits the wire
    assert list(session.headers) == list(dict.fromkeys(list(default_headers(session.client_identifier)) + ["X-Custom"]))


# ---------------------------------------------------------------------------
# response conveniences
# ---------------------------------------------------------------------------

def test_response_conveniences():
    response = Response(200, {"content-type": ["application/json"]}, {}, b'{"ok":true}', "https://example.test", "HTTP/2.0")
    assert response.ok and response.json() == {"ok": True}
    assert response.http_version == "2"
    assert response["Content-Type"] == "application/json"
    assert "Response [200]" in repr(response)


def test_multipart_order_and_wire_format():
    body, content_type = encode_multipart([("key", "uploads/42"), ("policy", "abc")], [("file", ("blob", b"%PDF", "application/pdf"))], "----WebKitFormBoundary0123456789abcdef")
    assert content_type.endswith("0123456789abcdef")
    assert body.index(b'name="key"') < body.index(b'name="policy"') < body.index(b'name="file"')
    assert b"%PDF\r\n" in body and body.endswith(b"--\r\n")


def test_multipart_requests_compat():
    import io
    # tuple arities 2..4, bare file object, mimetype guessing, CR/LF/quote escaping
    body, _ = encode_multipart(
        [("k", "v"), ("multi", ["1", "2"])],
        [("f1", ("doc.pdf", b"%PDF")),                       # len 2 -> guessed type
         ("f2", ("r.txt", "text content")),                  # str content
         ("f3", ("w\"n.txt", b"x", None, {"X-Extra": "1"})),  # len 4 + escaping
         ("f4", io.BytesIO(b"stream"))],                     # bare readable
        "----WebKitFormBoundary0123456789abcdef")
    assert b'filename="doc.pdf"\r\nContent-Type: application/pdf' in body
    assert b'filename="r.txt"\r\nContent-Type: text/plain' in body
    assert b'name="multi"\r\n\r\n1' in body and b'name="multi"\r\n\r\n2' in body
    assert b'filename="w%22n.txt"' in body
    assert b"X-Extra: 1" in body
    assert b"Content-Type: application/octet-stream" in body  # BytesIO no-ext -> default
    with pytest.raises(ValueError, match="file spec"):
        encode_multipart(None, [("bad", ("a", b"b", "c", "d", "e"))])


def test_invalid_http3_proxy_rejected_before_native_call():
    from yumeclient import _validateTransport
    with pytest.raises(SessionConfigurationError, match="socks5"):
        _validateTransport(http_version="3", force_http1=False, disable_http3=False, proxy="http://localhost:8080", client_identifier="chrome_152")


# ---------------------------------------------------------------------------
# cookie jar (pure python)
# ---------------------------------------------------------------------------

def test_cookie_identity_and_domain_selection():
    jar = CookieJar()
    jar.set("token", "parent", domain=".example.com")
    jar.set("token", "host", domain="www.example.com")
    assert len(jar) == 2
    assert jar.to_dict(domain="www.example.com")["token"] == "host"
    assert jar.to_dict(domain="api.example.com")["token"] == "parent"
    jar.update({"token": "updated"}, domain=".example.com")
    assert len(jar) == 2
    assert jar.get("token") == "host"


# ---------------------------------------------------------------------------
# sync session over local server (native)
# ---------------------------------------------------------------------------

def test_sync_session_default_headers_on_wire(server, native):
    with Session() as session:
        r = session.get(f"{server}/echo")
        assert r.status_code == 200
        sent = r.json()["headers"]
        assert sent["user-agent"].startswith("Mozilla/5.0")
        assert "sec-ch-ua" in sent
        # defaults in Chrome's HTTP/1.1 order and spelling: Connection, then the client hints
        assert list(session.headers)[:2] == ["Connection", "sec-ch-ua"]


def test_sync_session_headers_update_and_replacement(server, native):
    with Session() as session:
        session.headers.update({"Accept": "application/json"})
        r = session.get(f"{server}/echo")
        assert r.json()["headers"]["accept"] == "application/json"
        session.headers = {"X-Only": "one"}
        r2 = session.get(f"{server}/echo")
        assert r2.json()["headers"].get("x-only") == "one"
        # profile defaults are gone; Go still injects its base UA (like requests does)
        assert "mozilla" not in r2.json()["headers"].get("user-agent", "").lower()


def test_cookie_roundtrip_and_updates(server, native):
    with Session() as session:
        session.get(f"{server}/set-cookie")
        jar = session.cookies.to_dict()
        assert jar["sid"] == "test123"
        assert jar["tracker"] == "abc"
        r = session.get(f"{server}/echo")
        assert r.json()["cookies"]["sid"] == "test123"
        # jar mutation propagates
        session.cookies.set("sid", "overwritten")
        r2 = session.get(f"{server}/echo")
        assert r2.json()["cookies"]["sid"] == "overwritten"


def test_cookie_update_on_redirect_hops(server, native):
    with Session() as session:
        r = session.get(f"{server}/redirect-cookie")
        assert r.status_code == 200
        jar = session.cookies.to_dict()
        # hop cookie (302 response) and final cookie both survive
        assert jar.get("hop") == "y"
        assert jar.get("final") == "1"
        r2 = session.get(f"{server}/echo")
        cookies = r2.json()["cookies"]
        assert cookies.get("hop") == "y" and cookies.get("final") == "1"


def test_cookie_chain_three_hops(server, native):
    with Session() as session:
        session.get(f"{server}/chain")
        jar = session.cookies.to_dict()
        assert jar.get("c1") == "1" and jar.get("c2") == "2"


def test_per_request_cookies_do_not_pollute_jar(server, native):
    with Session() as session:
        session.get(f"{server}/echo", cookies={"one_shot": "1"})
        assert "one_shot" not in session.cookies.to_dict()


def test_methods_and_shapes(server, native):
    with Session() as session:
        assert session.post(f"{server}/echo", json={"a": 1}).json()["headers"]["content-type"] == "application/json"
        assert session.post(f"{server}/echo", data={"f": "1"}).json()["headers"]["content-type"] == "application/x-www-form-urlencoded"
        assert session.head(f"{server}/echo").status_code == 200
        assert session.delete(f"{server}/echo").json()["method"] == "DELETE"
        assert session.options(f"{server}/echo").status_code == 200


def test_top_level_sync_api(server, native):
    r = yumeclient.get(f"{server}/echo", headers={"X-One": "1"})
    assert r.status_code == 200 and r.json()["headers"]["x-one"] == "1"


# ---------------------------------------------------------------------------
# async session (native)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_session_basic_and_cookies(server, native):
    async with AsyncSession() as session:
        r = await session.get(f"{server}/set-cookie")
        assert r.status_code == 200
        assert session.cookies.to_dict()["sid"] == "test123"
        r2 = await session.get(f"{server}/echo")
        assert r2.json()["cookies"]["sid"] == "test123"
        # parallel requests share the session safely
        rs = await asyncio.gather(*(session.get(f"{server}/echo") for _ in range(4)))
        assert all(x.status_code == 200 for x in rs)


@pytest.mark.asyncio
async def test_async_session_redirect_cookies(server, native):
    async with AsyncSession() as session:
        await session.get(f"{server}/chain")
        jar = session.cookies.to_dict()
        assert jar.get("c1") == "1" and jar.get("c2") == "2"


@pytest.mark.asyncio
async def test_closed_session_rejects_request(server, native):
    session = Session()
    session.close()
    with pytest.raises(SessionConfigurationError):
        session.get(f"{server}/echo")
    async_session = AsyncSession()
    await async_session.close()
    with pytest.raises(SessionConfigurationError):
        await async_session.get(f"{server}/echo")


@pytest.mark.asyncio
async def test_async_top_level_api(server, native):
    r = await yumeclient.aget(f"{server}/echo", headers={"X-Async": "1"})
    assert r.json()["headers"]["x-async"] == "1"


def test_sync_async_api_parity():
    for method in ("request", "get", "post", "put", "patch", "delete", "options", "close", "reset_connection"):
        assert callable(getattr(Session, method))
        assert inspect.iscoroutinefunction(getattr(AsyncSession, method))


def test_executor_api_exists():
    assert callable(AsyncSession.configure_executor)


# ---------------------------------------------------------------------------
# live smoke (network) — skipped by default, run with --run-online
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption("--run-online", action="store_true", default=False, help="run tests that hit httpbin.org")


@pytest.fixture(scope="module")
def online(request):
    if not request.config.getoption("--run-online"):
        pytest.skip("online test; pass --run-online")
    return True


def test_live_httpbin_default_headers(online):
    with Session(timeout=30) as session:
        r = session.get("https://httpbin.org/get")
        assert r.status_code == 200
        sent = r.json()["headers"]
        assert sent["User-Agent"].startswith("Mozilla/5.0")
        assert sent["Sec-Ch-Ua-Platform"] == '"Windows"'


def test_live_httpbin_cookie_flow(online):
    with Session(timeout=30) as session:
        session.get("https://httpbin.org/cookies/set/live/1")
        r = session.get("https://httpbin.org/cookies")
        assert r.json()["cookies"]["live"] == "1"


def test_cookie_jar_keeps_concurrent_updates():
    # parallel requests (threads, AsyncSession workers) merge cookies at the same time;
    # set() used to rebuild the list without a lock and dropped other threads' cookies
    import sys
    jar = yumeclient.CookieJar()
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-5)
    try:
        def work(t):
            for i in range(300): jar.set(f"c{t}_{i}", "v", domain="example.com")
        threads = [threading.Thread(target=work, args=(t,)) for t in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
    finally:
        sys.setswitchinterval(interval)
    assert len(jar) == 2400 and len({(c.name, c.domain, c.path) for c in jar}) == 2400


@pytest.mark.asyncio
async def test_async_gather_keeps_every_cookie(server, native):
    import sys
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-5)
    try:
        async with AsyncSession(timeout=10) as s:
            await asyncio.gather(*(s.get(f"{server}/set/k{i}") for i in range(64)))
            assert sorted(c.name for c in s.cookies) == sorted(f"k{i}" for i in range(64))
    finally:
        sys.setswitchinterval(interval)


@pytest.mark.parametrize("code, method", [(301, "GET"), (302, "GET"), (303, "GET"), (307, "POST"), (308, "POST")])
def test_redirect_request_headers_like_browsers(server, native, code, method):
    # a redirect that turns POST into GET drops the body headers and Origin (Chromium,
    # requests); no Referer is invented on redirect hops (Go set the redirecting URL)
    headers = {"Content-Type": "text/plain", "Content-Language": "en", "Origin": "https://a.example"}
    with Session(timeout=10) as s:
        r = s.post(f"{server}/r/{code}", data=b"payload", headers=headers)
        got = r.json()
        assert got["method"] == method and [h.status_code for h in r.history] == [code]
        kept = {k for k in ("content-type", "content-language", "origin") if k in got["headers"]}
        assert kept == (set() if method == "GET" else {"content-type", "content-language", "origin"})
        assert "referer" not in got["headers"]
        r = s.get(f"{server}/redirect-cookie", headers={"Referer": "https://ref.example/page"})
        assert s.get(f"{server}/chain").json()["headers"].get("referer") is None
        r = s.get(f"{server}/chain", headers={"Referer": "https://ref.example/page"})
        assert r.json()["headers"]["referer"] == "https://ref.example/page"


@pytest.mark.parametrize("code, method, sent, body", [
    (301, "POST", "GET", ""), (302, "POST", "GET", ""), (303, "POST", "GET", ""),
    (301, "PUT", "PUT", "payload"), (302, "PATCH", "PATCH", "payload"), (303, "PUT", "GET", ""),
    (307, "PUT", "PUT", "payload"), (308, "POST", "POST", "payload"),
])
def test_redirect_method_like_browsers(server, native, code, method, sent, body):
    # the Fetch standard: 301/302 change only POST to GET, 303 everything but GET/HEAD;
    # Go changed every method on 301/302 to GET and dropped the body
    class Redirect(Handler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            data = self.rfile.read(length) if length else b""
            if self.path == "/go":
                return self._send(code, headers=[("Location", "/to")])
            return self._send(body=json.dumps({"method": self.command, "body": data.decode()}).encode())
        do_PUT = do_PATCH = do_POST

        def do_GET(self):
            return self._send(body=json.dumps({"method": "GET", "body": ""}).encode())

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with Session(timeout=10) as s:
            r = s.request(method, f"http://127.0.0.1:{httpd.server_address[1]}/go", data=b"payload")
        assert r.json() == {"method": sent, "body": body} and [h.status_code for h in r.history] == [code]
    finally:
        httpd.shutdown()


def test_too_many_redirects(server, native):
    # 20 redirects are followed, the 21st is an error (Fetch, Chromium); Go stopped at the 10th
    with Session(timeout=10) as s:
        r = s.get(f"{server}/chain/20")
        assert r.content == b"end" and len(r.history) == 20
        with pytest.raises(yumeclient.TooManyRedirects) as info:
            s.get(f"{server}/chain/21")
        with pytest.raises(yumeclient.TooManyRedirects):
            s.get(f"{server}/loop")
    assert info.value.kind == "too_many_redirects" and not info.value.retryable


def test_response_headers_stay_as_sent(server, native):
    # the body is decoded, the headers are the server's (like requests and our HTTP/2);
    # HTTP/1.1 used to drop Content-Length of every response and Content-Encoding
    with Session(timeout=10) as s:
        r = s.get(f"{server}/echo")
        assert int(r["Content-Length"]) == len(r.content)
        r = s.get(f"{server}/gzip")
        assert r.json() == {"packed": True}
        assert r["Content-Encoding"] == "gzip" and int(r["Content-Length"]) > len(r.content) - 20


@pytest.mark.parametrize("proxy, message", [
    ("127.0.0.1:8080", "has no scheme"),
    ("ftp://127.0.0.1:21", "unsupported scheme 'ftp'"),
    ("socks5://127.0.0.1", "needs a port"),
    ("http://:8080", "no host"),
    ("http://127.0.0.1:99999", "invalid port"),
    ("http://user:secret@:8080", "no host"),
])
def test_bad_proxy_urls_fail_before_any_request(proxy, message):
    # before 0.8.1 they surfaced at the first request as "client creation failed: ..."
    with pytest.raises(yumeclient.SessionConfigurationError, match=message) as info:
        yumeclient.Session(proxy=proxy)
    assert "secret" not in str(info.value)
    with yumeclient.Session() as s, pytest.raises(yumeclient.SessionConfigurationError, match=message):
        s.get("http://127.0.0.1:1/", proxy=proxy)
    with pytest.raises(yumeclient.SessionConfigurationError, match=message.replace("proxy", "udp_proxy")):
        yumeclient.Session(udp_proxy=proxy.replace("ftp", "socks5").replace("http", "socks5")
                           if message != "unsupported scheme 'ftp'" else proxy)


def test_per_request_proxy_override_and_direct(server):
    from socks5udp import Socks5

    session_proxy, other = Socks5(), Socks5()
    try:
        with yumeclient.Session(proxy=session_proxy.url) as s:
            assert s.get(f"{server}/get").status_code == 200
            assert s.get(f"{server}/get", proxy=None).status_code == 200  # None: the session's proxy
            assert s.get(f"{server}/get", proxy=other.url).status_code == 200
            assert s.get(f"{server}/get", proxy="").status_code == 200  # "": direct
        # the test server closes every connection: one CONNECT per request
        assert len([e for e in session_proxy.log if e[0] == "connect"]) == 2
        assert len([e for e in other.log if e[0] == "connect"]) == 1
    finally:
        session_proxy.close(); other.close()


def test_plain_http_through_an_https_proxy_with_a_self_signed_certificate(server):
    """The TLS leg to an https:// proxy is not verified for http:// requests either;
    before 0.8.1 they failed with "certificate signed by unknown authority"."""
    import os
    import socket
    import ssl
    import tempfile
    from test_wire import _PEM

    fd, pem = tempfile.mkstemp(suffix=".pem")
    os.write(fd, _PEM.encode() if isinstance(_PEM, str) else _PEM)
    os.close(fd)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    seen = []

    def serve():
        conn, _ = listener.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls:
            head = b""
            while b"\r\n\r\n" not in head:
                head += tls.recv(4096)
            seen.append(head.split(b"\r\n", 1)[0].decode())
            host, port = server.removeprefix("http://").split(":")
            with socket.create_connection((host, int(port))) as up:
                up.sendall(head)
                while chunk := up.recv(65536):
                    tls.sendall(chunk)

    threading.Thread(target=serve, daemon=True).start()
    try:
        r = yumeclient.get(f"{server}/get", proxy=f"https://127.0.0.1:{listener.getsockname()[1]}", timeout=5)
        assert r.status_code == 200
        assert seen == [f"GET {server}/get HTTP/1.1"]
    finally:
        listener.close()
        os.unlink(pem)


@pytest.mark.parametrize("scheme,target", [("http", "https"), ("http", "http"), ("https", "https"),
                                           ("https", "http"), ("socks5", "https"), (None, "http")])
def test_local_address_binds_the_connection_to_every_proxy_kind(native, scheme, target):
    """local_address binds the connection to the proxy; before 0.8.2 it was ignored for
    https:// targets through an https:// proxy."""
    import os
    import socket
    import ssl
    import tempfile
    from test_wire import _PEM

    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.2", 0))
    except OSError:
        pytest.skip("127.0.0.2 is not a local address here (macOS)")
    ctx = None
    if scheme == "https":
        fd, pem = tempfile.mkstemp(suffix=".pem")
        os.write(fd, _PEM.encode() if isinstance(_PEM, str) else _PEM)
        os.close(fd)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pem)
        os.unlink(pem)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    peers = []

    def serve():
        conn, addr = listener.accept()
        peers.append(addr[0])
        try:
            if ctx is not None:
                conn = ctx.wrap_socket(conn, server_side=True)
            conn.recv(4096)
            # SOCKS5: no acceptable method; HTTP: a refusal
            conn.sendall(b"\x05\xff" if scheme == "socks5" else b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    port = listener.getsockname()[1]
    kwargs = {"proxy": f"{scheme}://127.0.0.1:{port}"} if scheme else {}
    url = f"{target}://example.test/" if scheme else f"http://127.0.0.1:{port}/"
    try:
        with Session(local_address="127.0.0.2:0", timeout=5, **kwargs) as s:
            try:
                s.get(url)
            except yumeclient.RequestError:
                pass
        assert peers == ["127.0.0.2"]
    finally:
        listener.close()


@pytest.mark.parametrize("url", ["ftp://example.com/x", "http:///x", "not a url", "//example.com/x",
                                 "http://example.com:99999/", "https://[::1/", "http://exa\nmple.com/"])
def test_invalid_urls_fail_before_sending(native, url):
    # these went to the native layer and came back as a retryable ConnectError
    with Session(timeout=5) as s:
        with pytest.raises(yumeclient.InvalidRequestError) as info:
            s.get(url)
    assert info.value.kind == "invalid_request" and info.value.stage == "request" and not info.value.retryable


@pytest.mark.parametrize("identifier", ["chrome_152", "safari_ios_18_5", "mesh_android", "okhttp4_android_13"])
def test_default_headers_are_always_headers(identifier):
    headers = yumeclient.default_headers(identifier)
    assert isinstance(headers, yumeclient.Headers)
    if headers:
        assert headers.get("USER-AGENT") == headers.get("user-agent") is not None
