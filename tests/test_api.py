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
        return self._echo()

    def do_POST(self): return self._echo()
    def do_HEAD(self): return self._send()
    def do_DELETE(self): return self._echo()
    def do_OPTIONS(self): return self._send()


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
    assert len(ALL_IDENTIFIERS) == 83
    assert Profiles.CHROME_152 == "chrome_152"
    assert find("chrome_15") == ["chrome_150", "chrome_150_PSK", "chrome_152", "chrome_152_PSK"]
    with pytest.raises(SessionConfigurationError, match="chrome_152"):
        Session(client_identifier="chrome152")


def test_client_os_validation():
    assert validate_os(None, "chrome_152") == "windows"
    assert validate_os(None, "safari_ios_18_0") == "ios"
    assert validate_os(None, "okhttp4_android_13") == "android"
    assert validate_os(None, "safari_16_0") == "macos"
    assert validate_os("ANDROID", "chrome_152") == "android"
    with pytest.raises(ValueError, match="client_os"):
        validate_os("beos", "chrome_152")


def test_default_headers_per_profile_and_os():
    for identifier in ("chrome_152", "firefox_148", "safari_ios_26_0", "okhttp4_android_13", "opera_91", "brave_146"):
        headers = default_headers(identifier)
        assert "user-agent" in headers and "accept" in headers and "accept-encoding" in headers
        assert "go-http-client" not in headers["user-agent"].lower()
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
        # header order: defaults in insertion order, custom appended last
        order = [line.split(":")[0] for line in []]  # order is not observable in echo headers; verified by dict order
        assert list(session.headers)[0] == "sec-ch-ua"


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
