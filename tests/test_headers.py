"""Session header handling (0.6.0), offline."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import yumeclient
from yumeclient import Headers, Session

from test_okhttp import H1Server


@pytest.fixture(scope="module")
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    return True


@pytest.fixture()
def echo(native):
    seen: list[list[tuple[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            seen.append(list(self.headers.items()))
            self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.do_GET()
        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/", seen
    srv.shutdown(); srv.server_close()


def test_headers_mapping_ignores_case():
    h = Headers({"User-Agent": "a", "user-agent": "b", "Accept": "x"})
    assert list(h.items()) == [("User-Agent", "b"), ("Accept", "x")]  # first spelling, last value
    assert h["USER-AGENT"] == "b" and h.get("accept") == "x" and h.get("nope", 1) == 1
    assert "user-agent" in h and "nope" not in h and 1 not in h
    assert h.pop("user-agent") == "b" and h.pop("user-agent", None) is None
    with pytest.raises(KeyError):
        h.pop("user-agent")
    del h["ACCEPT"]
    assert dict(h) == {} and isinstance(h.copy(), Headers)


def _names(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers}


def test_removing_a_default_header_removes_it_from_the_wire(echo):
    url, seen = echo
    with Session(timeout=5) as s:
        assert "user-agent" in s.headers and "ACCEPT" in s.headers
        s.headers.pop("user-agent")
        del s.headers["accept"]
        s.get(url)
        s.get(url, headers={"user-agent": "mine"})
    first, second = (_names(h) for h in seen)
    # no application User-Agent must not turn into fhttp's "Go-http-client/1.1"
    assert "user-agent" not in first and "accept" not in first
    assert second["user-agent"] == "mine"


def test_okhttp_still_adds_its_user_agent_when_none_is_set(native):
    srv = H1Server()
    try:
        with Session(client_identifier="okhttp4_conscrypt", verify=False, timeout=5) as s:
            s.headers.pop("user-agent", None)
            s.get(f"https://127.0.0.1:{srv.port}/a")
        assert b"\r\nUser-Agent: okhttp/4.12.0\r\n" in srv.requests[0]
        assert b"Go-http-client" not in srv.requests[0]
    finally:
        srv.close()


def test_user_agent_spelled_differently_is_sent_once(echo):
    url, seen = echo
    with Session(timeout=5) as s:
        s.headers.pop("user-agent")
        s.get(url, headers={"USER-AGENT": "mine"})
    assert [(k, v) for k, v in seen[0] if k.lower() == "user-agent"] == [("USER-AGENT", "mine")]


def _wireUserAgents(response) -> list[str]:
    return [v for k, v in response.fingerprint["request_headers"] if k.lower() == "user-agent"]


@pytest.mark.filterwarnings("ignore:HTTP/2-only selection")
@pytest.mark.parametrize("identifier", ["chrome_133", "okhttp4_conscrypt"])
def test_no_go_user_agent_on_http2(native, identifier):
    from test_protocol import H2Server
    srv = H2Server()
    try:
        with Session(client_identifier=identifier, verify=False, timeout=5, http_version="2") as s:
            s.headers.pop("user-agent", None)
            bare = s.get(f"https://127.0.0.1:{srv.port}/a")
            mixed = s.get(f"https://127.0.0.1:{srv.port}/b", headers={"USER-AGENT": "mine"})
        assert bare.used_protocol == "HTTP/2.0" and bare.fingerprint.get("source", "wire") == "wire"
        # HTTP/2's encoder adds "Go-http-client/2.0" unless a User-Agent key carries an empty value
        assert _wireUserAgents(bare) == ([] if identifier == "chrome_133" else ["okhttp/4.12.0"])
        assert _wireUserAgents(mixed) == ["mine"]
    finally:
        srv.close()


def test_headers_or_operators_ignore_case():
    h = Headers({"User-Agent": "a"})
    h |= {"user-agent": "b", "Accept": "x"}
    assert list(h.items()) == [("User-Agent", "b"), ("Accept", "x")]
    merged = h | {"ACCEPT": "y"}
    assert isinstance(merged, Headers) and list(merged.items()) == [("User-Agent", "b"), ("Accept", "y")]
    assert list(({"accept": "z"} | h).items()) == [("accept", "x"), ("User-Agent", "b")]


def test_request_warnings_point_at_the_caller(echo):
    import asyncio
    url, _ = echo
    with Session(client_identifier="chrome_133", http_version="2", timeout=5) as s:
        with pytest.warns(UserWarning, match="HTTP/2-only") as caught:
            s.get(url)
    assert caught[0].filename == __file__

    async def run():
        async with yumeclient.AsyncSession(client_identifier="chrome_133", http_version="2", timeout=5) as s:
            with pytest.warns(UserWarning, match="HTTP/2-only") as caught:
                await s.get(url)
        return caught
    assert asyncio.run(run())[0].filename == __file__


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_no_go_user_agent_when_racing_http3(native):
    # http_version="3" races QUIC against TCP; both attempts share the request headers.
    # The local server has no HTTP/3, so the TCP attempt (HTTP/2) wins
    from test_protocol import H2Server
    srv = H2Server()
    try:
        with Session(client_identifier="chrome_133", verify=False, timeout=8, http_version="3") as s:
            s.headers.pop("user-agent")
            r = s.get(f"https://127.0.0.1:{srv.port}/a")
        assert r.used_protocol == "HTTP/2.0"
        assert _wireUserAgents(r) == []
    finally:
        srv.close()


def _wire(response) -> list[tuple[str, str]]:
    return [(name.lower(), value) for name, value in response.fingerprint["request_headers"]]


def test_chromium_priority_header_only_over_http2(native, echo):
    # Chrome 157 sends "priority: u=0, i" last on an HTTP/2 navigation and none on
    # HTTP/1.1 (tests/fixtures/chrome_157_wire.json)
    from test_protocol import H2Server
    srv = H2Server()
    try:
        with Session(client_identifier="chrome_152", verify=False, timeout=5) as s:
            h2 = s.get(f"https://127.0.0.1:{srv.port}/a")
            own = s.get(f"https://127.0.0.1:{srv.port}/a", headers={"Priority": "u=3"})
            h1 = s.get(echo[0])
        assert h2.used_protocol == "HTTP/2.0" and _wire(h2)[-1] == ("priority", "u=0, i")
        assert [v for k, v in _wire(own) if k == "priority"] == ["u=3"]
        assert "priority" not in _names(echo[1][-1]) and h1.status_code == 200
        with Session(client_identifier="firefox_147", verify=False, timeout=5) as s:
            assert "priority" not in dict(_wire(s.get(f"https://127.0.0.1:{srv.port}/a")))
    finally:
        srv.close()


def test_none_keeps_what_requests_keeps(native, echo):
    # requests: the body still sets Content-Type, the jar still sends cookies, Host is
    # always there, and a name that cannot be sent is just ignored
    url, seen = echo
    with Session(timeout=5, headers={"Content-Type": "application/json", "Cookie": "manual=1"}) as s:
        s.cookies.set("jar", "1")
        s.post(url, files={"f": ("a.txt", b"x")}, headers={"Content-Type": None})
        s.post(url, json={"a": 1}, headers={"Content-Type": None, "Cookie": None})
        s.get(url, headers={"Host": None, "Content-Length": None, "Bad Name": None})
        s.post(url, data=b"raw", headers={"Content-Type": None})  # our own default goes
    multipart, js, plain, raw = (_names(h) for h in seen[-4:])
    assert "content-type" not in raw and raw["content-length"] == "3"
    assert multipart["content-type"].startswith("multipart/form-data; boundary=")
    assert js["content-type"] == "application/json" and js["cookie"] == "jar=1"
    assert plain["host"].startswith("127.0.0.1:")


def test_none_removes_a_header(native, echo):
    # requests semantics: a None value removes the header (session default, profile
    # default, or one the transport adds when absent). It used to go out with an empty value
    from test_protocol import H2Server
    url, seen = echo
    srv = H2Server()
    try:
        with Session(client_identifier="chrome_152", verify=False, timeout=5, headers={"X-Session": "s"}) as s:
            s.get(url, headers={"X-Session": None, "user-agent": None, "X-Never": None, "Accept-Encoding": None})
            h2 = s.get(f"https://127.0.0.1:{srv.port}/a",
                       headers={"priority": None, "Accept-Language": None, "accept-encoding": None})
            again = s.get(url)
        with Session(client_identifier="okhttp4_android_13", timeout=5) as s:  # okhttp's own defaults too
            s.get(url, headers={"User-Agent": None, "Accept-Encoding": None, "Connection": None})
        sent = _names(seen[0])
        assert not {"x-session", "user-agent", "x-never", "accept-encoding"} & set(sent) and "accept" in sent
        assert h2.used_protocol == "HTTP/2.0"
        h2sent = {k for k, _ in _wire(h2)}
        assert not {"priority", "accept-language", "accept-encoding"} & h2sent and "user-agent" in h2sent
        assert _names(seen[1])["x-session"] == "s" and _names(seen[1])["user-agent"]  # per request only
        assert not {"user-agent", "accept-encoding", "connection"} & set(_names(seen[2])) and "host" in _names(seen[2])
    finally:
        srv.close()
