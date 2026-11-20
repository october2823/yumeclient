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
