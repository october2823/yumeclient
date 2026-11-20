"""Profiles export/import, fingerprint_diff, redacted traces, connection_info details (0.6.0).
Fully offline."""
from __future__ import annotations

import hashlib
import json
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time
from pathlib import Path

import pytest

import yumeclient
from yumeclient import AsyncSession, Session, SessionConfigurationError, fingerprint_diff
from yumeclient.diagnostics import PROFILE_FORMAT

from test_okhttp import H1Server

JA3 = "771,4865-4866-4867,0-10-11-13-16-43-45-51,29-23,0"


@pytest.fixture(scope="module")
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    return True


@pytest.fixture()
def tls_server(native):
    s = H1Server()
    yield s
    s.close()


class ConnectProxy:
    """CONNECT-only forward proxy; ``delay`` before the tunnel is established."""

    def __init__(self, delay: float = 0.0):
        self.delay, self.seen = delay, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = c.recv(4096)
            if not chunk:
                c.close(); return
            head += chunk
        line = head.split(b"\r\n", 1)[0].decode()
        self.seen.append(line)
        host, port = line.split()[1].rsplit(":", 1)
        time.sleep(self.delay)
        up = socket.create_connection((host, int(port)))
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        try:
            while True:
                ready, _, _ = select.select([c, up], [], [], 5)
                if not ready:
                    break
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is c else c).sendall(data)
        except OSError:
            pass
        finally:
            c.close(); up.close()

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------

def test_version_matches_pyproject():
    import tomllib
    data = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert yumeclient.__version__ == data["project"]["version"]


def test_profile_roundtrip_identifier():
    s = Session(client_identifier="firefox_147", http_version="2", header_order=["accept", "user-agent"],
                proxy="http://user:secret@127.0.0.1:1", timeout=3, verify=False, cookies={"sid": "abc"})
    s.headers.pop("accept-language")
    s.headers["X-App"] = "1"
    exported = json.loads(json.dumps(s.export_profile()))  # JSON-safe
    assert exported["format"] == PROFILE_FORMAT and exported["version"] == 1
    assert exported["yumeclient"] == yumeclient.__version__
    text = json.dumps(exported)
    for secret in ("secret", "127.0.0.1", "sid", "abc", "verify", "timeout"):
        assert secret not in text, secret  # environment and credentials are not part of a profile
    clone = Session.from_profile(exported)
    assert list(clone.headers.items()) == list(s.headers.items())  # order + removal + addition
    assert "accept-language" not in clone.headers
    same = lambda core: (core.client_identifier, core.client_os, core.header_style, core.http_version,  # noqa: E731
                         core.header_order, core.random_tls_extension_order, core.custom)
    assert same(clone._core) == same(s._core)
    assert clone._core.proxy is None and clone._core.verify is True
    with_proxy = AsyncSession.from_profile(exported, proxy="http://127.0.0.1:2", headers={"X-Only": "1"})
    assert with_proxy._core.proxy == "http://127.0.0.1:2" and with_proxy.headers["x-only"] == "1"
    for session in (s, clone, with_proxy):
        session._core.close()


def test_profile_roundtrip_ja3_with_binary_options():
    s = Session(ja3_string=JA3, tls_extension_order=[0, 10, 11, 13, 16, 43, 45, 51], grease=False,
                ech_config_list=b"\x00\x01ech", key_share_data={29: b"\x11" * 32}, alpn_protocols=["h2", "http/1.1"],
                h2_settings={"HEADER_TABLE_SIZE": 65536}, fill_custom_with_chrome_defaults=False,
                random_tls_extension_order=False)
    exported = json.loads(json.dumps(s.export_profile()))
    assert "client_identifier" not in exported["transport"]
    clone = Session.from_profile(exported)
    assert clone._core._transportMark() == s._core._transportMark()
    assert clone._core.ech_config_list == b"\x00\x01ech" and clone._core.key_share_data == {29: b"\x11" * 32}
    s.close(); clone.close()


@pytest.mark.parametrize("doc, match", [
    ({"format": "other"}, "not a yumeclient.profile"),
    ({"format": PROFILE_FORMAT, "version": 99}, "newer than this yumeclient supports"),
    ({"format": PROFILE_FORMAT, "version": "1"}, "invalid profile version"),
    ({"format": PROFILE_FORMAT, "version": 1, "transport": {"proxy": "http://x"}}, "unknown profile option"),
    ({"format": PROFILE_FORMAT, "version": 1, "headers": [1, 2]}, "list of \\[name, value\\] pairs"),
    ({"format": PROFILE_FORMAT, "version": 1, "transport": {"http_version": "1.1", "force_http1": True,
                                                            "alpn_protocols": ["h2"], "ja3_string": JA3}},
     "conflicts with forced HTTP/1.1"),
])
def test_profile_validation(doc, match):
    with pytest.raises(SessionConfigurationError, match=match):
        Session.from_profile(doc)


def test_export_carries_the_observed_fingerprint(tls_server):
    with Session(verify=False, timeout=5) as s:
        assert "fingerprint" not in s.export_profile()
        r = s.get(f"https://127.0.0.1:{tls_server.port}/x")
        exported = s.export_profile()
        # the next request carries the server's cookie and a body: same profile, no diff
        later = s.post(f"https://127.0.0.1:{tls_server.port}/y", data=b"payload")
        assert any(name.lower() == "cookie" for name, _ in later.fingerprint["request_headers"])
        assert fingerprint_diff(exported, later) == []
    fp = exported["fingerprint"]
    assert fp["ja4"] == r.fingerprint["ja4"] and fp["source"] == "wire"
    assert fp["header_order"] == [name.lower() for name, _ in r.fingerprint["request_headers"]
                                  if name.lower() not in ("cookie", "content-length", "content-type")]
    assert fingerprint_diff(exported, r) == []
    assert "fingerprint" not in s.export_profile(include_fingerprint=False)


# ---------------------------------------------------------------------------
# fingerprint_diff
# ---------------------------------------------------------------------------

BASE = {"ja4": "t13d1516h2_aaa_bbb", "ja3": "771,4865-4866,0-10-11,29-23,0", "alpn_offered": ["h2", "http/1.1"],
        "tls_extensions": [2570, 0, 10, 11, 6682], "header_order": ["Host", "User-Agent"], "tls_version": "1.3"}


def test_fingerprint_diff_identical_ignores_grease_and_case():
    actual = dict(BASE, tls_extensions=[0, 10, 11, 47802], header_order=["host", "user-agent"], extra="ignored")
    assert fingerprint_diff(BASE, actual) == []


def test_fingerprint_diff_kinds():
    actual = dict(BASE, ja4="t13d1516h2_aaa_ccc", ja3="771,4866-4865,11-0-10,29-23-24,0",
                  tls_extensions=[11, 0, 10], header_order=["user-agent", "host"], alpn_offered=["http/1.1"])
    del actual["tls_version"]
    diff = {d["field"]: d for d in fingerprint_diff(BASE, actual)}
    assert diff["ja4"]["kind"] == "value"
    assert diff["ja3.ciphers"]["kind"] == "order" and diff["ja3.extensions"]["kind"] == "order"
    assert diff["ja3.groups"]["kind"] == "set" and diff["ja3.groups"]["unexpected"] == ["24"]
    assert diff["tls_extensions"]["kind"] == "order" and diff["header_order"]["kind"] == "order"
    assert diff["alpn_offered"]["kind"] == "set" and diff["alpn_offered"]["missing"] == ["h2"]
    assert diff["tls_version"] == {"field": "tls_version", "kind": "missing", "expected": "1.3", "actual": None}
    assert "ja3_hash_md5" not in diff


def test_header_order_ignores_request_dependent_headers():
    expected = {"header_order": ["Host", "Cookie", "User-Agent", "Content-Length", "Accept"]}
    assert fingerprint_diff(expected, {"header_order": ["host", "user-agent", "accept", "authorization"]}) == []
    assert fingerprint_diff(expected, {"header_order": ["host", "accept", "user-agent"]})[0]["kind"] == "order"


def test_fingerprint_diff_accepts_responses(tls_server):
    with Session(verify=False, timeout=5, client_identifier="okhttp4_conscrypt") as a:
        ra = a.get(f"https://127.0.0.1:{tls_server.port}/x")
    with Session(verify=False, timeout=5, client_identifier="firefox_147") as b:
        rb = b.get(f"https://127.0.0.1:{tls_server.port}/x")
    assert fingerprint_diff(ra, ra) == []
    fields = {d["field"] for d in fingerprint_diff(ra, rb)}
    assert {"ja4", "ja4_r"} <= fields


# ---------------------------------------------------------------------------
# redacted trace
# ---------------------------------------------------------------------------

def test_trace_is_redacted_and_complete(tls_server):
    body = b'{"password": "hunter2-body"}'
    with Session(verify=False, timeout=5, cookies={"sid": "cookie-secret"}) as s:
        r = s.post(f"https://user:pw-secret@127.0.0.1:{tls_server.port}/login?token=query-secret&page=2",
                   data=body, headers={"Authorization": "Bearer bearer-secret", "X-Session-Id": "sess-secret",
                                       "X-Custom": "kept", "X-Internal": "internal-secret",
                                       "Content-Type": "application/json"})
    trace = json.loads(json.dumps(r.trace(redact=["X-Internal"])))
    text = json.dumps(trace)
    for secret in ("hunter2", "cookie-secret", "query-secret", "bearer-secret", "sess-secret", "pw-secret",
                   "internal-secret", "user:"):
        assert secret not in text, secret
    req = trace["request"]
    assert req["method"] == "POST" and req["header_source"] == "wire"
    assert req["url"] == f"https://127.0.0.1:{tls_server.port}/login?token=[redacted]&page=[redacted]"
    assert req["header_order"] == [name for name, _ in r.fingerprint["request_headers"]]
    values = {name.lower(): value for name, value in req["headers"]}
    assert values["x-custom"] == "kept" and values["authorization"] == "[redacted]" and values["cookie"] == "[redacted]"
    assert req["body"] == {"length": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    assert trace["response"]["status"] == 200
    assert trace["response"]["body"]["sha256"] == hashlib.sha256(r.content).hexdigest()
    assert trace["tls"]["ja4"] == r.fingerprint["ja4"] and trace["tls"]["source"] == "wire"
    assert trace["connection"]["alpn_negotiated"] == "http/1.1" and trace["connection"]["tls_cipher"]
    names_only = r.trace(values=False)
    assert all(len(item) == 1 for item in names_only["request"]["headers"])
    assert "query-secret" in json.dumps(r.trace(redact_query=False))


def test_trace_of_unconsumed_stream(tls_server):
    with Session(verify=False, timeout=5) as s:
        with s.get(f"https://127.0.0.1:{tls_server.port}/x", stream=True) as r:
            assert r.trace()["response"]["body"] == {"streamed": True, "consumed": False}
            assert r.trace()["request"]["body"] is None


# ---------------------------------------------------------------------------
# connection_info: cipher + proxy phase
# ---------------------------------------------------------------------------

def test_connection_info_cipher_and_proxy_timing(tls_server):
    proxy = ConnectProxy(delay=0.2)
    try:
        with Session(verify=False, timeout=5, proxy=f"http://127.0.0.1:{proxy.port}") as s:
            first = s.get(f"https://127.0.0.1:{tls_server.port}/a").connection_info
            second = s.get(f"https://127.0.0.1:{tls_server.port}/b").connection_info
        assert first["tls_cipher"].startswith("TLS_") and second["tls_cipher"] == first["tls_cipher"]
        assert 0.2 <= first["timings"]["proxy"] <= first["timings"]["connect"]
        assert second["connection_reused"] and second["timings"]["proxy"] is None
        assert proxy.seen == [f"CONNECT 127.0.0.1:{tls_server.port} HTTP/1.1"]
        with Session(verify=False, timeout=5) as direct:
            assert direct.get(f"https://127.0.0.1:{tls_server.port}/c").connection_info["timings"]["proxy"] is None
    finally:
        proxy.close()


def test_export_omits_credential_headers(native):
    with Session(headers={"Authorization": "Bearer SECRET", "X-Api-Key": "K1", "Ocp-Apim-Subscription-Key": "K2",
                          "X-Custom": "kept"}) as s:
        exported = s.export_profile()
        text = json.dumps(exported)
        assert "SECRET" not in text and "K1" not in text and "K2" not in text
        assert exported["omitted_headers"] == ["Authorization", "X-Api-Key", "Ocp-Apim-Subscription-Key"]
        clone = Session.from_profile(exported)
        assert "authorization" not in clone.headers and clone.headers["x-custom"] == "kept"
        clone.close()
        full = s.export_profile(include_secrets=True)
        assert "omitted_headers" not in full and ["Authorization", "Bearer SECRET"] in full["headers"]


def test_trace_redacts_urls_in_headers_and_bare_query(native):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://idp.example/cb?code=code-secret&state=state-secret#frag-secret")
            self.send_header("Link", "</next?cursor=cursor-secret>; rel=next")
            self.send_header("Refresh", "5; url=/r?ticket=ticket-secret")
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with Session(timeout=5) as s:
            r = s.get(f"http://127.0.0.1:{srv.server_address[1]}/cb?BARE_SECRET&a=1", allow_redirects=False,
                      headers={"Referer": "https://site.example/p?ref=ref-secret", "X-Client-Key": "key-secret"})
    finally:
        srv.shutdown(); srv.server_close()
    trace = r.trace()
    text = json.dumps(trace)
    for secret in ("code-secret", "state-secret", "frag-secret", "cursor-secret", "ticket-secret", "BARE_SECRET",
                   "ref-secret", "key-secret"):
        assert secret not in text, secret
    assert trace["request"]["url"].endswith("/cb?[redacted]&a=[redacted]")
    response = {name.lower(): value for name, value in trace["response"]["headers"]}
    assert response["location"] == "https://idp.example/cb?code=[redacted]&state=[redacted]"
    assert response["link"] == "</next?cursor=[redacted]>; rel=next"
    assert response["refresh"] == "5; url=/r?ticket=[redacted]"
    assert "code-secret" in json.dumps(r.trace(redact_query=False))


def test_trace_over_http2_keeps_authority_and_redacts_path_query(native):
    from test_protocol import H2Server
    srv = H2Server()
    try:
        with Session(verify=False, timeout=5, http_version="2", client_identifier="chrome_131") as s:
            r = s.get(f"https://127.0.0.1:{srv.port}/p?token=path-secret&BARE_SECRET")
    finally:
        srv.close()
    trace = r.trace()
    assert "path-secret" not in json.dumps(trace) and "BARE_SECRET" not in json.dumps(trace)
    headers = dict((name, value) for name, value in trace["request"]["headers"])
    assert headers[":authority"] == f"127.0.0.1:{srv.port}"
    assert headers[":path"] == "/p?token=[redacted]&[redacted]"
