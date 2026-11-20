"""Response.history: every followed redirect, oldest first (requests semantics)."""
from __future__ import annotations

import asyncio
import gzip
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

import yumeclient
from yumeclient import AsyncSession, Session


def _zstd_start(data: bytes) -> bytes:
    """A zstd frame header and one raw, not-last block: the stream goes on."""
    block = (len(data) << 3).to_bytes(3, "little")  # Last_Block=0, Block_Type=raw
    return b"\x28\xb5\x2f\xfd" + b"\x00\x20" + block + data  # no FCS, 16 KiB window


def _partial(enc: str, data: bytes) -> bytes:
    """The start of a compressed stream: complete up to data, unterminated."""
    if enc == "zstd":
        return _zstd_start(data)
    c = zlib.compressobj(wbits={"gzip": 31, "deflate": 15}[enc])
    return c.compress(data) + c.flush(zlib.Z_SYNC_FLUSH)


def _deflate(data: bytes, raw: bool) -> bytes:
    c = zlib.compressobj(wbits=-15 if raw else 15)
    return c.compress(data) + c.flush()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    connections: set[tuple[str, int]] = set()

    def log_message(self, *_: object) -> None:
        pass

    def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.connections.add(self.client_address)
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path == "/chain":  # /chain?n=3 -> 302 /chain?n=2 -> 301 /chain?n=1 -> 307 /final
            n = int(query["n"])
            status = {3: 302, 2: 301, 1: 307}.get(n, 302)
            target = f"/chain?n={n - 1}" if n > 1 else "/final"
            self._send(status, f"hop {n}".encode(), {"Location": target, "Set-Cookie": f"hop{n}=v{n}; Path=/"})
        elif parts.path == "/gzip-redirect":
            self._send(302, gzip.compress(b"moved here"), {"Location": "/final", "Content-Encoding": "gzip"})
        elif parts.path == "/big-redirect":
            self._send(302, b"z" * 100_000, {"Location": "/final"})
        elif parts.path == "/stall-redirect":  # 302 announcing 100000 bytes, 5000 sent, then silence
            self.connections.add(self.client_address)
            self.send_response(302)
            self.send_header("Location", "/final")
            if query.get("enc"):  # a compressed stream that stops halfway
                chunk = _partial(query["enc"], b"x" * 5000)
                self.send_header("Content-Encoding", query["enc"])
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            elif query.get("chunked"):
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"1388\r\n" + b"x" * 5000 + b"\r\n")
            else:
                self.send_header("Content-Length", "100000")
                self.end_headers()
                self.wfile.write(b"x" * 5000)
            self.wfile.flush()
            time.sleep(4)
            self.close_connection = True
        elif parts.path == "/slow-hop":
            time.sleep(0.3)
            self._send(302, b"", {"Location": "/final"})
        elif parts.path == "/multiple":  # 300 is not followed: the final response
            self._send(300, b"m" * 100_000, {"Location": "/final"})
        elif parts.path == "/deflate":  # ?raw=1: RFC 1951 without the zlib wrapper
            body = _deflate(b"deflated " * 1000, raw=bool(query.get("raw")))
            if query.get("redirect"):
                self._send(302, body, {"Location": "/final", "Content-Encoding": "deflate"})
            else:
                self._send(200, body, {"Content-Encoding": "deflate"})
        elif parts.path == "/zstd-redirect":  # complete frame: the last block
            data = b"zstd body"
            self._send(302, b"\x28\xb5\x2f\xfd\x00\x20" + ((len(data) << 3) | 1).to_bytes(3, "little") + data,
                       {"Location": "/final", "Content-Encoding": "zstd"})
        elif parts.path == "/loop":
            self._send(302, b"", {"Location": "/loop"})
        else:
            self._send(200, b"final:" + (self.headers.get("Cookie") or "").encode())

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if self.path == "/post-303":
            self._send(303, b"", {"Location": "/final"})
        elif self.path == "/post-307":
            self._send(307, b"", {"Location": "/echo"})
        elif self.path == "/post-307-308":
            self._send(307, b"", {"Location": "/post-308"})
        elif self.path == "/post-308":
            self._send(308, b"", {"Location": "/echo"})
        else:
            self._send(200, b"echo:" + body)


@pytest.fixture(scope="module")
def server():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


def test_history_of_a_redirect_chain(server):
    with Session(timeout=5) as s:
        r = s.get(f"{server}/chain?n=3")
    assert r.status_code == 200 and r.url == f"{server}/final" and not r.is_redirect
    assert [(h.status_code, h.url) for h in r.history] == [
        (302, f"{server}/chain?n=3"), (301, f"{server}/chain?n=2"), (307, f"{server}/chain?n=1")]
    first = r.history[0]
    assert first.is_redirect and first["location"] == "/chain?n=2"
    assert first.content == b"hop 3" and first.cookies == {"hop3": "v3"}
    assert first.used_protocol == "HTTP/1.1" and first.elapsed > 0 and first.history == []
    assert sorted(r.content[len(b"final:"):].split(b"; ")) == [b"hop1=v1", b"hop2=v2", b"hop3=v3"]
    assert [hop["status"] for hop in r.trace()["redirects"]] == [302, 301, 307]


def test_no_history_without_redirects(server):
    with Session(timeout=5) as s:
        assert s.get(f"{server}/final").history == []


def test_per_request_allow_redirects_false(server):
    with Session(timeout=5) as s:
        r = s.get(f"{server}/chain?n=2", allow_redirects=False)
        assert r.status_code == 301 and r.history == [] and r.content == b"hop 2"
        r = s.get(f"{server}/chain?n=2")
        assert [h.status_code for h in r.history] == [301, 307]


def test_redirect_bodies_decoded_and_bounded(server):
    with Session(timeout=5) as s:
        gz = s.get(f"{server}/gzip-redirect")
        big = s.get(f"{server}/big-redirect")
    assert gz.history[0].content == b"moved here"
    assert big.status_code == 200 and big.history[0].status_code == 302 and big.history[0].content == b""


def test_method_change_and_body_on_redirect(server):
    with Session(timeout=5) as s:
        see_other = s.post(f"{server}/post-303", data=b"payload")
        temporary = s.post(f"{server}/post-307", data=b"payload")
    assert see_other.content.startswith(b"final:") and [h.status_code for h in see_other.history] == [303]
    assert see_other.history[0]._method == "POST"
    assert temporary.content == b"echo:payload" and [h.status_code for h in temporary.history] == [307]


def test_replayed_body_through_several_redirects(server):
    # the 308 hop was followed (with the body) but missing from history
    with Session(timeout=5) as s:
        r = s.post(f"{server}/post-307-308", data=b"payload")
    assert r.content == b"echo:payload" and [h.status_code for h in r.history] == [307, 308]


def test_streamed_response_has_history(server):
    with Session(timeout=5) as s:
        with s.get(f"{server}/chain?n=2", stream=True) as r:
            assert [h.status_code for h in r.history] == [301, 307]
            assert r.read().startswith(b"final:")


def test_too_many_redirects_is_an_error(server):
    with Session(timeout=5) as s, pytest.raises(yumeclient.RequestError):
        s.get(f"{server}/loop")


def test_async_history(server):
    async def main():
        async with AsyncSession(timeout=5) as s:
            return await s.get(f"{server}/chain?n=3")
    r = asyncio.run(main())
    assert [h.status_code for h in r.history] == [302, 301, 307]


@pytest.mark.parametrize("query", ["", "?chunked=1", "?enc=gzip", "?enc=deflate", "?enc=zstd"])
def test_stalled_redirect_body_does_not_hold_the_request(server, query):
    # the redirect body is captured for history only while it keeps coming: a stall
    # gives content b"" and the redirect is followed (0.7.0 waited for the whole body,
    # without a read timeout, so this hung until the server gave up). A zstd decoder
    # closed during its read used to block, a zlib deflate body to deadlock
    with Session(timeout=yumeclient.TimeoutConfig(connect=2, read=10)) as s:
        t0 = time.monotonic()
        r = s.get(server + "/stall-redirect" + query)
        took = time.monotonic() - t0
    assert r.status_code == 200 and r.content.startswith(b"final:")
    assert [h.status_code for h in r.history] == [302] and r.history[0].content == b""
    assert took < 2.0, took


@pytest.mark.parametrize("raw", [False, True])
def test_deflate_responses(server, raw):
    # Content-Encoding: deflate over HTTP/1.1 hung (fhttp read the whole body inside its
    # read loop); raw deflate not starting with 0x78 was returned compressed
    expected = b"deflated " * 1000
    flag = "&raw=1" if raw else ""
    with Session(timeout=5) as s:
        final = s.get(f"{server}/deflate?x=1{flag}")
        moved = s.get(f"{server}/deflate?redirect=1{flag}")
        streamed = s.get(f"{server}/deflate?x=1{flag}", stream=True)
        chunks = b"".join(streamed.iter_bytes())
    assert final.status_code == 200 and final.content == expected
    assert moved.status_code == 200 and moved.history[0].content == expected
    assert chunks == expected


def test_zstd_redirect_body_is_captured(server):
    with Session(timeout=5) as s:
        r = s.get(server + "/zstd-redirect")
    assert r.status_code == 200 and r.history[0].content == b"zstd body"


def test_unfollowed_3xx_is_the_final_response(server):
    with Session(timeout=5) as s:
        r = s.get(server + "/multiple")
    assert r.status_code == 300 and r.history == [] and r.content == b"m" * 100_000


def test_history_elapsed_is_per_hop(server):
    with Session(timeout=5) as s:
        r = s.get(server + "/slow-hop")
    assert [h.status_code for h in r.history] == [302]
    assert r.history[0].elapsed >= 0.3
