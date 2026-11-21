"""Request lifecycle: native cancellation, split timeouts, structured errors, streaming,
resource release and per-request proxy isolation. Local servers only (no internet)."""
from __future__ import annotations

import asyncio
import gc
import gzip
import socket
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

import yumeclient
from yumeclient import (AsyncSession, ConnectError, ConnectionClosed, ConnectTimeout, ProxyError, ReadTimeout,
                        RequestCancelled, RequestError, ResponseTooLarge, Session, StreamClosed, Timeout,
                        TimeoutConfig, TLSError)

CHUNK = b"x" * 65536


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_: object) -> None:
        pass

    def _send(self, body: bytes, status: int = 200, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        delay = float(query.get("d", "0"))
        try:
            if parts.path == "/slow-headers":
                time.sleep(delay)
                self._send(b"late")
            elif parts.path == "/slow-body":
                # headers + first chunk at once, then the rest after `delay`
                self.send_response(200)
                self.send_header("Content-Length", str(len(CHUNK) * 2))
                self.end_headers()
                self.wfile.write(CHUNK)
                self.wfile.flush()
                time.sleep(delay)
                self.wfile.write(CHUNK)
            elif parts.path == "/big":
                total = int(query["n"])
                self.send_response(200)
                self.send_header("Content-Length", str(total))
                self.end_headers()
                sent = 0
                while sent < total:
                    piece = CHUNK[: min(len(CHUNK), total - sent)]
                    self.wfile.write(piece)
                    sent += len(piece)
            elif parts.path == "/gzip-bomb":
                body = gzip.compress(b"0" * 5_000_000)
                self._send(body, extra={"Content-Encoding": "gzip"})
            elif parts.path == "/drip":
                # chunked body: one small chunk every `delay` seconds, `n` chunks
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for _ in range(int(query.get("n", "5"))):
                    self.wfile.write(b"4\r\ndrip\r\n")
                    self.wfile.flush()
                    time.sleep(delay)
                self.wfile.write(b"0\r\n\r\n")
            else:
                self._send(b"direct", extra={"Set-Cookie": "seen=1; Path=/"})
        except OSError:
            pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


class _RawServer:
    """TCP listener with a scripted behaviour per connection: 'silent' (accept, never
    answer), 'close' (accept, read the request, close), 'proxy' (minimal forward proxy) or
    'slow-403' (read the request, answer 403 after ``delay`` seconds)."""

    def __init__(self, mode: str, delay: float = 0.0) -> None:
        self.mode, self.delay = mode, delay
        self.seen: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.conns: list[socket.socket] = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            if self.mode == "silent":
                return
            data = b""
            while b"\r\n\r\n" not in data:
                piece = conn.recv(65536)
                if not piece:
                    break
                data += piece
            self.seen.append(data)
            if self.mode == "proxy":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy")
            if self.mode == "slow-403":
                time.sleep(self.delay)
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            conn.close()
        except OSError:
            pass

    def close(self) -> None:
        self.sock.close()
        for conn in self.conns:
            try:
                conn.close()
            except OSError:
                pass


@pytest.fixture
def raw():
    servers: list[_RawServer] = []

    def make(mode: str, delay: float = 0.0) -> _RawServer:
        servers.append(_RawServer(mode, delay))
        return servers[-1]

    yield make
    for item in servers:
        item.close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _settle(predicate, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# -- cancellation ------------------------------------------------------------------

def test_async_cancel_while_awaiting_headers_is_prompt(server):
    async def main() -> float:
        async with AsyncSession(timeout=10) as session:
            started = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(session.get(server + "/slow-headers?d=2"), 0.1)
            return time.monotonic() - started
    assert asyncio.run(main()) < 0.5
    assert _settle(lambda: yumeclient._debugStats()["inflight"] == 0)


def test_async_cancel_during_slow_body_is_prompt(server):
    async def main() -> float:
        async with AsyncSession(timeout=10) as session:
            started = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(session.get(server + "/slow-body?d=2"), 0.2)
            return time.monotonic() - started
    assert asyncio.run(main()) < 0.6
    assert _settle(lambda: yumeclient._debugStats()["inflight"] == 0)


def test_session_close_cancels_inflight_after_grace(server):
    async def main() -> tuple[float, BaseException | None]:
        session = AsyncSession(timeout=10)
        task = asyncio.create_task(session.get(server + "/slow-headers?d=3"))
        await asyncio.sleep(0.1)
        started = time.monotonic()
        await session.close(grace=0.1)
        elapsed = time.monotonic() - started
        try:
            await task
        except BaseException as exc:  # noqa: BLE001
            return elapsed, exc
        return elapsed, None
    elapsed, exc = asyncio.run(main())
    assert elapsed < 0.8
    assert isinstance(exc, RequestCancelled), exc


# -- timeouts ----------------------------------------------------------------------

def test_total_timeout_applies_to_plain_http(server):
    # http:// used a hard-coded 30 s http.Client timeout and ignored the session value
    with Session(timeout=0.5) as session:
        started = time.monotonic()
        with pytest.raises(Timeout) as info:
            session.get(server + "/slow-headers?d=3")
    assert time.monotonic() - started < 1.5
    assert info.value.kind == "timeout" and isinstance(info.value, TimeoutError)
    assert info.value.retryable


def test_per_request_timeout_overrides_existing_session(server):
    with Session(timeout=10) as session:
        assert session.get(server + "/").text == "direct"   # Go session now exists
        started = time.monotonic()
        with pytest.raises(Timeout):
            session.get(server + "/slow-headers?d=3", timeout=0.4)
        assert time.monotonic() - started < 1.5
        assert session.get(server + "/slow-headers?d=0.6", timeout=5).text == "late"


def test_read_timeout_waiting_for_headers(server):
    with Session(timeout=TimeoutConfig(total=10, read=0.4)) as session:
        with pytest.raises(ReadTimeout) as info:
            session.get(server + "/slow-headers?d=3")
    assert info.value.kind == "read_timeout" and info.value.stage == "read"


def test_read_timeout_is_an_idle_limit_on_the_body(server):
    with Session(timeout=TimeoutConfig(total=10, read=0.4)) as session:
        # 5 chunks 0.2 s apart: 1 s total, never idle for 0.4 s
        assert session.get(server + "/drip?d=0.2&n=5").content == b"drip" * 5
        with pytest.raises(ReadTimeout) as info:
            session.get(server + "/slow-body?d=3")
    assert info.value.stage == "body"


def test_connect_timeout_on_silent_proxy(raw):
    silent = raw("silent")
    with Session(timeout=TimeoutConfig(total=10, connect=0.4), proxy=f"http://127.0.0.1:{silent.port}") as session:
        started = time.monotonic()
        with pytest.raises(ConnectTimeout) as info:
            session.get("https://example.test/")
    assert time.monotonic() - started < 1.5
    assert info.value.stage == "connect"
    assert isinstance(info.value, ConnectError) and isinstance(info.value, TimeoutError)


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_silent_proxy_connection_is_closed_when_the_request_gives_up(raw, scheme):
    """The CONNECT exchange follows the request: before 0.8.2 an http:// proxy that never
    answered kept the connection (and a goroutine) open for 30 s after the timeout."""
    silent = raw("silent")
    with Session(timeout=TimeoutConfig(total=10, connect=0.4), proxy=f"{scheme}://127.0.0.1:{silent.port}") as session:
        with pytest.raises(ConnectTimeout):
            session.get("https://example.test/")
    assert _settle(lambda: len(silent.conns) == 1)
    conn = silent.conns[0]
    conn.settimeout(3)
    received = b""
    while piece := conn.recv(65536):  # the CONNECT request or ClientHello, then EOF
        received += piece
    assert received


def test_opening_a_connection_is_not_cut_at_30_seconds(raw):
    """timeout=None has no connect limit; before 0.8.2 the session's dialer (built with
    max(30 s, connect of the first request)) cut the CONNECT exchange at 30 s."""
    slow = raw("slow-403", delay=31)
    with Session(timeout=None, proxy=f"http://127.0.0.1:{slow.port}") as session:
        started = time.monotonic()
        with pytest.raises(ProxyError, match="403"):
            session.get("https://example.test/")
    assert time.monotonic() - started >= 31


def test_connect_timeout_on_stalled_tls_handshake(raw):
    silent = raw("silent")
    with Session(timeout=TimeoutConfig(total=10, connect=0.4)) as session:
        with pytest.raises(ConnectTimeout):
            session.get(f"https://127.0.0.1:{silent.port}/")


def test_timeout_tuple_and_validation():
    assert yumeclient._timeoutConfig((1, 2)) == TimeoutConfig(connect=1, read=2)
    assert yumeclient._timeoutConfig(3) == TimeoutConfig(total=3)
    assert yumeclient._timeoutConfig(None) == TimeoutConfig()
    with pytest.raises(yumeclient.SessionConfigurationError):
        Session(timeout=0)
    with pytest.raises(yumeclient.SessionConfigurationError):
        Session(timeout=(1, 2, 3))


# -- structured errors -------------------------------------------------------------

def test_connection_refused_is_connect_error():
    with Session(timeout=5) as session:
        with pytest.raises(ConnectError) as info:
            session.get(f"http://127.0.0.1:{_free_port()}/")
    assert info.value.kind == "connect" and info.value.stage == "connect"
    assert isinstance(info.value, ConnectionError) and isinstance(info.value, RequestError)
    assert isinstance(info.value.__cause__, Exception)


def test_tls_to_plain_http_server_is_tls_error(server):
    port = urlsplit(server).port
    with Session(timeout=5) as session:
        with pytest.raises(TLSError) as info:
            session.get(f"https://127.0.0.1:{port}/")
    assert info.value.kind == "tls" and not info.value.retryable


def test_dead_proxy_is_proxy_error_without_credentials():
    proxy = f"http://user:s3cret@127.0.0.1:{_free_port()}"
    with Session(timeout=5, proxy=proxy) as session:
        with pytest.raises(ProxyError) as info:
            session.get("https://user2:pw2@example.test/path")
    text = str(info.value) + str(info.value.detail) + str(info.value.url)
    assert "s3cret" not in text and "pw2" not in text
    assert info.value.url == "https://example.test/path"


def test_server_closing_connection_is_connection_closed(raw):
    closer = raw("close")
    with Session(timeout=5) as session:
        with pytest.raises(ConnectionClosed) as info:
            session.get(f"http://127.0.0.1:{closer.port}/")
    assert info.value.kind == "connection_closed"


def test_response_too_large(server):
    with Session(timeout=10, max_content_size=100_000) as session:
        with pytest.raises(ResponseTooLarge):
            session.get(server + "/big?n=1000000")
        assert len(session.get(server + "/big?n=1000").content) == 1000
        assert len(session.get(server + "/big?n=1000000", max_content_size=2_000_000).content) == 1_000_000


def test_response_limit_counts_decoded_bytes(server):
    # ~5 KB on the wire, 5 MB decoded
    with Session(timeout=10, max_content_size=1_000_000) as session:
        with pytest.raises(ResponseTooLarge):
            session.get(server + "/gzip-bomb")
        with pytest.raises(ResponseTooLarge):
            session.get(server + "/gzip-bomb", stream=True).read()
        assert len(session.get(server + "/gzip-bomb", max_content_size=6_000_000).content) == 5_000_000


def test_raise_for_status_keeps_response():
    response = yumeclient.Response(404, {}, {}, b"", "https://u:p@example.test/x")
    with pytest.raises(yumeclient.HTTPStatusError) as info:
        response.raise_for_status()
    assert info.value.response is response and "u:p" not in str(info.value)


# -- streaming ---------------------------------------------------------------------

def test_stream_large_body_with_bounded_memory(server):
    size = 64 * 1024 * 1024
    with Session(timeout=30) as session:
        tracemalloc.start()
        try:
            total = 0
            with session.get(server + f"/big?n={size}", stream=True) as response:
                assert response.status_code == 200 and not response.is_stream_consumed
                for chunk in response.iter_bytes(256 * 1024):
                    total += len(chunk)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert total == size
    assert peak < 8 * 1024 * 1024, peak
    assert _settle(lambda: yumeclient._debugStats()["streams"] == 0)


def test_stream_read_and_content(server):
    with Session(timeout=10) as session:
        response = session.get(server + "/big?n=300000", stream=True)
        assert len(response.content) == 300000      # sync .content reads the rest
        assert response.is_stream_consumed
        response = session.get(server + "/big?n=1000", stream=True)
        assert sum(len(c) for c in response.iter_bytes()) == 1000
        with pytest.raises(StreamClosed):
            response.content                            # already consumed by iter_bytes
    assert _settle(lambda: yumeclient._debugStats()["streams"] == 0)


def test_stream_early_close_and_gc_release_native_handles(server):
    with Session(timeout=10) as session:
        for _ in range(3):
            response = session.get(server + "/big?n=5000000", stream=True)
            next(iter(response.iter_bytes(1024)))      # leaving the loop closes the stream
        response = session.get(server + "/big?n=5000000", stream=True)
        del response
        gc.collect()
        assert _settle(lambda: yumeclient._debugStats()["streams"] == 0)
        opened = session.get(server + "/big?n=5000000", stream=True)
    # session close releases streams that are still open
    assert opened.is_stream_consumed
    assert _settle(lambda: yumeclient._debugStats() ["inflight"] == 0)


def test_async_stream_and_cancel_partial_read(server):
    async def main() -> float:
        async with AsyncSession(timeout=10) as session:
            response = await session.get(server + "/big?n=200000", stream=True)
            with pytest.raises(StreamClosed):
                response.content                           # async streams need aread()
            assert len(await response.aread()) == 200000
            response = await session.get(server + "/slow-body?d=3", stream=True)

            async def consume() -> int:
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                return total
            started = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(consume(), 0.3)
            return time.monotonic() - started
    assert asyncio.run(main()) < 0.8
    assert _settle(lambda: yumeclient._debugStats()["streams"] == 0)
    assert _settle(lambda: yumeclient._debugStats()["inflight"] == 0)


def test_one_shot_stream_owns_its_session(server):
    response = yumeclient.get(server + "/big?n=4096", stream=True, timeout=10)
    assert sum(len(c) for c in response.iter_bytes(1000)) == 4096
    assert response._owner is None   # closed with the stream

    async def main() -> int:
        response = await yumeclient.aget(server + "/big?n=4096", stream=True, timeout=10)
        return len(await response.aread())
    assert asyncio.run(main()) == 4096


# -- observability -------------------------------------------------------------------

def test_connection_info_reports_reuse_and_timings(server):
    with Session(timeout=10) as session:
        first = session.get(server + "/")
        second = session.get(server + "/")
    assert first.connection_info["connection_reused"] is False
    assert second.connection_info["connection_reused"] is True
    timings = first.connection_info["timings"]
    phases = sum(v for k, v in timings.items() if k in ("redirects", "connect", "write", "wait", "body") and v)
    assert abs(phases - timings["total"]) < 0.01
    assert first.connection_info["remote_address"].startswith("127.0.0.1:")
    assert first.request_id and first.request_id != second.request_id


# -- proxy isolation -------------------------------------------------------------------

def test_per_request_proxy_is_not_ignored_by_an_existing_session(server, raw):
    proxy = raw("proxy")
    with Session(timeout=10) as session:
        assert session.get(server + "/").text == "direct"
        routed = session.get(server + "/", proxy=f"http://127.0.0.1:{proxy.port}")
        assert routed.text == "via-proxy"
        assert proxy.seen and proxy.seen[0].startswith(b"GET http://127.0.0.1:")
        assert session.get(server + "/").text == "direct"


def test_cancellation_logs_nothing_to_the_event_loop(server):
    # asyncio.shield (Python 3.14) reported every aborted native call as
    # "RequestCancelled exception in shielded future" through the loop's exception handler
    errors: list[dict] = []

    async def main() -> None:
        asyncio.get_running_loop().set_exception_handler(lambda _loop, context: errors.append(context))
        async with AsyncSession(timeout=10) as session:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(session.get(server + "/slow-headers?d=1"), 0.1)
            response = await session.get(server + "/slow-body?d=1", stream=True)

            async def consume() -> None:
                async for _ in response.aiter_bytes():
                    pass
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(consume(), 0.2)
            await asyncio.sleep(0.5)  # aborted native calls finish in the executor
            gc.collect()
    asyncio.run(main())
    assert errors == [], [str(item.get("message")) for item in errors]


def test_unclosed_session_releases_its_connections_when_collected():
    # a Session dropped without close() kept its native session (pool, connections) forever
    closed = threading.Event()
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            conn.settimeout(10)
            try:
                if not conn.recv(65536):
                    closed.set()
            except OSError:
                closed.set()

    threading.Thread(target=serve, daemon=True).start()
    try:
        s = Session(timeout=5)
        assert s.get(f"http://127.0.0.1:{srv.getsockname()[1]}/").content == b"ok"
        del s
        gc.collect()
        assert closed.wait(5), "the connection stayed open after the session was collected"
    finally:
        srv.close()
