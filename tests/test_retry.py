"""Automatic retries (``retries=`` / ``Retry``): which failures are repeated, for which
methods, statuses with Retry-After, backoff, per-request override, async and cancellation."""
from __future__ import annotations

import asyncio
import io
import socket
import threading
import time

import pytest

import yumeclient
from yumeclient import AsyncSession, Retry, Session, SessionConfigurationError


class ScriptedServer:
    """HTTP/1.1 server that answers request n with ``script[n]`` (the last entry repeats):
    "eof" (read the request, close), "slow:<s>" (wait, then 200), "status:<code>[:<retry-after>]",
    "ok" (200 with the request body echoed). Every connection serves one request."""

    def __init__(self, *script: str):
        self.script, self.requests, self.bodies = list(script), 0, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.sock.close()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, body = data.split(b"\r\n\r\n", 1)
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value)
            while len(body) < length:
                body += conn.recv(65536)
            with self._lock:
                action = self.script[min(self.requests, len(self.script) - 1)]
                self.requests += 1
                self.bodies.append(body)
            kind, _, arg = action.partition(":")
            if kind == "eof":
                return
            if kind == "slow":
                time.sleep(float(arg))
                kind = "ok"
            status, extra = 200, b""
            if kind == "status":
                code, _, retry_after = arg.partition(":")
                status = int(code)
                if retry_after:
                    extra = b"Retry-After: " + retry_after.encode() + b"\r\n"
            reply = body if kind == "ok" else b""
            conn.sendall(b"HTTP/1.1 %d X\r\nConnection: close\r\nContent-Length: %d\r\n%s\r\n%s"
                         % (status, len(reply), extra, reply))
        except OSError:
            pass
        finally:
            conn.close()


@pytest.fixture
def scripted():
    servers = []

    def make(*script):
        srv = ScriptedServer(*script)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


@pytest.fixture(scope="module", autouse=True)
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")


FAST = Retry(total=3, backoff=0)


def test_connection_drops_are_repeated(scripted):
    srv = scripted("eof", "eof", "ok")
    with Session(timeout=5, retries=Retry(total=3, backoff=0)) as s:
        r = s.get(srv.url)
    assert r.status_code == 200 and r.attempts == 3 and srv.requests == 3


def test_retries_int_is_total(scripted):
    srv = scripted("eof", "ok")
    with Session(timeout=5, retries=2) as s:
        assert s.get(srv.url).attempts == 2


def test_gives_up_with_the_last_error(scripted):
    srv = scripted("eof")
    with Session(timeout=5, retries=Retry(total=2, backoff=0)) as s:
        with pytest.raises(yumeclient.ConnectionClosed) as info:
            s.get(srv.url)
    assert info.value.attempts == 3 and srv.requests == 3


def test_timeout_awaiting_headers_is_repeated(scripted):
    srv = scripted("slow:2", "ok")
    with Session(timeout=0.5, retries=Retry(total=1, backoff=0)) as s:
        r = s.get(srv.url)
    assert r.status_code == 200 and r.attempts == 2


def test_requests_without_retries_are_sent_once(scripted):
    srv = scripted("eof")
    with Session(timeout=5) as s:
        with pytest.raises(yumeclient.ConnectionClosed) as info:
            s.get(srv.url)
    assert info.value.attempts == 1 and srv.requests == 1


def test_post_is_not_repeated_once_sent(scripted):
    # the server may have processed it: only idempotent methods are repeated by default
    srv = scripted("eof")
    with Session(timeout=5, retries=FAST) as s:
        with pytest.raises(yumeclient.ConnectionClosed) as info:
            s.post(srv.url, data=b"x")
    assert info.value.attempts == 1 and srv.requests == 1


def test_every_method_with_methods_none(scripted):
    srv = scripted("eof", "ok")
    with Session(timeout=5, retries=Retry(total=2, backoff=0, methods=None)) as s:
        r = s.post(srv.url, data=b"payload")
    assert r.content == b"payload" and r.attempts == 2 and srv.bodies == [b"payload", b"payload"]


def test_connect_failures_are_repeated_for_every_method():
    # nothing was sent: safe for POST too
    with Session(timeout=5, retries=Retry(total=2, backoff=0)) as s:
        with pytest.raises(yumeclient.ConnectError) as info:
            s.post("http://127.0.0.1:9/", data=b"x")
    assert info.value.stage == "connect" and info.value.attempts == 3


def test_errors_that_are_not_retryable_are_raised_at_once(scripted):
    with Session(timeout=5, retries=FAST) as s:
        with pytest.raises(yumeclient.InvalidRequestError) as info:
            s.get("ftp://example.com/")
    assert info.value.attempts == 1


def test_statuses_and_retry_after(scripted):
    srv = scripted("status:503:0", "ok")
    with Session(timeout=5, retries=Retry(total=2, statuses={503})) as s:
        r = s.get(srv.url)
    assert r.status_code == 200 and r.attempts == 2

    srv = scripted("status:503")
    with Session(timeout=5, retries=Retry(total=2, backoff=0, statuses={503})) as s:
        r = s.get(srv.url)
    assert r.status_code == 503 and r.attempts == 3 and srv.requests == 3  # the last response is returned

    srv = scripted("status:503:120")
    with Session(timeout=5, retries=Retry(total=2, statuses={503}, max_backoff=5)) as s:
        start = time.monotonic()
        r = s.get(srv.url)
    assert r.status_code == 503 and r.attempts == 1 and time.monotonic() - start < 2  # longer than max_backoff

    srv = scripted("status:503")
    with Session(timeout=5, retries=FAST) as s:  # statuses are not repeated unless listed
        assert s.get(srv.url).attempts == 1


def test_backoff_grows(scripted):
    srv = scripted("eof")
    with Session(timeout=5, retries=Retry(total=2, backoff=0.2)) as s:
        start = time.monotonic()
        with pytest.raises(yumeclient.ConnectionClosed):
            s.get(srv.url)
    # pauses: 0.1-0.2 s, then 0.2-0.4 s
    assert 0.3 <= time.monotonic() - start < 2


def test_per_request_override(scripted):
    srv = scripted("eof", "ok")
    with Session(timeout=5) as s:
        assert s.get(srv.url, retries=Retry(total=1, backoff=0)).attempts == 2
    srv = scripted("eof", "ok")
    with Session(timeout=5, retries=FAST) as s:
        with pytest.raises(yumeclient.ConnectionClosed):
            s.get(srv.url, retries=0)


def test_one_shot_functions_accept_retries(scripted):
    srv = scripted("eof", "ok")
    assert yumeclient.get(srv.url, timeout=5, retries=Retry(total=1, backoff=0)).attempts == 2


def test_file_objects_are_sent_again(scripted):
    srv = scripted("eof", "ok")
    with Session(timeout=5, retries=Retry(total=1, backoff=0, methods=None)) as s:
        s.post(srv.url, files={"f": ("a.txt", io.BytesIO(b"file-content"))})
    assert len(srv.bodies) == 2 and all(b"file-content" in body for body in srv.bodies)


def test_async_session_retries(scripted):
    srv = scripted("eof", "eof", "ok")

    async def main():
        async with AsyncSession(timeout=5, retries=FAST) as s:
            return await s.get(srv.url)

    r = asyncio.run(main())
    assert r.status_code == 200 and r.attempts == 3


def test_async_cancel_during_backoff(scripted):
    srv = scripted("eof")

    async def main():
        async with AsyncSession(timeout=5, retries=Retry(total=5, backoff=10)) as s:
            task = asyncio.create_task(s.get(srv.url))
            await asyncio.sleep(0.5)
            task.cancel()
            start = time.monotonic()
            with pytest.raises(asyncio.CancelledError):
                await task
            return time.monotonic() - start

    assert asyncio.run(main()) < 1 and srv.requests == 1


def test_closing_the_session_stops_retrying(scripted):
    srv = scripted("eof")
    s = Session(timeout=5, retries=Retry(total=5, backoff=1))
    threading.Timer(0.3, s.close).start()
    start = time.monotonic()
    with pytest.raises(yumeclient.ConnectionClosed):
        s.get(srv.url)
    assert time.monotonic() - start < 2 and srv.requests == 1


@pytest.mark.parametrize("value, message", [
    (-1, "total must be an int >= 0"),
    (True, "retries must be an int or a yumeclient.Retry"),
    ("3", "retries must be an int or a yumeclient.Retry"),
])
def test_invalid_retries(value, message):
    with pytest.raises(SessionConfigurationError, match=message):
        Session(retries=value)


@pytest.mark.parametrize("kwargs, message", [
    ({"backoff": -1}, "backoff must be a number >= 0"),
    ({"methods": "GET"}, "methods must be a collection"),
    ({"statuses": 503}, "statuses must be a collection"),
    ({"statuses": {700}}, "is not an HTTP status code"),
])
def test_invalid_retry(kwargs, message):
    with pytest.raises(SessionConfigurationError, match=message):
        Retry(**kwargs)


def test_retries_is_fixed_for_the_session():
    with Session() as s:
        with pytest.raises(AttributeError, match="retries="):
            s.retries = 3


def test_retry_normalizes_methods():
    assert Retry(methods=["get", "post"]).methods == frozenset({"GET", "POST"})
    assert "PUT" in Retry().methods and "POST" not in Retry().methods


def test_async_statuses_and_streams(scripted):
    srv = scripted("status:503:0", "ok")

    async def main():
        async with AsyncSession(timeout=5, retries=Retry(total=2, statuses={503})) as s:
            r = await s.post(srv.url, data=b"x", retries=Retry(total=2, statuses={503}, methods=None))
            body = await r.aread()
            streamed = await s.get(srv.url, stream=True)
            return r.status_code, r.attempts, body, streamed.status_code

    assert asyncio.run(main()) == (200, 2, b"x", 200)
