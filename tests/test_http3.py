"""HTTP/3 parameters on the wire (needs aioquic for the local HTTP/3 server).

Chrome 146-152 / Brave 146 used to send only SETTINGS_H3_DATAGRAM: upstream defines their
profiles without HTTP/3 parameters. They now send what real Chrome sends
(tests/fixtures/chrome_157_wire.json).
"""
from __future__ import annotations

import asyncio
import datetime
import json
import os
import socket
import tempfile
import threading
import time
import warnings
from pathlib import Path

import pytest

aioquic = pytest.importorskip("aioquic")
from aioquic.asyncio import serve  # noqa: E402
from aioquic.asyncio.protocol import QuicConnectionProtocol  # noqa: E402
from aioquic.buffer import Buffer  # noqa: E402
from aioquic.h3.connection import H3_ALPN, H3Connection  # noqa: E402
from aioquic.h3.events import HeadersReceived  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived  # noqa: E402

import yumeclient  # noqa: E402
from yumeclient import Session  # noqa: E402

from test_protocol import H2Server, native  # noqa: E402,F401
from test_wire import _PEM  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "chrome_157_wire.json"
_GREASE = lambda v: v >= 0x21 and (v - 0x21) % 0x1F == 0  # noqa: E731


class H3Server:
    """aioquic HTTP/3 server on 127.0.0.1 (UDP only: protocol racing has nothing on TCP)."""

    def __init__(self, port: int = 0):
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))  # OSError here when the port is unusable
            self.port = probe.getsockname()[1]
        except OSError:
            os.unlink(self._pem)
            raise
        finally:
            probe.close()
        self.settings: list[list[int]] = []
        self.requests: list[list[tuple[str, str]]] = []
        self.delay = 0.0  # seconds before each response
        self.reset = False  # reset every request stream (H3_INTERNAL_ERROR) instead
        # (paths starting with /reset are always reset)
        # Windows' default proactor loop stops reading a UDP socket after its first
        # ConnectionResetError (ICMP port unreachable from a client that closed its
        # socket): the server would go deaf. The selector loop keeps reading.
        self._loop = asyncio.SelectorEventLoop()
        ready = threading.Event()
        threading.Thread(target=self._run, args=(ready,), daemon=True).start()
        assert ready.wait(10)

    def _run(self, ready):
        asyncio.set_event_loop(self._loop)
        cfg = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=False, max_datagram_frame_size=65536)
        cfg.load_cert_chain(self._pem, self._pem)
        server = self

        class Proto(QuicConnectionProtocol):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.h3, self.control = None, b""

            def quic_event_received(self, event):
                if isinstance(event, ProtocolNegotiated):
                    self.h3 = H3Connection(self._quic)
                if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 2 and not server.settings:
                    self.control += event.data
                    server._parse_control(self.control)
                if self.h3 is not None:
                    for ev in self.h3.handle_event(event):
                        if isinstance(ev, HeadersReceived):
                            server.requests.append([(k.decode(), v.decode()) for k, v in ev.headers])
                            if server.reset or dict(ev.headers)[b":path"].startswith(b"/reset"):
                                self._quic.reset_stream(ev.stream_id, 0x102)
                                self.transmit()
                            else:
                                server._loop.call_later(server.delay, self.respond, ev.stream_id)

            def respond(self, stream_id):
                self.h3.send_headers(stream_id, [(b":status", b"200")])
                self.h3.send_data(stream_id, b"ok", end_stream=True)
                self.transmit()

        self._loop.run_until_complete(serve("127.0.0.1", self.port, configuration=cfg, create_protocol=Proto))
        ready.set()
        self._loop.run_forever()

    def _parse_control(self, data: bytes) -> None:
        try:
            buf = Buffer(data=data)
            if buf.pull_uint_var() != 0 or buf.pull_uint_var() != 4:  # control stream, SETTINGS first
                return
            length = buf.pull_uint_var()
            body = Buffer(data=buf.pull_bytes(length))
            while not body.eof():
                self.settings.append([body.pull_uint_var(), body.pull_uint_var()])
        except Exception:  # incomplete: wait for more data
            self.settings.clear()

    def close(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        os.unlink(self._pem)


@pytest.fixture()
def h3():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    s = H3Server()
    yield s
    s.close()


def _get(h3, **options):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(verify=False, timeout=8, http_version="3", **options) as s:
            r = s.get(f"https://localhost:{h3.port}/")
    assert r.status_code == 200 and r.used_protocol == "HTTP/3.0", r.used_protocol
    return [["GREASE", "GREASE"] if _GREASE(k) else [k, v] for k, v in h3.settings], dict(h3.requests[0]), h3.requests[0]


@pytest.mark.parametrize("identifier", ["chrome_152", "chrome_146", "brave_146"])
def test_chromium_profiles_send_chrome_http3_settings(h3, identifier):
    real = json.loads(FIXTURE.read_text(encoding="utf-8"))["http3"]
    settings, headers, ordered = _get(h3, client_identifier=identifier)
    assert settings == real["settings"]
    assert headers.get("priority") == real["priority_header"] == "u=0, i"
    assert [k for k, _ in ordered if k.startswith(":")] == [k for k in real["header_order"] if k.startswith(":")]


def test_custom_ja3_with_chrome_fill_sends_chrome_http3_settings(h3):
    # no MLKEM group: protocol racing stays enabled for custom JA3 sessions
    ja3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
           "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-21,29-23-24,0")
    settings, _, _ = _get(h3, ja3_string=ja3)
    assert settings == json.loads(FIXTURE.read_text(encoding="utf-8"))["http3"]["settings"]


def test_none_removes_the_http3_priority_header(h3):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(verify=False, timeout=8, http_version="3", client_identifier="chrome_152") as s:
            r = s.get(f"https://localhost:{h3.port}/", headers={"priority": None, "accept-encoding": None})
    assert r.used_protocol == "HTTP/3.0"
    assert not {"priority", "accept-encoding"} & set(dict(h3.requests[0]))


def _servers_on_one_port():
    """An HTTP/2 (TCP) and an HTTP/3 (UDP) server on the same port number. A port free
    for UDP may be taken or reserved for TCP (Windows excluded port ranges), so try a
    few TCP ports."""
    for _ in range(20):
        h2 = H2Server()
        try:
            return h2, H3Server(port=h2.port)
        except OSError:
            h2.close()
    pytest.skip("no port usable for both TCP and UDP")


def test_racing_sends_a_request_once(native):
    # protocol racing (http_version="3") sent the request over HTTP/3 and, 300 ms later,
    # over HTTP/2 too: a POST reached the server twice whenever HTTP/3 answered slowly
    h2, h3 = _servers_on_one_port()
    h3.delay = 0.8
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=8, http_version="3") as s:
                r = s.post(f"https://localhost:{h3.port}/order", data=b"once")
            time.sleep(0.5)  # the old HTTP/2 attempt started after 300 ms
        assert r.status_code == 200 and r.used_protocol == "HTTP/3.0"
        assert len(h3.requests) == 1 and h2.streams == 0 and h2.connections == 0
    finally:
        h2.close()
        h3.close()


def test_racing_falls_back_to_http2_once(native):
    # nothing on UDP: the HTTP/3 attempt fails and HTTP/2 carries the request alone
    h2 = H2Server()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=8, http_version="3") as s:
                r = s.post(f"https://127.0.0.1:{h2.port}/order", data=b"once")
        assert r.status_code == 200 and r.used_protocol == "HTTP/2.0" and h2.streams == 1
    finally:
        h2.close()


def test_closed_http3_sessions_release_their_sockets(h3):
    # every HTTP/3 session left its UDP socket, QUIC connection and goroutines behind
    # (the racing transport that won was never cached nor closed)
    before = yumeclient._debugStats()["goroutines"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for _ in range(3):
            with Session(verify=False, timeout=8, http_version="3") as s:
                assert s.get(f"https://localhost:{h3.port}/").used_protocol == "HTTP/3.0"
    deadline = time.monotonic() + 3
    while yumeclient._debugStats()["goroutines"] > before + 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert yumeclient._debugStats()["goroutines"] <= before + 1


@pytest.fixture()
def bad(native):
    """An HTTP/3 server resetting every request: a failure that removes the session."""
    s = H3Server()
    s.reset = True
    yield s
    s.close()


def test_failed_request_leaves_other_requests_alone(h3):
    # a failed request removes its session: that closed the session's HTTP/3
    # connections under the requests still running on them (the GET below was cut
    # off, re-raced and reached the server twice)
    before = yumeclient._debugStats()["goroutines"]
    out = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(verify=False, timeout=10, http_version="3") as s:
            assert s.get(f"https://localhost:{h3.port}/warm").used_protocol == "HTTP/3.0"
            h3.delay = 1.5

            def slow():
                r = s.get(f"https://localhost:{h3.port}/slow")
                out["slow"] = (r.status_code, r.content)

            t = threading.Thread(target=slow)
            t.start()
            time.sleep(0.3)
            with pytest.raises(yumeclient.RequestError):
                s.post(f"https://localhost:{h3.port}/reset", data=b"x")
            t.join(10)
    assert out["slow"] == (200, b"ok")
    assert [dict(r)[":path"] for r in h3.requests] == ["/warm", "/slow", "/reset"]
    deadline = time.monotonic() + 3
    while yumeclient._debugStats()["goroutines"] > before + 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert yumeclient._debugStats()["goroutines"] <= before + 1


def test_redirect_survives_a_failed_sibling_request(bad):
    # the session of a failed request is closed once its other requests are done:
    # that was counted per hop, so a redirect being followed lost its session
    # between the hops ("http3: transport is closed")
    class Redirecting(H2Server):
        def _respond(self, s, stream):
            if self.streams == 2:
                time.sleep(1.0)
                # :status 302, location: /final (HPACK literals, static name indexes 8 and 46)
                s.sendall(self._frame(1, 5, stream, b"\x08\x03302\x0f\x1f\x06/final"))
            else:
                super()._respond(s, stream)

    srv = Redirecting()
    out = {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=10, http_version="3") as s:
                assert s.get(f"https://localhost:{srv.port}/warm").used_protocol == "HTTP/2.0"

                def follow():
                    try:
                        r = s.get(f"https://localhost:{srv.port}/r")
                        out["r"] = (r.status_code, [h.status_code for h in r.history], r.content)
                    except Exception as exc:  # noqa: BLE001 - reported by the assert below
                        out["r"] = exc

                t = threading.Thread(target=follow)
                t.start()
                time.sleep(0.3)
                with pytest.raises(yumeclient.RequestError):
                    s.post(f"https://localhost:{bad.port}/bad", data=b"x")
                t.join(10)
        assert out["r"] == (200, [302], b"ok")
    finally:
        srv.close()


def test_racing_recovers_when_http3_goes_silent(native):
    # a timeout on the remembered protocol kept it: with HTTP/3 packets dropped every
    # request timed out until QUIC's idle timeout; now the next request races again
    h2, h3 = _servers_on_one_port()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=1, http_version="3") as s:
                url = f"https://localhost:{h3.port}/"
                assert s.get(url).used_protocol == "HTTP/3.0"
                h3.close()  # the UDP socket stays open, nothing answers: a black hole
                with pytest.raises(yumeclient.Timeout):
                    s.get(url)
                t0 = time.monotonic()
                r = s.get(url)
        assert r.used_protocol == "HTTP/2.0" and time.monotonic() - t0 < 0.9
    finally:
        h2.close()


def test_concurrent_requests_with_failures_each_sent_once(bad):
    # failing requests remove the session while others run on it, new requests
    # rebuild it concurrently: every request still goes out exactly once and
    # nothing is left behind (old builds overwrote concurrently built sessions,
    # leaking their connections, and sent racing requests twice)
    h2, h3 = _servers_on_one_port()
    h3.delay = 0.05
    before = yumeclient._debugStats()["goroutines"]
    ok, errors = [], []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=10, http_version="3") as s:

                def send(i):
                    try:
                        r = s.post(f"https://localhost:{h3.port}/g{i}", data=b"x", stream=i % 3 == 0)
                        ok.append((r.status_code, r.content))
                        r.close()
                    except Exception as exc:  # noqa: BLE001 - reported by the assert below
                        errors.append(exc)

                def fail():
                    with pytest.raises(yumeclient.RequestError):
                        s.post(f"https://localhost:{bad.port}/bad", data=b"x")

                threads = []
                for i in range(80):
                    threads.append(threading.Thread(target=send, args=(i,)))
                    if i % 4 == 0:
                        threads.append(threading.Thread(target=fail))
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(20)
        assert errors == [] and ok == [(200, b"ok")] * 80
        sent = len([r for r in h3.requests if dict(r)[":path"].startswith("/g")])
        assert sent + h2.streams == 80
        deadline = time.monotonic() + 3
        while yumeclient._debugStats()["goroutines"] > before + 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert yumeclient._debugStats()["goroutines"] <= before + 1
    finally:
        h2.close()
        h3.close()


def test_invalid_header_rejected_before_sending(h3):
    # an invalid header value failed in the transport: the session lost its
    # connections and the protocol cache, and a GET was raced out again
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(verify=False, timeout=5, http_version="3") as s:
            url = f"https://localhost:{h3.port}/"
            first = s.get(url)
            for headers in ({"X-Bad": "a\x01b"}, {"X-Bad": "a\r\nInjected: 1"}, {"Bad Name": "v"}):
                with pytest.raises(yumeclient.InvalidRequestError):
                    s.get(url, headers=headers)
            second = s.get(url, headers={"X-Ok": "tab\tand caf\u00e9"})
    assert len(h3.requests) == 2
    assert second.used_protocol == "HTTP/3.0" and second.connection_info["connection_reused"]
    assert first.connection_info["local_address"] == second.connection_info["local_address"]


def test_http2_timeout_keeps_the_connection(native):
    # racing mode with HTTP/2 remembered: a slow response (timeout) is not a broken
    # protocol — the next request reuses the connection instead of racing again
    class Slow(H2Server):
        def _respond(self, s, stream):
            if self.streams == 2:
                time.sleep(1.5)
            super()._respond(s, stream)

    srv = Slow()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=5, http_version="3") as s:
                url = f"https://localhost:{srv.port}/"
                assert s.get(url).used_protocol == "HTTP/2.0"
                with pytest.raises(yumeclient.Timeout):
                    s.get(url, timeout=0.5)
                r = s.get(url)
        assert r.used_protocol == "HTTP/2.0" and r.connection_info["connection_reused"]
        assert srv.connections == 1
    finally:
        srv.close()


@pytest.mark.parametrize("headers", [{"Connection": "Upgrade", "Upgrade": "websocket"},
                                     {"Transfer-Encoding": "gzip"}])
def test_header_http2_refuses_keeps_the_connection(native, headers):
    # valid tokens HTTP/2 cannot carry: refused before sending, which cost the
    # remembered protocol its connection, re-raced the GET and dropped the session
    srv = H2Server()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=5, http_version="3") as s:
                url = f"https://localhost:{srv.port}/"
                assert s.get(url).used_protocol == "HTTP/2.0"
                with pytest.raises(yumeclient.InvalidRequestError):
                    s.get(url, headers=headers)
                r = s.get(url)
        assert r.used_protocol == "HTTP/2.0" and r.connection_info["connection_reused"]
        assert srv.connections == 1 and srv.streams == 2
    finally:
        srv.close()
