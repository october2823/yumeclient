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
        self.response_headers = [(b":status", b"200")]
        self.connections = 0
        self.uni: dict[int, bytes] = {}  # client unidirectional streams by ID
        self.reset = False  # reset every request stream (H3_INTERNAL_ERROR) instead
        self.fail = False  # close the connection with H3_GENERAL_PROTOCOL_ERROR on a request
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
                    server.connections += 1
                if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 2:
                    server.uni[event.stream_id] = server.uni.get(event.stream_id, b"") + event.data
                if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 2 and not server.settings:
                    # the control stream (type 0x00); QPACK streams may arrive first
                    data = server.uni[event.stream_id]
                    if data[:1] == b"\x00":
                        server._parse_control(data)
                if self.h3 is not None:
                    for ev in self.h3.handle_event(event):
                        if isinstance(ev, HeadersReceived):
                            server.requests.append([(k.decode(), v.decode()) for k, v in ev.headers])
                            if server.fail:
                                self._quic.close(error_code=0x101, reason_phrase="broken")
                                self.transmit()
                            elif server.reset or dict(ev.headers)[b":path"].startswith(b"/reset"):
                                self._quic.reset_stream(ev.stream_id, 0x102)
                                self.transmit()
                            else:
                                server._loop.call_later(server.delay, self.respond, ev.stream_id)

            def respond(self, stream_id):
                self.h3.send_headers(stream_id, list(server.response_headers))
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
    for _ in range(100):  # the control stream may arrive after the request stream
        if h3.settings:
            break
        time.sleep(0.01)
    return [["GREASE", "GREASE"] if _GREASE(k) else [k, v] for k, v in h3.settings], dict(h3.requests[0]), h3.requests[0]


@pytest.mark.parametrize("identifier", ["chrome_152", "chrome_146", "brave_146"])
def test_chromium_profiles_send_chrome_http3_settings(h3, identifier):
    real = json.loads(FIXTURE.read_text(encoding="utf-8"))["http3"]
    settings, headers, ordered = _get(h3, client_identifier=identifier)
    assert settings == real["settings"]
    assert headers.get("priority") == real["priority_header"] == "u=0, i"
    assert [k for k, _ in ordered if k.startswith(":")] == [k for k in real["header_order"] if k.startswith(":")]


def test_custom_ja3_with_chrome_fill_sends_chrome_http3_settings(h3):
    ja3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
           "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-21,29-23-24,0")
    settings, _, _ = _get(h3, ja3_string=ja3)
    assert settings == json.loads(FIXTURE.read_text(encoding="utf-8"))["http3"]["settings"]


@pytest.mark.parametrize("fill", [True, False])
def test_custom_ja3_with_mlkem_uses_http3(h3, fill):
    # X25519MLKEM768 (4588) in the JA3, as in every current Chrome: such sessions used to
    # stay on TCP without a word (the QUIC hello does not take the JA3's curves)
    ja3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
           "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037,4588-29-23-24,0")
    settings, _, _ = _get(h3, ja3_string=ja3, fill_custom_with_chrome_defaults=fill)
    if fill:
        assert settings == json.loads(FIXTURE.read_text(encoding="utf-8"))["http3"]["settings"]


def test_none_removes_the_http3_priority_header(h3):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(verify=False, timeout=8, http_version="3", client_identifier="chrome_152") as s:
            r = s.get(f"https://localhost:{h3.port}/", headers={"priority": None, "accept-encoding": None})
    assert r.used_protocol == "HTTP/3.0"
    assert not {"priority", "accept-encoding"} & set(dict(h3.requests[0]))


@pytest.mark.parametrize("identifier", ["chrome_144", "firefox_147"])
def test_responses_using_the_qpack_dynamic_table(h3, identifier):
    # The profiles announce the browsers' SETTINGS_QPACK_MAX_TABLE_CAPACITY, so a
    # server may refer to its dynamic table (aioquic does, so do Google's servers).
    # A static-only decoder failed every such response ("expected Required Insert
    # Count to be zero"), and each failure re-raced on a new connection.
    h3.response_headers = [(b":status", b"200"), (b"content-type", b"text/plain"),
                           (b"x-served-by", b"h3-test"), (b"cache-control", b"private, max-age=0")]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(client_identifier=identifier, verify=False, timeout=8, http_version="3") as s:
            for _ in range(4):
                r = s.get(f"https://localhost:{h3.port}/")
                assert r.status_code == 200 and r.used_protocol == "HTTP/3.0"
                assert r.headers["X-Served-By"] == ["h3-test"]
    assert h3.connections == 1
    # the decoder stream (type 0x03) acknowledged the field sections
    decoder = [data for data in h3.uni.values() if data[:1] == b"\x03"]
    assert decoder and len(decoder[0]) > 1


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


def test_broken_http3_falls_back_to_tcp(native):
    # HTTP/3 connected, then the server closed the connection with an HTTP/3 error:
    # the request failed, and so did every later one (each race won by HTTP/3 again).
    # Like Chrome: HTTP/3 is marked broken for the server, a GET goes again over TCP
    h2, h3 = _servers_on_one_port()
    try:
        h3.fail = True
        url = f"https://localhost:{h3.port}/"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=8, http_version="3") as s:
                r = s.get(url)
                assert r.status_code == 200 and r.used_protocol == "HTTP/2.0"
                assert len(h3.requests) == 1 and h2.streams == 1
                r = s.get(url)  # straight to TCP: no new QUIC connection
                assert r.used_protocol == "HTTP/2.0" and h3.connections == 1
            with Session(verify=False, timeout=8, http_version="3") as s:
                # a POST may have been processed: not sent again, but HTTP/3 is broken
                with pytest.raises(yumeclient.RequestError):
                    s.post(url, data=b"once")
                assert s.post(url, data=b"twice").used_protocol == "HTTP/2.0"
        assert len(h3.requests) == 2 and h2.streams == 3
    finally:
        h2.close()
        h3.close()


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


def test_http3_read_timeout(h3):
    # stage timers were off for HTTP/3: read=0.5 waited for the whole response (2 s)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(verify=False, http_version="3",
                     timeout=yumeclient.TimeoutConfig(total=10, read=0.5)) as s:
            url = f"https://localhost:{h3.port}/"
            assert s.get(url).used_protocol == "HTTP/3.0"
            h3.delay = 2
            t0 = time.monotonic()
            with pytest.raises(yumeclient.ReadTimeout) as err:
                s.get(url)
    assert err.value.stage == "read" and time.monotonic() - t0 < 1.5


def test_http3_connect_timeout(native):
    # nothing answers on UDP and nothing listens on TCP: before, ConnectError after
    # QUIC's 5 s handshake timeout instead of connect=0.5
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, http_version="3",
                         timeout=yumeclient.TimeoutConfig(total=10, connect=0.5)) as s:
                t0 = time.monotonic()
                with pytest.raises(yumeclient.ConnectTimeout) as err:
                    s.get(f"https://localhost:{udp.getsockname()[1]}/")
        assert err.value.stage == "connect" and time.monotonic() - t0 < 1.5
    finally:
        udp.close()


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


# --- adversarial servers (raw HTTP/3) -------------------------------------------------

def _raw_get(respond, on_conn=None, **options):
    from h3raw import RawH3Server
    srv = RawH3Server(respond, on_conn)
    t0 = time.monotonic()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, http_version="3", **options) as s:
                try:
                    return s.get(f"https://127.0.0.1:{srv.port}/"), time.monotonic() - t0, srv
                except yumeclient.RequestError as exc:
                    return exc, time.monotonic() - t0, srv
    finally:
        srv.close()


@pytest.mark.parametrize("identifier", ["chrome_144", "firefox_147"])
def test_http3_response_header_limit_is_enforced(native, identifier):
    # the fingerprinted profiles turned the limit off: a HEADERS frame claiming 2^40
    # bytes made the client allocate them (out of memory, the process died), a 60 KB
    # dynamic table entry referenced 2000 times became 120 MB of headers
    from h3raw import STATUS_200, frame, qint, qstr, varint

    def huge(proto, sid):
        proto._quic.send_stream_data(sid, varint(1) + varint(1 << 40), end_stream=False)

    result, _, _ = _raw_get(huge, client_identifier=identifier, timeout=10)
    assert isinstance(result, yumeclient.RequestError) and "too large" in str(result)

    def on_conn(proto):
        proto._quic.send_stream_data(proto.enc, qint(5, 0x20, 65536) + qstr(5, 0x40, b"x-amp") + qstr(7, 0x00, b"a" * 60000))

    def amplify(proto, sid):
        block = qint(8, 0, 2) + qint(7, 0, 0) + STATUS_200 + bytes([0x80]) * 2000  # RIC 1, 2000 refs
        proto._quic.send_stream_data(sid, frame(1, block) + frame(0, b"ok"), end_stream=True)

    result, _, _ = _raw_get(amplify, on_conn, client_identifier=identifier, timeout=10)
    assert isinstance(result, yumeclient.RequestError) and "too large" in str(result)


def test_http3_blocked_trailers_respect_the_timeout(native):
    # trailers referring to a dynamic table entry that never comes waited for it past
    # every timeout (the connection kept alive by the server)
    from h3raw import STATUS_200, frame, qint

    def on_conn(proto):
        proto._quic.send_stream_data(proto.enc, qint(5, 0x20, 4096))  # capacity, no inserts

    def respond(proto, sid):
        trailers = qint(8, 0, 2) + qint(7, 0, 0) + bytes([0x80])  # RIC 1: blocked forever
        proto._quic.send_stream_data(sid, frame(1, b"\x00\x00" + STATUS_200) + frame(0, b"ok") + frame(1, trailers))

    result, elapsed, _ = _raw_get(respond, on_conn, client_identifier="chrome_144", timeout=2)
    assert isinstance(result, yumeclient.Timeout) and elapsed < 4


def test_server_forgetting_a_connection_does_not_break_http3(native):
    # the server lost the pooled QUIC connection: the next request ran into QUIC's idle
    # timeout and marked HTTP/3 broken for the server (5 minutes of TCP and up to 2 days);
    # like Chrome, a new QUIC connection is the cure
    from h3raw import STATUS_200, RawH3Server, frame

    def respond(proto, sid):
        proto._quic.send_stream_data(sid, frame(1, b"\x00\x00" + STATUS_200) + frame(0, b"ok"), end_stream=True)

    srv = RawH3Server(respond, idle_timeout=2)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=15, http_version="3") as s:
                url = f"https://127.0.0.1:{srv.port}/"
                assert s.get(url).used_protocol == "HTTP/3.0"
                srv.forget_connections()
                time.sleep(0.5)
                assert s.get(url).used_protocol == "HTTP/3.0"  # after the idle timeout, a new connection
                assert s.get(url).used_protocol == "HTTP/3.0" and srv.connections == 2
    finally:
        srv.close()


def test_short_server_idle_timeout_is_honoured(native):
    # the server's max_idle_timeout was raised to at least 5 s: after the server had
    # dropped an idle connection, the next request waited up to 5 s on it
    from h3raw import RawH3Server, STATUS_200, frame

    def respond(proto, sid):
        proto._quic.send_stream_data(sid, frame(1, bytes(2) + STATUS_200) + frame(0, b"ok"), end_stream=True)

    srv = RawH3Server(respond, idle_timeout=1)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=15, http_version="3") as s:
                url = f"https://127.0.0.1:{srv.port}/"
                assert s.get(url).used_protocol == "HTTP/3.0"
                time.sleep(1.6)
                t0 = time.monotonic()
                assert s.get(url).used_protocol == "HTTP/3.0"
                assert time.monotonic() - t0 < 1.5 and srv.connections == 2
    finally:
        srv.close()


def test_peer_withholding_stream_credit_does_not_hold_requests(native):
    # the server grants our unidirectional streams 40 bytes and never more, and every
    # response refers to the dynamic table (a Section Acknowledgment each): the
    # acknowledgments and Chrome's PRIORITY_UPDATEs were written on the request path
    # and blocked it past every timeout once the credit ran out
    from h3raw import STATUS_200, RawH3Server, frame, qint, qstr

    def on_init(proto):
        quic = proto._quic
        quic._local_max_stream_data_uni = 40
        limits = quic._write_stream_limits
        quic._write_stream_limits = lambda builder, space, stream: (
            None if stream.stream_id % 4 == 2 else limits(builder=builder, space=space, stream=stream))

    def on_conn(proto):
        proto._quic.send_stream_data(proto.enc, qint(5, 0x20, 4096) + qstr(5, 0x40, b"x-a") + qstr(7, 0, b"1"))

    def respond(proto, sid):
        block = qint(8, 0, 2) + qint(7, 0, 0) + STATUS_200 + bytes([0x80])  # RIC 1: the dynamic entry
        proto._quic.send_stream_data(sid, frame(1, block) + frame(0, b"ok"), end_stream=True)

    srv = RawH3Server(respond, on_conn, on_init=on_init)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for identifier in ("chrome_144", "firefox_147"):
                with Session(client_identifier=identifier, verify=False, http_version="3", timeout=3) as s:
                    t0 = time.monotonic()
                    for i in range(250):
                        r = s.get(f"https://127.0.0.1:{srv.port}/{i}")
                        assert r.used_protocol == "HTTP/3.0" and r.headers["X-A"] == ["1"]
                    assert time.monotonic() - t0 < 20
    finally:
        srv.close()


@pytest.mark.parametrize("close", ["quic_no_error", "quic_application_error", "app_zero", "app_reserved", "h3_no_error"])
def test_graceful_close_does_not_break_http3(native, close):
    # a server closing the connection without an error (QUIC NO_ERROR, application code
    # 0, a reserved or unknown code - RFC 9114 8.1 equates those with H3_NO_ERROR)
    # marked HTTP/3 broken: the session went over TCP for 5 minutes and more
    from h3raw import STATUS_200, RawH3Server, frame
    count = [0]

    def respond(proto, sid):
        count[0] += 1
        if count[0] == 2:
            quic = proto._quic
            if close == "quic_no_error":
                quic.close(error_code=0x0, frame_type=0, reason_phrase="bye")
            elif close == "quic_application_error":
                # an application close during the handshake travels as a transport
                # APPLICATION_ERROR (RFC 9000 10.2.3): its code is unknown
                quic.close(error_code=0xC, frame_type=0, reason_phrase="bye")
            else:
                quic.close(error_code={"app_zero": 0x0, "app_reserved": 0x21, "h3_no_error": 0x100}[close], reason_phrase="bye")
            return
        proto._quic.send_stream_data(sid, frame(1, bytes(2) + STATUS_200) + frame(0, b"ok"), end_stream=True)

    for _ in range(20):
        h2 = H2Server()
        try:
            srv = RawH3Server(respond, port=h2.port)
            break
        except OSError:
            h2.close()
    else:
        pytest.skip("no TCP+UDP port pair")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(verify=False, timeout=10, http_version="3") as s:
                protocols = [s.get(f"https://localhost:{srv.port}/{i}").used_protocol for i in range(4)]
        assert protocols == ["HTTP/3.0"] * 4 and h2.streams == 0, protocols
    finally:
        h2.close()
        srv.close()


def test_aborted_response_cancels_its_qpack_stream(native):
    # a response abandoned before its end (a timeout while reading the body) still
    # pinned the encoder's dynamic table entries: no Stream Cancellation (RFC 9204 4.4.2)
    from h3raw import STATUS_200, RawH3Server, frame, qint, qstr, varint

    def on_conn(proto):
        proto._quic.send_stream_data(proto.enc, qint(5, 0x20, 4096) + qstr(5, 0x40, b"x-a") + qstr(7, 0, b"1"))

    def respond(proto, sid):
        block = qint(8, 0, 2) + qint(7, 0, 0) + STATUS_200 + bytes([0x80])
        proto._quic.send_stream_data(sid, frame(1, block) + varint(0) + varint(100) + b"x", end_stream=False)

    srv = RawH3Server(respond, on_conn)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(client_identifier="chrome_144", verify=False, http_version="3", timeout=1) as s:
                with pytest.raises(yumeclient.Timeout):
                    s.get(f"https://127.0.0.1:{srv.port}/")
                deadline = time.monotonic() + 3
                decoder = b""
                while time.monotonic() < deadline:
                    decoder = next((v for v in srv.uni.values() if v[:1] == b"\x03"), b"")
                    if b"\x40" in decoder[1:]:
                        break
                    time.sleep(0.05)
        assert decoder[1:] == b"\x80\x40", decoder  # Section Ack, then Stream Cancellation of stream 0
    finally:
        srv.close()


@pytest.mark.parametrize("identifier", ["chrome_144", "firefox_147"])
def test_fully_read_deflate_response_is_not_cancelled(native, identifier):
    # a deflate body ends with its zlib trailer: when the stream's end (FIN) came after
    # the last DATA frame, Close found the stream unfinished and sent STOP_SENDING and a
    # QPACK Stream Cancellation for a response read to the end - no browser does that
    import zlib

    from aioquic.quic.events import StopSendingReceived, StreamReset
    from h3raw import STATUS_200, RawH3Server, frame, literal
    body = b"hello yumeclient " * 200
    data = zlib.compress(body)
    events = []

    def on_event(proto, ev):
        if isinstance(ev, (StopSendingReceived, StreamReset)):
            events.append(ev)

    def respond(proto, sid):
        quic = proto._quic
        fields = bytes(2) + STATUS_200 + literal(b"content-encoding", b"deflate") + \
            literal(b"content-length", str(len(data)).encode())
        quic.send_stream_data(sid, frame(1, fields) + frame(0, data), end_stream=False)

        def fin():
            quic.send_stream_data(sid, b"", end_stream=True)
            proto.transmit()
        proto._loop.call_later(0.06, fin)

    srv = RawH3Server(respond, on_event=on_event)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(client_identifier=identifier, verify=False, http_version="3", timeout=5) as s:
                for i in range(2):
                    assert s.get(f"https://127.0.0.1:{srv.port}/{i}").content == body
                time.sleep(0.5)
        decoder = next((v for v in srv.uni.values() if v[:1] == b"\x03"), b"")
        assert events == [] and decoder[1:] == b"", (events, decoder)
    finally:
        srv.close()


def test_frames_keep_their_order_across_streams(native):
    # queued writes (0.8.0) let a request's HEADERS overtake its PRIORITY_UPDATE
    # (Chromium writes the PRIORITY_UPDATE first) and Firefox's QPACK stream types
    # overtake each other and the SETTINGS
    from aioquic.quic.events import StreamDataReceived
    from h3raw import STATUS_200, RawH3Server, frame, varint
    log = []

    def on_event(proto, ev):
        if isinstance(ev, StreamDataReceived) and ev.data:
            log.append((ev.stream_id, ev.data))

    def respond(proto, sid):
        proto._quic.send_stream_data(sid, frame(1, bytes(2) + STATUS_200) + frame(0, b"ok"), end_stream=True)

    srv = RawH3Server(respond, on_event=on_event)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for identifier in ("chrome_144", "firefox_147"):
                log.clear()
                for attempt in range(3):
                    with Session(client_identifier=identifier, verify=False, http_version="3", timeout=5) as s:
                        for i in range(3):
                            s.get(f"https://127.0.0.1:{srv.port}/{i}")
                    time.sleep(0.2)
                    if identifier == "chrome_144":
                        control, requests = b"", set()
                        for sid, data in list(log):
                            if sid == 2:
                                control += data
                            elif sid % 4 == 0 and sid not in requests:
                                requests.add(sid)  # its HEADERS: the PRIORITY_UPDATE came first
                                assert frame(0xF0700, varint(sid) + b"u=0, i") in control, (sid, control.hex())
                        assert len(requests) == 3
                    else:
                        firsts = []
                        for sid, _ in log:
                            if sid in (2, 6, 10) and sid not in firsts:
                                firsts.append(sid)
                        assert firsts[:3] == [6, 10, 2], firsts  # encoder, decoder, control
                    log.clear()
    finally:
        srv.close()


def test_tiny_server_idle_timeout_does_not_flood_pings(native):
    # the peer's idle timeout is honoured as announced (no 5 s floor) and profiles without
    # a QUIC fingerprint keep alive at half of it: 1 ms meant a PING every PTO
    from h3raw import STATUS_200, RawH3Server, frame

    def respond(proto, sid):
        proto._quic.send_stream_data(sid, frame(1, bytes(2) + STATUS_200) + frame(0, b"ok"), end_stream=True)

    srv = RawH3Server(respond, idle_timeout=0.001)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(client_identifier="safari_16_0", verify=False, http_version="3", timeout=5) as s:
                assert s.get(f"https://127.0.0.1:{srv.port}/").used_protocol == "HTTP/3.0"
                before = srv.datagrams
                time.sleep(1.5)
                idle = srv.datagrams - before
                assert s.get(f"https://127.0.0.1:{srv.port}/").used_protocol == "HTTP/3.0"
        assert idle <= 6, idle
    finally:
        srv.close()


def test_udp_proxy_carries_quic_and_proxy_tcp(native):
    # udp_proxy used to replace the TCP proxy as well, and http_version="3" behind an
    # HTTP proxy was refused even with a SOCKS5 udp_proxy for the QUIC part
    from socks5udp import Socks5
    from test_diagnostics import ConnectProxy

    h2, h3 = _servers_on_one_port()
    tcp, udp = ConnectProxy(), Socks5()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Session(client_identifier="chrome_144", verify=False, timeout=8, http_version="3",
                         proxy=f"http://127.0.0.1:{tcp.port}", udp_proxy=udp.url) as s:
                assert s.get(f"https://127.0.0.1:{h3.port}/").used_protocol == "HTTP/3.0"
            assert ("udp", "127.0.0.1", h3.port) in udp.log
            with Session(client_identifier="chrome_144", verify=False, timeout=8,
                         proxy=f"http://127.0.0.1:{tcp.port}", udp_proxy=udp.url) as s:
                assert s.get(f"https://127.0.0.1:{h2.port}/").used_protocol == "HTTP/2.0"
        assert tcp.seen == [f"CONNECT 127.0.0.1:{h2.port} HTTP/1.1"]
        assert not [entry for entry in udp.log if entry[0] == "connect"]
        with pytest.raises(yumeclient.SessionConfigurationError, match="udp_proxy"):
            Session(udp_proxy="udp://127.0.0.1:1")
        with pytest.raises(yumeclient.SessionConfigurationError, match="QUIC needs UDP"):
            Session(http_version="3", proxy="http://127.0.0.1:1")
    finally:
        tcp.sock.close(); udp.close(); h2.close(); h3.close()
