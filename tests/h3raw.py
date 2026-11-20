"""Raw HTTP/3 server for adversarial responses: aioquic does QUIC, the HTTP/3 and QPACK
bytes are written by hand. respond(proto, stream_id) is called once per request stream."""
from __future__ import annotations

import asyncio
import os
import socket
import tempfile
import threading

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import encode_uint_var
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived

from test_wire import _PEM

STATUS_200 = bytes([0xC0 | 25])  # QPACK: indexed static field line, :status 200


def varint(v: int) -> bytes:
    return encode_uint_var(v)


def frame(kind: int, payload: bytes) -> bytes:
    return varint(kind) + varint(len(payload)) + payload


def qint(prefix_bits: int, first_bits: int, v: int) -> bytes:
    """QPACK prefixed integer; first_bits: the pattern bits above the prefix."""
    mask = (1 << prefix_bits) - 1
    if v < mask:
        return bytes([first_bits | v])
    out = [first_bits | mask]
    v -= mask
    while v >= 128:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def qstr(prefix_bits: int, first_bits: int, s: bytes) -> bytes:
    return qint(prefix_bits, first_bits, len(s)) + s


def literal(name: bytes, value: bytes) -> bytes:
    """Literal field line with a literal name."""
    return qstr(3, 0x20, name) + qstr(7, 0x00, value)


class RawH3Server:
    def __init__(self, respond, on_conn=None, idle_timeout: float = 60.0, port: int = 0, on_init=None,
                 on_event=None):
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", port))
        self.port = probe.getsockname()[1]
        probe.close()
        self.respond, self.on_conn, self.idle_timeout = respond, on_conn, idle_timeout
        self.on_init = on_init  # called with every new connection's protocol
        self.on_event = on_event  # called with every QUIC event (protocol, event)
        self.datagrams = 0  # datagrams received from clients
        self.requests = 0
        self.connections = 0
        self.uni: dict[int, bytes] = {}
        self.protocols: list = []
        self.deaf: set = set()  # connections whose datagrams are dropped (forget_connections)
        self.loop = asyncio.SelectorEventLoop()
        ready = threading.Event()
        threading.Thread(target=self._run, args=(ready,), daemon=True).start()
        assert ready.wait(10)

    def _run(self, ready):
        asyncio.set_event_loop(self.loop)
        cfg = QuicConfiguration(alpn_protocols=["h3"], is_client=False, idle_timeout=self.idle_timeout)
        cfg.load_cert_chain(self._pem, self._pem)
        srv = self

        class Proto(QuicConnectionProtocol):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.seen, self.enc = set(), None
                srv.protocols.append(self)
                if srv.on_init:
                    srv.on_init(self)

            def datagram_received(self, data, addr):
                srv.datagrams += 1
                if self not in srv.deaf:
                    super().datagram_received(data, addr)

            def quic_event_received(self, ev):
                if srv.on_event:
                    srv.on_event(self, ev)
                if isinstance(ev, ProtocolNegotiated):
                    srv.connections += 1
                    control = self._quic.get_next_available_stream_id(is_unidirectional=True)
                    self._quic.send_stream_data(control, varint(0) + frame(4, b""))  # empty SETTINGS
                    self.enc = self._quic.get_next_available_stream_id(is_unidirectional=True)
                    self._quic.send_stream_data(self.enc, varint(2))  # QPACK encoder stream
                    if srv.on_conn:
                        srv.on_conn(self)
                    self.transmit()
                if isinstance(ev, StreamDataReceived):
                    if ev.stream_id % 4 == 2:
                        srv.uni[ev.stream_id] = srv.uni.get(ev.stream_id, b"") + ev.data
                    elif ev.stream_id % 4 == 0 and ev.stream_id not in self.seen:
                        self.seen.add(ev.stream_id)
                        srv.requests += 1
                        srv.respond(self, ev.stream_id)
                        self.transmit()

        self.loop.run_until_complete(serve("127.0.0.1", self.port, configuration=cfg, create_protocol=Proto))
        ready.set()
        self.loop.run_forever()

    def forget_connections(self):
        """The server loses its connections without a word (a restart behind the same
        address, a NAT rebinding): their packets are dropped from now on."""
        self.deaf = set(self.protocols)

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        try:
            os.unlink(self._pem)
        except OSError:
            pass
