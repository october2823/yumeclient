"""Record the full HTTP/3 fingerprint a client sends to a local QUIC server.

Layers recorded per connection:
  quic   - version, connection ID lengths, token, Initial datagram sizes and the frame
           layout of every client Initial packet (decrypted: Initial keys derive from
           the client's first destination connection ID, RFC 9001 5.2)
  tls    - the ClientHello carried in CRYPTO frames (ciphers, extension order, groups,
           key shares, ALPN, JA3, JA4 with the QUIC "q" prefix)
  tp     - QUIC transport parameters in wire order (id, value)
  h3     - unidirectional streams (type, frames; SETTINGS ids/values in order),
           request streams (frame layout, header list in wire order)

Usage:
  python scripts/h3_capture.py chrome --exe PATH [--headless new|old|none] --out FILE
  python scripts/h3_capture.py firefox --exe PATH --out FILE
  python scripts/h3_capture.py yumeclient --profile chrome_144 --out FILE
  python scripts/h3_capture.py serve [--port N]       # run until Ctrl+C, print captures
  python scripts/h3_capture.py diff A.json B.json     # compare two captures

Needs aioquic (pip install aioquic). Loopback only.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.packet import QuicProtocolVersion

HOST = "localhost"
VERSION_2 = int(QuicProtocolVersion.VERSION_2)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _varint(data: bytes, p: int) -> tuple[int, int]:
    first = data[p]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | data[p + i]
    return v, p + n


def _tls_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _quic_grease(v: int) -> bool:
    # transport parameters, H3 settings / frame types / stream types: 0x1f * N + 0x21
    # (H3) or 31 * N + 27 (transport parameters)
    return v >= 0x21 and (v - 0x21) % 0x1F == 0


def _tp_grease(v: int) -> bool:
    return v >= 27 and (v - 27) % 31 == 0


def _u16s(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b) - 1, 2)]


TP_NAMES = {
    0x00: "original_destination_connection_id", 0x01: "max_idle_timeout",
    0x02: "stateless_reset_token", 0x03: "max_udp_payload_size", 0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local", 0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni", 0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni", 0x0A: "ack_delay_exponent", 0x0B: "max_ack_delay",
    0x0C: "disable_active_migration", 0x0D: "preferred_address",
    0x0E: "active_connection_id_limit", 0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id", 0x11: "version_information",
    0x20: "max_datagram_frame_size", 0x2AB2: "grease_quic_bit", 0x1D: "reset_stream_at",
    0x3127: "google_initial_rtt", 0x3128: "google_connection_options",
    0x3129: "google_user_agent", 0x4752: "google_quic_version",
    0xFF04DE1B: "min_ack_delay", 0xFF73DB: "version_information_draft",
}
TP_INT = {0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0E, 0x20, 0x3127,
          0xFF04DE1B}
TP_RANDOM = {0x0F, 0x00, 0x02, 0x10}  # connection IDs / tokens: only their length is stable

H3_SETTING_NAMES = {0x01: "QPACK_MAX_TABLE_CAPACITY", 0x06: "MAX_FIELD_SECTION_SIZE",
                    0x07: "QPACK_BLOCKED_STREAMS", 0x08: "ENABLE_CONNECT_PROTOCOL",
                    0x33: "H3_DATAGRAM", 0x2B603742: "ENABLE_WEBTRANSPORT",
                    0xC671706A: "WEBTRANSPORT_MAX_SESSIONS"}
H3_FRAME_NAMES = {0x00: "DATA", 0x01: "HEADERS", 0x03: "CANCEL_PUSH", 0x04: "SETTINGS",
                  0x05: "PUSH_PROMISE", 0x07: "GOAWAY", 0x0D: "MAX_PUSH_ID",
                  0xF0700: "PRIORITY_UPDATE", 0xF0701: "PRIORITY_UPDATE_PUSH"}
H3_STREAM_NAMES = {0x00: "control", 0x01: "push", 0x02: "qpack_encoder", 0x03: "qpack_decoder"}


def parse_client_hello(hs: bytes) -> dict:
    """hs: the handshake message (type 1, 3-byte length, body)."""
    assert hs[0] == 1, "not a ClientHello"
    hs_len = int.from_bytes(hs[1:4], "big")
    b = hs[4:4 + hs_len]
    legacy = int.from_bytes(b[0:2], "big")
    p = 34
    sid_len = b[p]
    p += 1 + sid_len
    cl = int.from_bytes(b[p:p + 2], "big"); p += 2
    ciphers = _u16s(b[p:p + cl]); p += cl
    p += 1 + b[p]
    el = int.from_bytes(b[p:p + 2], "big"); p += 2
    end = p + el
    exts: list[tuple[int, bytes]] = []
    while p < end:
        t = int.from_bytes(b[p:p + 2], "big"); n = int.from_bytes(b[p + 2:p + 4], "big")
        exts.append((t, b[p + 4:p + 4 + n])); p += 4 + n
    e = dict(exts)
    groups = _u16s(e[10][2:]) if 10 in e else []
    sig = _u16s(e[13][2:]) if 13 in e else []
    versions = _u16s(e[43][1:]) if 43 in e else [legacy]
    key_share = []
    if 51 in e:
        d = e[51][2:]; q = 0
        while q < len(d):
            g = int.from_bytes(d[q:q + 2], "big"); n = int.from_bytes(d[q + 2:q + 4], "big")
            key_share.append(["GREASE" if _tls_grease(g) else g, n]); q += 4 + n
    alpn_list = []
    if 16 in e:
        d = e[16]; q = 2
        while q < len(d):
            alpn_list.append(d[q + 1:q + 1 + d[q]].decode(errors="replace")); q += 1 + d[q]
    alpn = alpn_list[0] if alpn_list else ""
    order = [t for t, _ in exts]
    norm = lambda vs: ["GREASE" if _tls_grease(v) else v for v in vs]  # noqa: E731
    cs = sorted(c for c in ciphers if not _tls_grease(c))
    es = [t for t in order if not _tls_grease(t)]
    ver = {0x0304: "13", 0x0303: "12"}.get(max(v for v in versions if not _tls_grease(v)), "00")
    ext_in = ",".join(f"{t:04x}" for t in sorted(t for t in es if t not in (0, 16)))
    sig_ja4 = [s for s in sig if not _tls_grease(s)]
    if sig_ja4:
        ext_in += "_" + ",".join(f"{s:04x}" for s in sig_ja4)
    head = f"q{ver}{'d' if 0 in e else 'i'}{len(cs):02d}{len(es):02d}{(alpn[0] + alpn[-1]) if alpn else '00'}"
    ja4 = (f"{head}_{hashlib.sha256(','.join(f'{c:04x}' for c in cs).encode()).hexdigest()[:12]}_"
           f"{hashlib.sha256(ext_in.encode()).hexdigest()[:12]}")
    ja4_r = f"{head}_" + ",".join(f"{c:04x}" for c in cs) + "_" + ext_in
    ja3 = ",".join([str(legacy), "-".join(str(c) for c in ciphers if not _tls_grease(c)),
                    "-".join(str(t) for t in es),
                    "-".join(str(g) for g in groups if not _tls_grease(g)), ""])
    other = {}
    for t, v in exts:
        if t in (10, 13, 16, 43, 51, 57, 0xFFA5, 0, 41, 21):
            continue
        random_data = t in (65037, 0xFE0D) or _tls_grease(t)  # ECH GREASE payload is random
        other["GREASE" if _tls_grease(t) else str(t)] = f"<{len(v)} bytes>" if random_data else v.hex()
    tp_raw = e.get(57, e.get(0xFFA5))
    return {"hs_len": hs_len, "legacy_version": legacy, "session_id_len": sid_len,
            "ciphers": norm(ciphers), "extensions": norm(order), "groups": norm(groups),
            "signature_algorithms": norm(sig), "versions": norm(versions), "key_share": key_share,
            "alpn": alpn_list, "psk": 41 in e, "padding_len": len(e[21]) if 21 in e else None,
            "ja3": ja3, "ja3_md5": hashlib.md5(ja3.encode()).hexdigest(), "ja4": ja4, "ja4_r": ja4_r,
            "extension_data": other, "tp_extension": 57 if 57 in e else (0xFFA5 if 0xFFA5 in e else None),
            "_tp_raw": tp_raw, "raw_hello": hs[:4 + hs_len].hex()}


def parse_transport_parameters(raw: bytes) -> list[dict]:
    out = []
    p = 0
    while p < len(raw):
        tid, p = _varint(raw, p)
        n, p = _varint(raw, p)
        val = raw[p:p + n]; p += n
        item: dict = {"id": "GREASE" if _tp_grease(tid) else tid,
                      "name": "grease" if _tp_grease(tid) else TP_NAMES.get(tid, f"0x{tid:x}"),
                      "len": n}
        if tid in TP_INT and n:
            item["value"] = _varint(val, 0)[0]
        elif tid in TP_RANDOM or _tp_grease(tid):
            pass  # random per connection
        elif tid == 0x11 and n >= 4:
            item["value"] = [f"0x{int.from_bytes(val[i:i + 4], 'big'):08x}" for i in range(0, n, 4)]
        elif n:
            item["value"] = val.hex()
        out.append(item)
    return out


def parse_h3_frames(data: bytes) -> list[dict]:
    frames = []
    p = 0
    while p < len(data):
        try:
            ftype, q = _varint(data, p)
            n, q = _varint(data, q)
        except IndexError:
            frames.append({"type": "TRUNCATED"}); break
        payload = data[q:q + n]
        if q + n > len(data):
            frames.append({"type": H3_FRAME_NAMES.get(ftype, f"0x{ftype:x}"), "truncated": True}); break
        f: dict = {"type": "GREASE" if _quic_grease(ftype) else H3_FRAME_NAMES.get(ftype, f"0x{ftype:x}"),
                   "len": n}
        if ftype == 0x04:
            settings = []; r = 0
            while r < n:
                sid, r = _varint(payload, r); val, r = _varint(payload, r)
                if _quic_grease(sid):
                    settings.append(["GREASE", "GREASE" if val else 0])
                else:
                    settings.append([H3_SETTING_NAMES.get(sid, f"0x{sid:x}"), val])
            f["settings"] = settings
        elif ftype == 0xF0700:
            r = 0
            elem, r = _varint(payload, r)
            f["element"] = elem
            f["value"] = payload[r:].decode(errors="replace")
        elif ftype == 0x01:
            f["qpack_prefix"] = payload[:2].hex()
        frames.append(f)
        p = q + n
    return frames


# ---------------------------------------------------------------------------
# capture state
# ---------------------------------------------------------------------------

class ConnCapture:
    def __init__(self, dcid: bytes, version: int, addr):
        self.addr = addr
        self.odcid = dcid
        self.version = version
        self.pair = CryptoPair()
        self.pair.setup_initial(cid=dcid, is_client=False, version=version)
        self.next_pn = 0
        self.packets: list[dict] = []
        self.datagrams: list[int] = []
        self.trailers: list[dict] = []
        self.crypto: dict[int, bytes] = {}
        self.hello: dict | None = None
        self.tp: list[dict] | None = None
        self.scid_len = None
        self.token_len = None
        self.streams: dict[int, bytearray] = {}
        self.stream_order: list[int] = []
        self.requests: list[dict] = []
        self.started = time.monotonic()

    def crypto_data(self) -> bytes:
        out = b""
        for off in sorted(self.crypto):
            data = self.crypto[off]
            if off > len(out):
                break
            out += data[len(out) - off:] if off < len(out) else data
        return out

    def initial_packet(self, packet: bytes, pn_offset: int) -> None:
        try:
            _, payload, pn = self.pair.decrypt_packet(packet, pn_offset, self.next_pn)
        except Exception as exc:  # noqa: BLE001 - recorded
            self.packets.append({"error": f"decrypt: {exc}"}); return
        self.next_pn = pn + 1
        frames = []
        p = 0
        while p < len(payload):
            ftype = payload[p]
            if ftype == 0x00:
                start = p
                while p < len(payload) and payload[p] == 0:
                    p += 1
                frames.append(f"PADDING({p - start})"); continue
            if ftype == 0x01:
                frames.append("PING"); p += 1; continue
            if ftype == 0x06:
                off, q = _varint(payload, p + 1)
                n, q = _varint(payload, q)
                self.crypto.setdefault(off, payload[q:q + n])
                frames.append(f"CRYPTO({off},{n})"); p = q + n; continue
            if ftype in (0x02, 0x03):
                frames.append("ACK"); break  # client Initials after the first carry ACKs: stop parsing
            if ftype == 0x1C:
                frames.append("CONNECTION_CLOSE"); break
            frames.append(f"0x{ftype:x}"); break
        self.packets.append({"pn": pn, "len": len(packet), "frames": frames})
        data = self.crypto_data()
        if self.hello is None and len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big"):
            self.hello = parse_client_hello(data)
            raw = self.hello.pop("_tp_raw")
            self.tp = parse_transport_parameters(raw) if raw else None

    def h3_summary(self) -> dict:
        uni, req = [], []
        for sid in self.stream_order:
            data = bytes(self.streams[sid])
            if sid % 4 == 2:  # client-initiated unidirectional
                stype, p = _varint(data, 0) if data else (None, 0)
                entry: dict = {"stream": sid, "type": "GREASE" if stype is not None and _quic_grease(stype)
                               else H3_STREAM_NAMES.get(stype, f"0x{stype:x}" if stype is not None else None),
                               "len": len(data)}
                if stype == 0x00:
                    entry["frames"] = parse_h3_frames(data[p:])
                elif stype in (0x02, 0x03):
                    entry["data"] = data[p:p + 32].hex()
                uni.append(entry)
            elif sid % 4 == 0:
                req.append({"stream": sid, "frames": [f["type"] for f in parse_h3_frames(data)]})
        for r in req:
            for h in self.requests:
                if h["stream"] == r["stream"]:
                    r["headers"] = h["headers"]
        return {"uni_streams": uni, "requests": req}

    def result(self) -> dict:
        return {
            "quic": {"version": f"0x{self.version:08x}", "dcid_len": len(self.odcid), "scid_len": self.scid_len,
                     "token_len": self.token_len, "initial_datagrams": self.datagrams[:8], "datagram_trailers": self.trailers,
                     "initial_packets": self.packets[:8]},
            "tls": self.hello, "transport_parameters": self.tp, "h3": self.h3_summary(),
        }


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.conns: dict[bytes, ConnCapture] = {}
        self.by_addr: dict = {}
        self.got_request = threading.Event()

    def datagram(self, data: bytes, addr) -> None:
        if not data or not data[0] & 0x80:
            return  # short header: 1-RTT, nothing to record
        with self.lock:
            p = 0
            first_in_dgram = True
            while p < len(data) and data[p] & 0x80:
                first = data[p]
                version = int.from_bytes(data[p + 1:p + 5], "big")
                if version == 0:
                    return
                q = p + 5
                dl = data[q]; dcid = data[q + 1:q + 1 + dl]; q += 1 + dl
                sl = data[q]; q += 1 + sl
                ptype = (first & 0x30) >> 4
                initial = ptype == (1 if version == VERSION_2 else 0)
                token_len = 0
                if initial:
                    token_len, q = _varint(data, q)
                    q += token_len
                length, q = _varint(data, q)
                end = q + length
                if initial:
                    cap = self.by_addr.get(addr)
                    if cap is None:
                        cap = ConnCapture(dcid, version, addr)
                        cap.scid_len, cap.token_len = sl, token_len
                        self.by_addr[addr] = cap
                        self.conns[dcid] = cap
                    if first_in_dgram and cap.hello is None:
                        cap.datagrams.append(len(data))
                    if cap.hello is None or len(cap.packets) < 8:
                        cap.initial_packet(data[p:end], q)
                first_in_dgram = False
                p = end
            cap = self.by_addr.get(addr)
            if cap is not None and p < len(data) and len(cap.trailers) < 4:
                # bytes after the last long-header packet of the datagram
                tail = data[p:]
                cap.trailers.append({"offset": p, "len": len(tail), "zero": not any(tail),
                                     "head": tail[:8].hex()})

    def conn_for(self, odcid: bytes) -> ConnCapture | None:
        with self.lock:
            return self.conns.get(odcid)

    def results(self) -> list[dict]:
        with self.lock:
            return [c.result() for c in sorted(self.conns.values(), key=lambda c: c.started)]


def make_cert(directory: str) -> tuple[str, str, str, str]:
    """A throwaway CA and a localhost leaf signed by it (mozilla::pkix refuses a CA
    certificate used as the end-entity). Returns cert chain, key, CA path, leaf SPKI pin."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "yumeclient h3 capture CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    cert_path = os.path.join(directory, "chain.pem")
    key_path = os.path.join(directory, "key.pem")
    ca_path = os.path.join(directory, "ca.pem")
    Path(cert_path).write_bytes(leaf.public_bytes(pem) + ca.public_bytes(pem))
    Path(ca_path).write_bytes(ca.public_bytes(pem))
    Path(key_path).write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    spki = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert_path, key_path, ca_path, base64.b64encode(hashlib.sha256(spki).digest()).decode()


PAGE = (b"<!doctype html><title>h3</title><meta http-equiv=refresh content=1>"
        b"<body>ok <img src=/pixel></body>")


class _TCPFallback:
    """HTTPS over TCP on the same port number: answers with Alt-Svc so a browser that does
    not start with HTTP/3 learns about it and switches on the reload."""

    def __init__(self, sock, cert: str, key: str, port: int):
        import socket
        import ssl
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.sock, self.port, self.socket = sock, port, socket
        self.requests = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(10)
            tls = self.ctx.wrap_socket(conn, server_side=True)
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = tls.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                head, buf = buf.split(b"\r\n\r\n", 1)
                self.requests += 1
                path = head.split(b" ", 2)[1] if b" " in head else b"/"
                body = PAGE if path == b"/" else b""
                alt = f'h3=":{self.port}"; ma=86400'.encode()
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nAlt-Svc: " + alt +
                            b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        except Exception:  # noqa: BLE001 - browsers drop connections all the time
            pass
        finally:
            conn.close()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class CaptureServer:
    """HTTP/3 server on 127.0.0.1 recording every client connection."""

    def __init__(self, port: int = 0, tcp: bool = False):
        import socket
        self.dir = tempfile.mkdtemp(prefix="h3cap")
        self.cert, self.key, self.ca, self.spki = make_cert(self.dir)
        self.recorder = Recorder()
        self._loop = asyncio.SelectorEventLoop()  # proactor stops reading UDP after ICMP resets
        self._ready = threading.Event()
        self._port = port
        self.tcp = None
        self._udp = None
        for _ in range(50 if tcp else 1):
            if tcp:
                t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                t.bind(("127.0.0.1", port))
                t.listen(64)
                self._port = t.getsockname()[1]
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                u.bind(("127.0.0.1", self._port))
            except OSError:
                u.close()
                if tcp:
                    t.close()
                    continue
                raise
            self._udp = u
            if tcp:
                self.tcp = _TCPFallback(t, self.cert, self.key, self._port)
            break
        if self._udp is None:
            raise OSError("no port free for both TCP and UDP")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(10)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        recorder = self.recorder
        cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN + ["h3-29"], max_datagram_frame_size=65536)
        cfg.load_cert_chain(self.cert, self.key)

        class Proto(QuicConnectionProtocol):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.h3 = H3Connection(self._quic, enable_webtransport=False)
                self.cap = None

            def quic_event_received(self, event):
                if self.cap is None:
                    self.cap = recorder.conn_for(self._quic._original_destination_connection_id)
                if isinstance(event, StreamDataReceived) and self.cap is not None:
                    with recorder.lock:
                        if event.stream_id not in self.cap.streams:
                            self.cap.streams[event.stream_id] = bytearray()
                            self.cap.stream_order.append(event.stream_id)
                        self.cap.streams[event.stream_id] += event.data
                for ev in self.h3.handle_event(event):
                    if isinstance(ev, HeadersReceived):
                        headers = [[k.decode(errors="replace"), v.decode(errors="replace")] for k, v in ev.headers]
                        if self.cap is not None:
                            with recorder.lock:
                                self.cap.requests.append({"stream": ev.stream_id, "headers": headers})
                        path = dict(ev.headers).get(b":path", b"/")
                        body = PAGE if path == b"/" else b""
                        self.h3.send_headers(ev.stream_id, [(b":status", b"200" if body else b"404"),
                                                            (b"content-type", b"text/html"),
                                                            (b"content-length", str(len(body)).encode())])
                        self.h3.send_data(ev.stream_id, body, end_stream=True)
                        self.transmit()
                        if path == b"/":
                            recorder.got_request.set()

        async def start():
            _, server = await self._loop.create_datagram_endpoint(
                lambda: QuicServer(configuration=cfg, create_protocol=Proto), sock=self._udp)
            orig = server.datagram_received

            def tap(data, addr):
                try:
                    recorder.datagram(data, addr)
                except Exception as exc:  # noqa: BLE001 - never break the server
                    print("capture error:", exc, file=sys.stderr)
                orig(data, addr)

            server.datagram_received = tap
            self.port = server._transport.get_extra_info("sockname")[1]
            self._ready.set()

        self._loop.run_until_complete(start())
        self._loop.run_forever()

    def close(self):
        if self.tcp:
            self.tcp.close()
        self._loop.call_soon_threadsafe(self._loop.stop)
        shutil.rmtree(self.dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------

def _wait(srv: CaptureServer, timeout: float, settle: float = 1.5) -> bool:
    ok = srv.recorder.got_request.wait(timeout)
    time.sleep(settle)
    return ok


def capture_chrome(exe: str, headless: str = "new", timeout: float = 40,
                   extra_args: list[str] | None = None) -> dict:
    srv = CaptureServer()
    profile = tempfile.mkdtemp(prefix="h3chrome")
    url = f"https://{HOST}:{srv.port}/"
    args = [exe, f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-background-networking", "--disable-sync",
            "--disable-component-update", "--disable-features=OptimizationHints,MediaRouter",
            "--enable-quic", f"--origin-to-force-quic-on={HOST}:{srv.port}",
            f"--ignore-certificate-errors-spki-list={srv.spki}",
            "--host-resolver-rules=MAP localhost 127.0.0.1", "--window-size=800,600",
            "--disable-field-trial-config", "--disable-gpu", *(extra_args or [])]
    if headless == "new":
        args.append("--headless=new")
    elif headless == "old":
        args.append("--headless")
    args.append(url)
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ok = _wait(srv, timeout)
    finally:
        _kill_tree(proc)
        shutil.rmtree(profile, ignore_errors=True)
    out = {"client": {"kind": "chrome", "exe": exe, "version": _exe_version(exe), "headless": headless,
                      "extra_args": list(extra_args or [])},
           "ok": ok, "connections": srv.recorder.results()}
    srv.close()
    return out


FIREFOX_PREFS = {
    "network.http.http3.enable": True, "network.http.http3.enabled": True,
    "network.http.http3.disable_when_third_party_roots_found": False,
    "network.dns.disableIPv6": True, "network.proxy.type": 0,
    "browser.shell.checkDefaultBrowser": False, "browser.startup.homepage_override.mstone": "ignore",
    "datareporting.policy.dataSubmissionEnabled": False, "toolkit.telemetry.reportingpolicy.firstRun": False,
    "app.update.enabled": False, "app.update.auto": False, "app.normandy.enabled": False,
    "browser.newtabpage.enabled": False, "browser.startup.page": 0,
    "browser.safebrowsing.malware.enabled": False, "browser.safebrowsing.phishing.enabled": False,
    "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
    "extensions.update.enabled": False, "browser.aboutwelcome.enabled": False,
    "security.enterprise_roots.enabled": False, "network.trr.mode": 5,
}


def capture_firefox(exe: str, headless: bool = True, timeout: float = 60) -> dict:
    srv = CaptureServer(tcp=True)
    profile = tempfile.mkdtemp(prefix="h3firefox")
    prefs = dict(FIREFOX_PREFS)
    prefs["network.http.http3.alt-svc-mapping-for-testing"] = f"{HOST};h3=:{srv.port}"
    lines = [f"user_pref({json.dumps(k)}, {json.dumps(v)});" for k, v in prefs.items()]
    Path(profile, "user.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
    dist = Path(exe).parent / "distribution"
    dist.mkdir(exist_ok=True)
    policies = {"policies": {"Certificates": {"Install": [srv.ca]}, "DisableAppUpdate": True,
                             "DisableTelemetry": True, "DontCheckDefaultBrowser": True}}
    (dist / "policies.json").write_text(json.dumps(policies), encoding="utf-8")
    args = [exe, "-no-remote", "-profile", profile]
    if headless:
        args.append("-headless")
    args.append(f"https://{HOST}:{srv.port}/")
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ok = _wait(srv, timeout, settle=2.5)
    finally:
        _kill_tree(proc)
        shutil.rmtree(profile, ignore_errors=True)
    out = {"client": {"kind": "firefox", "exe": exe, "version": _exe_version(exe), "headless": headless,
                      "tcp_requests": srv.tcp.requests},
           "ok": ok, "connections": srv.recorder.results()}
    srv.close()
    return out


def _install_root(exe: str) -> Path | None:
    """The directory of a browser downloaded by h3_browsers.py (YC_BROWSER_CACHE/
    opera-91.0.4516.77, .../firefox-123.0), None for any other executable."""
    path = Path(exe).resolve()
    cache = Path(os.environ.get("YC_BROWSER_CACHE", "browsers")).resolve()
    try:
        rel = path.relative_to(cache)
    except ValueError:
        return None  # an installed browser: only its process tree is ours
    return cache / rel.parts[0] if len(rel.parts) > 1 else None


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        # browsers that relaunch themselves (Opera) or outlive their parent leave
        # processes outside the tree, some with windows: every process started from
        # the downloaded browser's directory goes too (never an installed browser)
        root = _install_root(str(proc.args[0]))
        if root is not None:
            script = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and "
                      "$_.ExecutablePath.StartsWith($env:YC_KILL_ROOT + [IO.Path]::DirectorySeparatorChar, "
                      "[StringComparison]::OrdinalIgnoreCase) } | "
                      "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
            subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True,
                           env={**os.environ, "YC_KILL_ROOT": str(root)}, timeout=60)
    else:
        proc.kill()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        pass


def capture_yumeclient(profile: str, timeout: float = 20, **options) -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import warnings
    import yumeclient
    srv = CaptureServer()
    url = f"https://{HOST}:{srv.port}/"
    err = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            with yumeclient.Session(client_identifier=profile, verify=False, timeout=timeout,
                                    http_version="3", **options) as s:
                r = s.get(url)
                proto = r.used_protocol
        except Exception as exc:  # noqa: BLE001 - recorded
            err, proto = repr(exc), None
    time.sleep(0.5)
    out = {"client": {"kind": "yumeclient", "profile": profile, "version": yumeclient.__version__,
                      "used_protocol": proto, "error": err},
           "ok": err is None, "connections": srv.recorder.results()}
    srv.close()
    return out


def _exe_version(exe: str) -> str | None:
    if os.name == "nt":
        try:
            ps = ["powershell", "-NoProfile", "-Command", f"(Get-Item '{exe}').VersionInfo.ProductVersion"]
            return subprocess.run(ps, capture_output=True, text=True, timeout=20).stdout.strip() or None
        except Exception:  # noqa: BLE001
            return None
    return None


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------

def _stable_tp_value(t: dict):
    v = t.get("value")
    if t["name"] in ("version_information", "version_information_draft"):
        # chosen version, then the available ones in any order, GREASE versions blanked
        words = v if isinstance(v, list) else [v[i:i + 8] for i in range(0, len(v or ""), 8)]
        words = [w[2:] if w.startswith("0x") else w for w in words]
        words = ["GREASE" if (int(w, 16) & 0x0F0F0F0F) == 0x0A0A0A0A else w for w in words]
        return words[:1] + sorted(words[1:])
    return v


def fingerprint(cap: dict, connection: int = 0) -> dict:
    """The stable parts of a connection (by default the first): what a browser
    randomises per connection (extension and transport parameter order, GREASE
    values, the chaos layout of the Initial packets) is compared as a set."""
    c = cap["connections"][connection]
    tls = c["tls"] or {}
    # HTTP/3: the first connection that carried a request (browsers preconnect)
    h3 = next((x["h3"] for x in cap["connections"][connection:] if x["h3"]["requests"]), c["h3"])
    control = next((u for u in h3["uni_streams"] if u["type"] == "control"), {})
    first_req = h3["requests"][0] if h3["requests"] else {}
    tps = c["transport_parameters"] or []
    packets = c["quic"]["initial_packets"]
    first_frames = {f.split("(")[0] for p in packets[:2] for f in p.get("frames", []) if not f.startswith("ACK")}
    return {
        "quic.version": c["quic"]["version"], "quic.dcid_len": c["quic"]["dcid_len"],
        "quic.scid_len": c["quic"]["scid_len"], "quic.initial_datagrams": c["quic"]["initial_datagrams"],
        "quic.first_packet_number": packets[0].get("pn") if packets else None,
        "quic.first_flight_frame_kinds": sorted(first_frames),
        "tls.ja4": tls.get("ja4"), "tls.ciphers": tls.get("ciphers"),
        "tls.extension_set": sorted(map(str, tls.get("extensions") or [])),
        "tls.groups": tls.get("groups"), "tls.key_share": tls.get("key_share"),
        "tls.signature_algorithms": tls.get("signature_algorithms"), "tls.alpn": tls.get("alpn"),
        "tls.versions": tls.get("versions"),
        "tls.extension_data": {k: "<GREASE ECH>" if k == "65037" else v
                               for k, v in (tls.get("extension_data") or {}).items()},
        "tp.set": sorted(t["name"] for t in tps),
        "tp.values": {t["name"]: _stable_tp_value(t) for t in tps if "value" in t},
        "h3.uni_stream_types": sorted(u["type"] for u in h3["uni_streams"]),
        "h3.control_frames": [f["type"] for f in control.get("frames", [])][:2],
        "h3.settings": next((f["settings"] for f in control.get("frames", []) if f["type"] == "SETTINGS"), None),
        "h3.request_frames": first_req.get("frames"),
        "h3.header_order": [k for k, _ in first_req.get("headers", [])],
        "h3.priority": next((v for k, v in first_req.get("headers", []) if k == "priority"), None),
        "h3.priority_updates": [f.get("value") for f in control.get("frames", []) if f["type"] == "PRIORITY_UPDATE"][:1],
    }


def _frame_kinds(frames: list[str]) -> list[str]:
    out = []
    for f in frames:
        k = f.split("(")[0]
        if not out or out[-1] != k:
            out.append(k)
    return out


def diff(a: dict, b: dict) -> list[str]:
    fa, fb = fingerprint(a), fingerprint(b)
    # header values and the requests themselves depend on what was asked for
    for f in (fa, fb):
        f.pop("h3.header_order")
    return [f"{k}:\n    A {fa[k]!r}\n    B {fb.get(k)!r}" for k in fa if fa[k] != fb.get(k)]


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("chrome"); c.add_argument("--exe", required=True); c.add_argument("--headless", default="new")
    c.add_argument("--out"); c.add_argument("--timeout", type=float, default=40)
    y = sub.add_parser("yumeclient"); y.add_argument("--profile", required=True); y.add_argument("--out")
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=4433)
    d = sub.add_parser("diff"); d.add_argument("a"); d.add_argument("b")
    args = ap.parse_args()
    if args.cmd == "diff":
        a, b = (json.loads(Path(p).read_text(encoding="utf-8")) for p in (args.a, args.b))
        lines = diff(a, b)
        print("\n".join(lines) if lines else "identical"); return
    if args.cmd == "serve":
        srv = CaptureServer(args.port)
        print(f"listening on https://{HOST}:{srv.port}/  spki={srv.spki}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(json.dumps(srv.recorder.results(), indent=1))
        return
    cap = capture_chrome(args.exe, args.headless, args.timeout) if args.cmd == "chrome" else capture_yumeclient(args.profile)
    text = json.dumps(cap, indent=1, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"{args.out}: ok={cap['ok']} connections={len(cap['connections'])}")
    else:
        print(text)


if __name__ == "__main__":
    main()
