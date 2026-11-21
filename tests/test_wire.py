"""Wire-level ClientHello checks (0.4.5): a local TLS server behind a sniffing
TCP relay records the exact bytes each session sends, then
  * profile identifiers must produce THEIR hello (not upstream's Chrome default),
  * Response.fingerprint must equal what an independent parser reads off the wire.
Fully offline."""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import tempfile
import threading

import pytest

import yumeclient
from yumeclient import Session

# self-signed localhost/127.0.0.1 test certificate + key (test-only, 100 years)
_PEM = """-----BEGIN CERTIFICATE-----
MIIBnDCCAUGgAwIBAgIUBp+dHlyfV3M581SZtG9Eb699c6MwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExNjE5MzQwN1oYDzIxMjYxMDIz
MTkzNDA3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAARG3mfZW0izHYvPZdPxubaRrfPnY9fnYOJaHuKzPLWgbIYnkUV0ODza
fg1FHgSqFc3QCcCpv8CFGcUwNcJJ/klyo28wbTAdBgNVHQ4EFgQUlxVnqbIR1Kx1
a1J31VAoSEWQk4swHwYDVR0jBBgwFoAUlxVnqbIR1Kx1a1J31VAoSEWQk4swDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSQAwRgIhAMbibVwpVvtNL0eu7rnx2DZEdwmA8zWasI/wWmVeqYhpAiEA
td0mj9NSdi15Mr13Y0RkmAB/0zKZ+2EOUAqusH/X2MM=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzz4R2e4TPUOu3gar
EsjklD0k/F2Q9BwFsAFFH8lo98+hRANCAARG3mfZW0izHYvPZdPxubaRrfPnY9fn
YOJaHuKzPLWgbIYnkUV0ODzafg1FHgSqFc3QCcCpv8CFGcUwNcJJ/kly
-----END PRIVATE KEY-----
"""

# reference: real Android app (okhttp over platform Conscrypt), tshark on the phone capture
CONSCRYPT_JA3 = ("771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,"
                 "0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0")
CONSCRYPT_JA3_MD5 = "f79b6bad2ad0641e1921aef10262856b"
CONSCRYPT_JA4_R = ("t13d1513h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
                   "0005,000a,000b,000d,0015,0017,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0501,0806,0601,0201")
CONSCRYPT_EXT_ORDER = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 21]
CONSCRYPT_JA4 = "t13d1513h2_8daaf6152771_eca864cca44a"  # = Wireshark 4.6 tls.handshake.ja4 on the phone capture


# ---------------------------------------------------------------------------
# independent ClientHello parser (deliberately not sharing code with native/wire.go)
# ---------------------------------------------------------------------------

def _grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _u16s(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b) - 1, 2)]


def parse_hello(rec: bytes) -> dict:
    assert rec[0] == 22 and rec[5] == 1, "not a ClientHello"
    hs = rec[5:]
    hs_len = int.from_bytes(hs[1:4], "big")
    b = hs[4:4 + hs_len]
    legacy = int.from_bytes(b[0:2], "big")
    p = 34
    p += 1 + b[p]
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
    points = list(e[11][1:]) if 11 in e else []
    sig = _u16s(e[13][2:]) if 13 in e else []
    versions = _u16s(e[43][1:]) if 43 in e else [legacy]
    key_share = []
    if 51 in e:
        d = e[51][2:]; q = 0
        while q < len(d):
            g = int.from_bytes(d[q:q + 2], "big"); n = int.from_bytes(d[q + 2:q + 4], "big")
            key_share.append((g, n)); q += 4 + n
    alpn, alpn_list = "", []
    if 16 in e:
        d = e[16]; alpn = d[3:3 + d[2]].decode()
        q = 2
        while q < len(d):
            alpn_list.append(d[q + 1:q + 1 + d[q]].decode()); q += 1 + d[q]
    order = [t for t, _ in exts]
    ja3 = ",".join([str(legacy), "-".join(str(c) for c in ciphers if not _grease(c)),
                    "-".join(str(t) for t in order if not _grease(t)),
                    "-".join(str(g) for g in groups if not _grease(g)), "-".join(map(str, points))])
    cs = sorted(c for c in ciphers if not _grease(c))
    es = [t for t in order if not _grease(t)]
    ver = {0x0304: "13", 0x0303: "12"}.get(max(v for v in versions if not _grease(v)), "00")
    ext_in = ",".join(f"{t:04x}" for t in sorted(t for t in es if t not in (0, 16)))
    sig_ja4 = [s for s in sig if not _grease(s)]  # JA4 ignores GREASE in every list (chrome_152 greases sigalgs)
    if sig_ja4:
        ext_in += "_" + ",".join(f"{s:04x}" for s in sig_ja4)
    ja4_r = (f"t{ver}{'d' if 0 in e else 'i'}{len(cs):02d}{len(es):02d}{(alpn[0] + alpn[-1]) if alpn else '00'}_"
             + ",".join(f"{c:04x}" for c in cs) + "_" + ext_in)
    ja4 = (f"t{ver}{'d' if 0 in e else 'i'}{len(cs):02d}{len(es):02d}{(alpn[0] + alpn[-1]) if alpn else '00'}_"
           f"{hashlib.sha256(','.join(f'{c:04x}' for c in cs).encode()).hexdigest()[:12]}_"
           f"{hashlib.sha256(ext_in.encode()).hexdigest()[:12]}")
    return {"rec_ver": rec[1:3].hex(), "rec_len": int.from_bytes(rec[3:5], "big"), "sid_len": b[34],
            "hs_len": hs_len, "ciphers": ciphers, "order": order, "groups": groups, "sig": sig,
            "key_share": key_share, "alpn": alpn, "ja3": ja3, "ja3_md5": hashlib.md5(ja3.encode()).hexdigest(),
            "ja4": ja4, "ja4_r": ja4_r, "alpn_list": alpn_list, "exts": e, "versions": versions}


# ---------------------------------------------------------------------------
# TLS server + sniffing relay
# ---------------------------------------------------------------------------

class Sniffer:
    def __init__(self):
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self._pem)
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.hellos: list[bytes] = []
        self._lock = threading.Lock()
        self.tls_sock = self._listen(); self.relay_sock = self._listen()
        self.port = self.relay_sock.getsockname()[1]
        threading.Thread(target=self._accept, args=(self.tls_sock, self._serve_tls), daemon=True).start()
        threading.Thread(target=self._accept, args=(self.relay_sock, self._relay), daemon=True).start()

    @staticmethod
    def _listen():
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(32); return s

    @staticmethod
    def _accept(ls, fn):
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=fn, args=(c,), daemon=True).start()

    def _serve_tls(self, c):
        try:
            s = self.ctx.wrap_socket(c, server_side=True)
            buf = b""
            while True:
                d = s.recv(65536)
                if not d:
                    return
                buf += d
                while b"\r\n\r\n" in buf:
                    head, buf = buf.split(b"\r\n\r\n", 1)
                    close = b"/close" in head.split(b"\r\n", 1)[0]
                    s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n"
                              + (b"Connection: close\r\n" if close else b"") + b"\r\n{}")
                    if close:  # forces a new connection -> TLS 1.3 resumption with the ticket
                        # FIN after the response, then drain: closing with unread client bytes
                        # makes Windows send RST, which can discard the response (flaky on CI)
                        try:
                            s.shutdown(socket.SHUT_WR)
                            s.settimeout(2)
                            while s.recv(65536):
                                pass
                        except OSError:
                            pass
                        s.close()
                        return
        except Exception:
            pass
        finally:
            c.close()

    def _relay(self, c):
        u = socket.create_connection(self.tls_sock.getsockname())
        first = bytearray(); state = {"done": False}

        def up():
            try:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    if not state["done"]:
                        first.extend(d)
                        if len(first) >= 5 and len(first) >= 5 + int.from_bytes(first[3:5], "big"):
                            state["done"] = True
                            with self._lock:
                                self.hellos.append(bytes(first[:5 + int.from_bytes(first[3:5], "big")]))
                    u.sendall(d)
            except Exception:
                pass
            finally:
                try: u.shutdown(socket.SHUT_WR)
                except Exception: pass
                c.close()  # the client has closed too: nothing left to read

        def down():
            try:
                while True:
                    d = u.recv(65536)
                    if not d:
                        break
                    c.sendall(d)
            except Exception:
                pass
            finally:
                # pass the server's FIN on, do not close: closing a socket that up() is still
                # reading makes Windows abort the connection with RST, and the client loses the
                # response it has not read yet (a rare ConnectionClosed in these tests)
                try: c.shutdown(socket.SHUT_WR)
                except OSError: pass

        threading.Thread(target=up, daemon=True).start(); threading.Thread(target=down, daemon=True).start()

    def last(self) -> dict:
        with self._lock:
            assert self.hellos, "no ClientHello captured"
            return parse_hello(self.hellos[-1])

    def close(self):
        for s in (self.tls_sock, self.relay_sock):
            s.close()
        os.unlink(self._pem)


@pytest.fixture(scope="module")
def sniffer():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    s = Sniffer()
    yield s
    s.close()


def _get(sniffer, **kw):
    s = Session(verify=False, timeout=10, **kw)
    try:
        r = s.get(f"https://localhost:{sniffer.port}/x")
        assert r.status_code == 200
        return r, sniffer.last()
    finally:
        s.close()


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ident", ["okhttp4_conscrypt", "conscrypt_android_latest"])
def test_conscrypt_profile_is_conscrypt_on_wire(sniffer, ident):
    # 0.4.4 regression: extra profiles were routed to upstream CreateClient, which
    # silently used DefaultClientProfile (Chrome: GREASE, MLKEM, ext 27, shuffled, 1718b)
    r, w = _get(sniffer, client_identifier=ident)  # random_tls_extension_order left at default True
    assert not any(_grease(x) for x in w["ciphers"] + w["order"] + w["groups"])
    assert w["order"] == CONSCRYPT_EXT_ORDER
    assert w["groups"] == [29, 23, 24]
    assert w["key_share"] == [(29, 32)]
    assert 27 not in w["order"] and 18 not in w["order"]
    assert w["hs_len"] == 508
    assert w["sig"] == [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
    assert w["ja4"] == CONSCRYPT_JA4
    assert w["ja3"] == CONSCRYPT_JA3 and w["ja3_md5"] == CONSCRYPT_JA3_MD5  # Conscrypt cipher wire order
    assert (w["rec_ver"], w["rec_len"], w["sid_len"]) == ("0301", 512, 32)
    fp = r.fingerprint
    assert fp["ja4_r"] == CONSCRYPT_JA4_R
    assert fp["source"] == "wire"
    assert fp["ja4"] == w["ja4"] and fp["ja3_hash_md5"] == w["ja3_md5"]
    assert fp["client_hello_len"] == 508


def test_explicit_ja3_conscrypt_matches_profile(sniffer):
    r, w = _get(sniffer, ja3_string=CONSCRYPT_JA3, tls_extension_order=CONSCRYPT_EXT_ORDER,
                key_share_curves=["X25519"], grease=False, fill_custom_with_chrome_defaults=False,
                random_tls_extension_order=False,
                supported_signature_algorithms=["0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601", "0201"])
    assert w["order"] == CONSCRYPT_EXT_ORDER and w["hs_len"] == 508 and w["ja4"] == CONSCRYPT_JA4
    assert r.fingerprint["source"] == "wire" and r.fingerprint["ja4"] == w["ja4"]
    assert r.fingerprint["ja3_hash_md5"] == w["ja3_md5"]


@pytest.mark.parametrize("ident,check", [
    ("tor_145", lambda w: 256 in w["groups"] and 28 in w["order"]),           # Firefox FFDHE + record_size_limit
    ("safari_macos_26_0", lambda w: len([c for c in w["ciphers"] if not _grease(c)]) == 20),
    ("edge_131", lambda w: w["ja4"].startswith("t13d1516h2_8daaf6152771_02713d6af862")),
])
def test_extra_profiles_reach_the_wire(sniffer, ident, check):
    r, w = _get(sniffer, client_identifier=ident)
    assert check(w), w
    assert r.fingerprint["ja4"] == w["ja4"]


def test_reporter_follows_wire_for_upstream_profile(sniffer):
    r, w = _get(sniffer, client_identifier="chrome_131")
    fp = r.fingerprint
    assert fp["source"] == "wire"
    assert fp["ja4"] == w["ja4"] and fp["ja3_hash_md5"] == w["ja3_md5"]
    assert fp["tls_extensions"] == w["order"]


def test_force_http1_rewrites_alpn(sniffer):
    # documents why force_http1 is NOT a profile default: it changes the hello
    r, w = _get(sniffer, client_identifier="okhttp4_conscrypt", force_http1=True)
    assert w["alpn"] == "http/1.1" and w["ja4"].startswith("t13d1513h1_")
    assert r.fingerprint["ja4"] == w["ja4"]


def _hellos_over_new_connections(sniffer, n, **kw):
    s = Session(client_identifier="okhttp4_conscrypt", verify=False, timeout=10, **kw)
    try:
        start = len(sniffer.hellos)
        fps = []
        for i in range(n):
            r = s.get(f"https://localhost:{sniffer.port}/close{i}")
            assert r.status_code == 200
            fps.append(r.fingerprint)
        return [parse_hello(h) for h in sniffer.hellos[start:]], fps
    finally:
        s.close()


def test_conscrypt_resumption_hello(sniffer):
    # phone variant B: resumed hello = same list, pre_shared_key (41) last instead of padding (21)
    hellos, fps = _hellos_over_new_connections(sniffer, 2)
    first, resumed = hellos[0], hellos[-1]
    assert first["order"] == CONSCRYPT_EXT_ORDER and first["hs_len"] == 508
    assert resumed["order"] == CONSCRYPT_EXT_ORDER[:-1] + [41]
    assert resumed["ciphers"] == first["ciphers"] and resumed["groups"] == [29, 23, 24]
    assert fps[-1]["tls_extensions"] == resumed["order"]


def test_disable_session_tickets_is_applied(sniffer):
    hellos, _ = _hellos_over_new_connections(sniffer, 2, disable_session_tickets=True)
    assert all(h["order"] == CONSCRYPT_EXT_ORDER for h in hellos)


@pytest.mark.parametrize("ident", ["okhttp4_android_13", "safari_ios_26_0", "firefox_147"])
def test_non_chromium_profiles_keep_fixed_order(sniffer, ident):
    # random_tls_extension_order defaults to True, yet only Chromium shuffles
    orders = [[t for t in _get(sniffer, client_identifier=ident)[1]["order"] if not _grease(t)] for _ in range(3)]
    assert orders[0] == orders[1] == orders[2]


def test_upstream_okhttp_android_13_is_conscrypt(sniffer):
    _, w = _get(sniffer, client_identifier="okhttp4_android_13")
    assert w["ja3_md5"] == CONSCRYPT_JA3_MD5 and w["order"] == CONSCRYPT_EXT_ORDER
