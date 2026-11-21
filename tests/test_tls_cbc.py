"""CBC cipher suites against OpenSSL, with and without RFC 7366 encrypt_then_mac.

cloudscraper offers only TLS 1.2 CBC suites plus encrypt_then_mac. OpenSSL acknowledges
the extension and then protects records MAC-after-encryption; uTLS used to offer the
extension without implementing it, so every such connection failed with bad_record_mac
(native/third_party/patches/utls.patch).
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import tempfile
import threading
import warnings

import pytest

import yumeclient
from yumeclient import Session

from test_wire import _PEM

OP_NO_ENCRYPT_THEN_MAC = 1 << 19  # SSL_OP_NO_ENCRYPT_THEN_MAC (OpenSSL 1.1.1 / 3.x)
BIG = 70_000  # several TLS records in both directions


@pytest.fixture(scope="module")
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")


class CBCServer:
    """HTTP/1.1 over TLS 1.2 with CBC suites only; echoes the body's sha256."""

    def __init__(self, etm: bool, version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2):
        fd, self._pem = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(_PEM)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self._pem)
        self.ctx.minimum_version = self.ctx.maximum_version = version
        self.ctx.set_ciphers("ECDHE+AES+SHA1:ECDHE+AES+SHA256:ECDHE+AES+SHA384:@SECLEVEL=0")
        if not etm:
            self.ctx.options |= OP_NO_ENCRYPT_THEN_MAC
        self.ciphers: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
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
        try:
            with self.ctx.wrap_socket(c, server_side=True) as s:
                self.ciphers.append(s.cipher()[0])
                f = s.makefile("rb")
                while True:
                    line = f.readline()
                    if not line:
                        return
                    length = 0
                    while (h := f.readline()) not in (b"\r\n", b""):
                        if h.lower().startswith(b"content-length:"):
                            length = int(h.split(b":")[1])
                    digest = hashlib.sha256(f.read(length)).hexdigest().encode()
                    body = digest + b"\n" + b"x" * BIG
                    s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        except (OSError, ssl.SSLError, ValueError):
            pass

    def close(self):
        self.sock.close()
        os.unlink(self._pem)


def _reachable(srv) -> bool:
    """Whether this OpenSSL build/policy can serve the version at all (TLS 1.0/1.1 often not)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection(("127.0.0.1", srv.port), timeout=5) as raw, ctx.wrap_socket(raw) as s:
            s.sendall(b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            return s.recv(1).startswith(b"H")
    except (OSError, ssl.SSLError):
        return False


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion:DeprecationWarning")
@pytest.mark.parametrize("version", ["TLSv1_2", "TLSv1_1", "TLSv1"])
@pytest.mark.parametrize("etm", [True, False], ids=["encrypt_then_mac", "mac_then_encrypt"])
def test_cloudscraper_cbc_against_openssl(native, etm, version):
    # TLS 1.0 has no explicit per-record IV: the CBC state chains across records
    srv = CBCServer(etm, ssl.TLSVersion[version])
    payload = os.urandom(BIG)
    try:
        if version != "TLSv1_2" and not _reachable(srv):
            pytest.skip(f"local OpenSSL does not serve {version}")
        srv.ciphers.clear()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = Session(client_identifier="cloudscraper", verify=False, timeout=10, force_http1=True)
        with s:
            for _ in range(2):  # the second request reuses the connection: sequence numbers advance
                r = s.post(f"https://127.0.0.1:{srv.port}/x", data=payload)
                assert r.status_code == 200
                assert r.content.split(b"\n", 1) == [hashlib.sha256(payload).hexdigest().encode(), b"x" * BIG]
        assert len(srv.ciphers) == 1 and "-SHA" in srv.ciphers[0] and "GCM" not in srv.ciphers[0], srv.ciphers
        assert r.connection_info["tls_cipher"].endswith(("_CBC_SHA", "_CBC_SHA256", "_CBC_SHA384"))
    finally:
        srv.close()


def test_cbc_with_other_profiles(native):
    # profiles without encrypt_then_mac still negotiate MAC-then-encrypt CBC
    srv = CBCServer(etm=True)
    try:
        with Session(client_identifier="firefox_135", verify=False, timeout=10, force_http1=True) as s:
            r = s.post(f"https://127.0.0.1:{srv.port}/y", data=b"abc")
        assert r.status_code == 200 and r.content.startswith(hashlib.sha256(b"abc").hexdigest().encode())
    except yumeclient.TLSError as exc:  # pragma: no cover - profile offers no CBC suite in common
        pytest.skip(str(exc))
    finally:
        srv.close()


def test_cloudscraper_ja3_with_encrypt_then_mac(native):
    # extension 22 (encrypt_then_mac) was missing from the JA3 mapper: cloudscraper's own
    # JA3 failed on every handshake ("unknown ClientHelloID: Custom-ja3")
    ja3 = "771,49172-49162-49171-49161-53-47-10,0-11-10-35-16-22-23-13,29-23-24,0"
    srv = CBCServer(etm=True)
    try:
        srv.ciphers.clear()
        with Session(ja3_string=ja3, verify=False, timeout=10, force_http1=True,
                     alpn_protocols=["http/1.1"]) as s:
            r = s.post(f"https://127.0.0.1:{srv.port}/z", data=b"abc")
        assert r.status_code == 200 and r.content.startswith(hashlib.sha256(b"abc").hexdigest().encode())
        assert "22" in r.fingerprint["ja3"].split(",")[2].split("-")
        assert r.connection_info["tls_cipher"].endswith(("_CBC_SHA", "_CBC_SHA256"))
    finally:
        srv.close()
