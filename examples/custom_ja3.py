"""Custom TLS and HTTP/2: a ClientHello from a JA3 string, the missing parts filled from
Chrome or set explicitly, and Firefox-like HTTP/2 settings.

    python examples/custom_ja3.py
"""
import os

from yumeclient import Session

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")

# A JA3 string fixes the TLS version, ciphers, extensions, groups and point formats. The rest
# (signature algorithms, key shares, ALPN, HTTP/2, headers) comes from Chrome by default.
JA3 = ("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,"
       "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0")

with Session(ja3_string=JA3, timeout=20) as s:
    r = s.get(f"{BASE}/get")
    print("JA3 sent:", r.fingerprint["ja3"])
    print("Akamai (Chrome defaults):", r.fingerprint["akamai_fingerprint"])

# The same JA3 with everything else written out: Firefox's signature algorithms, key
# shares, certificate compression and HTTP/2 SETTINGS, window update and pseudo-header order.
FIREFOX_LIKE = dict(
    ja3_string=JA3,
    random_tls_extension_order=False,  # Firefox does not shuffle its extensions
    supported_signature_algorithms=[
        "ECDSAWithP256AndSHA256", "ECDSAWithP384AndSHA384", "ECDSAWithP521AndSHA512",
        "PSSWithSHA256", "PSSWithSHA384", "PSSWithSHA512",
        "PKCS1WithSHA256", "PKCS1WithSHA384", "PKCS1WithSHA512", "ECDSAWithSHA1", "PKCS1WithSHA1",
    ],
    key_share_curves=["X25519MLKEM768", "X25519", "P256"],
    supported_versions=["1.3", "1.2"],
    alpn_protocols=["h2", "http/1.1"],
    cert_compression_algos=["zlib", "brotli", "zstd"],
    h2_settings={"HEADER_TABLE_SIZE": 65536, "INITIAL_WINDOW_SIZE": 131072, "MAX_FRAME_SIZE": 16384,
                 "NO_RFC7540_PRIORITIES": 1},
    connection_flow=12517377,
    pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
)
with Session(**FIREFOX_LIKE, timeout=20) as s:
    r = s.get(f"{BASE}/get")
    print("Akamai (explicit):", r.fingerprint["akamai_fingerprint"])
