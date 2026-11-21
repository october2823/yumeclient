"""Fingerprints and diagnostics: what the request looked like on the wire (JA3, JA4,
Akamai HTTP/2), connection details, comparing two clients, saving a client setup as a
profile, and a redacted trace for a bug report.

    python examples/fingerprint.py
"""
import json
import os

from yumeclient import Session, fingerprint_diff

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")

with Session(client_identifier="chrome_152", timeout=20) as s:
    r = s.get(f"{BASE}/get")
    fp = r.fingerprint
    print("protocol:", r.used_protocol)
    print("JA4:   ", fp["ja4"])
    print("JA3:   ", fp["ja3"])
    print("Akamai:", fp["akamai_fingerprint"])
    print("connection:", {k: r.connection_info.get(k) for k in ("remote_address", "tls_version", "tls_cipher")})
    chrome = fp

with Session(client_identifier="firefox_147", timeout=20) as s:
    firefox = s.get(f"{BASE}/get").fingerprint

# fingerprint_diff compares two fingerprints field by field. Chromium shuffles its TLS
# extensions per connection, so differences of kind "order" are expected noise.
for d in fingerprint_diff(chrome, firefox):
    if d["kind"] != "order":
        print(f"  {d['field']}: {d['kind']}")

# Save a client setup (profile, headers, TLS/HTTP options; no proxy or secrets) and
# recreate it later or elsewhere.
with Session(client_identifier="safari_ios_18_0", headers={"X-App": "1"}) as s:
    profile = s.export_profile()
text = json.dumps(profile)
with Session.from_profile(json.loads(text), timeout=10) as clone:
    print("cloned:", clone.client_identifier, clone.headers["X-App"])

# A trace of one request for a bug report: sensitive headers, cookies and query values
# are redacted.
with Session(timeout=20) as s:
    r = s.get(f"{BASE}/get", params={"token": "secret"}, headers={"Authorization": "Bearer secret"})
    trace = r.trace()
    print("trace url:", trace["request"]["url"])
    print("trace Authorization:", dict(trace["request"]["headers"]).get("Authorization"))
