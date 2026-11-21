"""Profiles and headers: picking a client, its default headers, adding, removing and
ordering headers, and the okhttp header style of Android apps.

    python examples/profiles_and_headers.py
"""
import os

from yumeclient import ALL_IDENTIFIERS, Session, default_headers, find

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")

print(len(ALL_IDENTIFIERS), "profiles, e.g. Safari on iOS:", find("safari_ios"))

# Every browser profile comes with that browser's headers, in its order.
print("Firefox 147 headers:")
for name, value in default_headers("firefox_147").items():
    print(f"  {name}: {value}")

# client_os changes the platform parts (User-Agent, sec-ch-ua-platform), not the TLS hello.
with Session(client_identifier="chrome_152", client_os="macos") as s:
    print("Chrome on macOS:", s.headers["User-Agent"])

with Session(client_identifier="safari_ios_18_0", timeout=20) as s:
    print("Safari on iOS:", s.headers["User-Agent"])

    # Headers are case-insensitive; the spelling you give is the one sent over HTTP/1.1.
    s.headers["X-App-Version"] = "3.1"
    s.headers.update({"Accept-Language": "de-DE,de;q=0.9"})

    # None removes a header for one request; header_order puts the listed ones first.
    r = s.get(f"{BASE}/headers", headers={"Accept-Encoding": None, "X-Trace": "abc"},
              header_order=["X-Trace", "User-Agent"])
    sent = r.json()["headers"]
    print("sent:", sorted(sent))
    print("Accept-Encoding removed:", "Accept-Encoding" not in sent)

# Replace the whole header set (start from nothing but what you set).
with Session(client_identifier="chrome_152") as s:
    s.headers = {"User-Agent": "my-crawler/1.0", "Accept": "*/*"}
    print("custom set:", dict(s.headers))

# Android apps on okhttp: the okhttp4 profiles also use okhttp's header style: no browser
# headers, and the transport adds Host, Connection, Accept-Encoding: gzip and okhttp's
# User-Agent the way okhttp does.
with Session(client_identifier="okhttp4_android_13", timeout=20) as s:
    print("okhttp session headers:", dict(s.headers), "style:", s.header_style)
    r = s.get(f"{BASE}/headers", headers={"Authorization": "Bearer token"})
    print("okhttp on the wire:", r.json()["headers"])
