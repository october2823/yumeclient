"""Quickstart: one-shot requests, a session, query parameters, JSON, forms and statuses.

    python examples/quickstart.py
    HTTPBIN=http://127.0.0.1:8080 python examples/quickstart.py   # python tests/httpbin_local.py 8080
"""
import os

import yumeclient
from yumeclient import Profiles, Session

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")

# One-shot request: a session with the default profile (the latest Chrome) is created for it
# and closed afterwards. Fine for a single call; use a Session for anything more.
r = yumeclient.get(f"{BASE}/get", params={"q": "yumeclient", "page": 2})
print(r.status_code, f"HTTP/{r.http_version}", f"{r.elapsed * 1000:.0f} ms")
print("query echoed:", r.json()["args"])

# A session keeps connections, cookies and headers between requests.
with Session(client_identifier=Profiles.CHROME_152, timeout=20) as s:
    print("User-Agent:", s.headers["User-Agent"])

    r = s.post(f"{BASE}/post", json={"name": "yume", "tags": ["a", "b"]})  # application/json
    print("json body:", r.json()["json"])

    r = s.post(f"{BASE}/post", data={"login": "user", "remember": "1"})  # form-urlencoded
    print("form body:", r.json()["form"])

    r = s.put(f"{BASE}/put", data="plain text body")  # str/bytes are sent as is
    print("raw body:", r.json()["data"])

    # Extra headers for one request are merged over the session's headers.
    r = s.get(f"{BASE}/headers", headers={"X-Request-Id": "42"})
    print("X-Request-Id sent:", r.json()["headers"].get("X-Request-Id"))

    # HTTP errors are responses, not exceptions; raise_for_status() turns them into one.
    r = s.get(f"{BASE}/status/404")
    print("status 404:", r.status_code, "ok =", r.ok)
    try:
        r.raise_for_status()
    except yumeclient.HTTPStatusError as e:
        print("raise_for_status:", e)

    # Redirects are followed (up to 10); the hops are in r.history.
    r = s.get(f"{BASE}/redirect/2")
    print("redirects:", [h.status_code for h in r.history], "->", r.url)
