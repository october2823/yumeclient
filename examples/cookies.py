"""Cookies: the session jar, setting cookies by hand, per-request cookies, and saving the
jar to a file and loading it into a new session.

    python examples/cookies.py
"""
import json
import os
import tempfile
from pathlib import Path

from yumeclient import CookieJar, Session

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")
host = BASE.split("://", 1)[1].split("/")[0].split(":")[0]

with Session(timeout=20) as s:
    # Set-Cookie responses land in the jar and are sent back on the next requests.
    s.get(f"{BASE}/cookies/set", params={"session": "abc123", "theme": "dark"})
    print("jar:", s.cookies.to_dict())
    print("server sees:", s.get(f"{BASE}/cookies").json()["cookies"])

    # Set a cookie by hand. With a domain it follows the RFC 6265 domain rules; without
    # one it is sent to every host (like requests).
    s.cookies.set("consent", "yes", domain=host)
    print("after set:", s.get(f"{BASE}/cookies").json()["cookies"])

    # Cookies for one request: sent with it, not stored.
    r = s.get(f"{BASE}/cookies", cookies={"preview": "1"})
    print("with a per-request cookie:", r.json()["cookies"])
    print("still in the jar:", sorted(s.cookies.to_dict()))

    # Cookies the server deletes (Max-Age=0) leave the jar.
    s.get(f"{BASE}/cookies/delete", params={"theme": ""})
    print("after delete:", sorted(s.cookies.to_dict()))

    # Save the jar: a list of dicts in the browser-extension (Cookie-Editor) format.
    path = Path(tempfile.gettempdir()) / "yumeclient-cookies.json"
    path.write_text(json.dumps(s.cookies.export(), indent=2))
    print("saved to", path)

# Later: load it into a new session.
jar = CookieJar(json.loads(path.read_text()))
with Session(cookies=jar, timeout=20) as s:
    print("restored:", s.get(f"{BASE}/cookies").json()["cookies"])
    for cookie in s.cookies:
        print(f"  {cookie.name}={cookie.value} domain={cookie.domain} path={cookie.path} "
              f"host_only={cookie.host_only}")
path.unlink()
