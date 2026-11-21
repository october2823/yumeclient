"""Proxies: a session proxy, a different proxy or none for one request, and what the
connection went through.

    PROXY=socks5://user:pass@127.0.0.1:1080 python examples/proxies.py
    PROXY=http://user:pass@127.0.0.1:8080 python examples/proxies.py
"""
import os
import sys

from yumeclient import ProxyError, Session

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")
PROXY = os.environ.get("PROXY")
if not PROXY:
    sys.exit("set PROXY, e.g. PROXY=socks5://127.0.0.1:1080 python examples/proxies.py")

# The session proxy is used for every request (TCP and, with socks5://, HTTP/3 too).
with Session(proxy=PROXY, timeout=20) as s:
    r = s.get(f"{BASE}/ip")
    info = r.connection_info
    print("via proxy:", r.json(), "| connected to", info["remote_address"],
          "| proxy handshake", info["timings"]["proxy"], "s")

    # proxy="" sends one request directly; proxy="<url>" uses another proxy for it.
    r = s.get(f"{BASE}/ip", proxy="")
    print("direct:", r.json(), "| connected to", r.connection_info["remote_address"])

# Proxy failures are ProxyError (a ConnectError): bad credentials, refused connection, ...
try:
    with Session(proxy="socks5://127.0.0.1:9", timeout=5) as s:
        s.get(f"{BASE}/ip")
except ProxyError as e:
    print(f"ProxyError: kind={e.kind} retryable={e.retryable}")
