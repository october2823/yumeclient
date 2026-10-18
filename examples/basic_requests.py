"""Basic syntax tour: sessions, headers, cookies, methods, OS variants.

Run: python examples/basic_requests.py
Every request here targets httpbin.org; trim what you don't need.
"""
import asyncio

import yumeclient
from yumeclient import AsyncSession, Profiles, Session

# ---------------------------------------------------------------------------
# 1. simplest possible: one-shot sync request (no session)
# ---------------------------------------------------------------------------
r = yumeclient.get("https://httpbin.org/get", timeout=30)
print("one-shot:", r.status_code, r.http_version, f"{r.elapsed*1000:.0f}ms")
print("UA sent:", r.json()["headers"]["User-Agent"][:60])

# ---------------------------------------------------------------------------
# 2. sync session: cookies + headers persist between calls
# ---------------------------------------------------------------------------
with Session() as s:
    # session starts with a full browser-like default header set for the profile
    # (user-agent, sec-ch-ua, accept, sec-fetch-*, accept-encoding, accept-language)
    print("default headers:", list(s.headers)[:5], "...")

    # headers.update works exactly like requests
    s.headers.update({"Accept": "application/json", "X-Track": "yume"})

    r = s.get("https://httpbin.org/get", params={"page": 1, "q": "tls"})
    assert r.json()["headers"]["X-Track"] == "yume"
    assert r.json()["args"] == {"page": "1", "q": "tls"}

    # full replacement is allowed too (dict order == wire header order)
    s.headers = {"User-Agent": "my-ua/1.0", "Accept": "*/*"}

    # cookies: set on a response get stored in session.cookies automatically
    s.get("https://httpbin.org/cookies/set/demo/42")   # 302 -> follows -> Set-Cookie stored
    print("session jar:", s.cookies.to_dict())          # {'demo': '42'}

    # next request carries them
    r = s.get("https://httpbin.org/cookies")
    print("server sees:", r.json()["cookies"])          # {'demo': '42'}

    # manual cookie control
    s.cookies.set("manual", "yes")                       # or s.cookies["manual"] = "yes"
    s.cookies.update({"a": "1", "b": "2"})
    s.cookies.remove("demo")

    # per-request cookies are transient (do not stick to the session)
    s.get("https://httpbin.org/cookies", cookies={"temp": "1"})

    # body variants
    s.post("https://httpbin.org/post", json={"user": "yume"})
    s.post("https://httpbin.org/post", data={"form": "field"})
    s.post("https://httpbin.org/post", data=b"raw-bytes")
    s.put("https://httpbin.org/put", json={"v": 2})
    s.patch("https://httpbin.org/patch", json={"v": 3})
    s.delete("https://httpbin.org/delete")
    s.head("https://httpbin.org/get")

# ---------------------------------------------------------------------------
# 3. async: same syntax, every method awaited
# ---------------------------------------------------------------------------
async def async_demo():
    async with AsyncSession() as s:
        s.headers.update({"Accept": "application/json"})
        rs = await asyncio.gather(                       # parallel through one session
            s.get("https://httpbin.org/get?i=1"),
            s.get("https://httpbin.org/get?i=2"),
            s.get("https://httpbin.org/get?i=3"),
        )
        print("gather:", [r.status_code for r in rs])

asyncio.run(async_demo())

# ---------------------------------------------------------------------------
# 4. one-shot async helpers
# ---------------------------------------------------------------------------
r = asyncio.run(yumeclient.aget("https://httpbin.org/get"))
print("aone-shot:", r.status_code)
