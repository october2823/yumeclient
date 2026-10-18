"""Cookie behavior: what sticks, what doesn't, redirect hops, domain identity.

Run: python examples/cookies_flow.py
"""
import yumeclient
from yumeclient import CookieJar, Session

with Session() as s:
    # 1. server sets cookies -> they land in the session jar automatically
    s.get("https://httpbin.org/cookies/set/token/abc123")
    print("jar:", s.cookies.to_dict())                    # {'token': 'abc123'}

    # 2. redirect chains: cookies set on ANY hop are kept, not just the final URL
    #    (httpbin /cookies/set redirects once; multi-hop covered in tests)

    # 3. sending cookies on a single request (transient, does not pollute the jar)
    r = s.get("https://httpbin.org/cookies", cookies={"one_shot": "42"})
    print("transient :", r.json()["cookies"])             # {'one_shot': '42', 'token': 'abc123'}
    assert "one_shot" not in s.cookies.to_dict()

    # 4. manual jar control
    s.cookies.set("sid", "manual", domain="httpbin.org")
    s.cookies["sid"] = "updated"                           # replaces same-name in place
    s.cookies.update({"multi": "1"})
    s.cookies.load("a=1; b=2", domain="httpbin.org")       # parse a Cookie header
    print("jar now  :", s.cookies.to_dict())

    # 5. inspect / export
    for cookie in s.cookies:
        print(f"  {cookie.name}={cookie.value} domain={cookie.domain or '(none)'} secure={cookie.secure}")
    browser_json = s.cookies.export()                      # browser-export compatible

    # 6. start a new session from an existing jar
    jar = CookieJar(browser_json)
    with Session(cookies=jar) as s2:
        r = s2.get("https://httpbin.org/cookies")
        print("restored :", r.json()["cookies"])

    # 7. cleanup
    s.cookies.remove("token")
    s.cookies.clear_domain("httpbin.org")
