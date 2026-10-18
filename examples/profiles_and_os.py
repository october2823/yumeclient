"""client_identifier x client_os: fingerprint and header-set selection.

client_os only changes the *header baseline* (UA + client hints), never the
TLS fingerprint itself — the fingerprint comes from client_identifier.
Run: python examples/profiles_and_os.py
"""
import yumeclient
from yumeclient import Session, default_headers
from yumeclient.profiles import find

# every available profile name
from yumeclient import ALL_IDENTIFIERS
LATEST = "chrome_152"
print(len(ALL_IDENTIFIERS), "profiles; latest chrome:", LATEST)

# search by substring
print(find("safari_ios"))        # ['safari_ios_15_5', ..., 'safari_ios_26_0']

# 1. default: latest chrome on windows
with Session() as s:
    r = s.get("https://httpbin.org/headers")
    h = r.json()["headers"]
    print("chrome/windows :", h["User-Agent"][:55], "|", h["Sec-Ch-Ua-Platform"])

# 2. same profile, android header baseline
with Session(client_os="android") as s:
    r = s.get("https://httpbin.org/headers")
    h = r.json()["headers"]
    print("chrome/android :", h["User-Agent"][:55], "|", h["Sec-Ch-Ua-Mobile"])

# 3. same profile, ios header baseline (Chrome on iOS = CriOS, no client hints)
with Session(client_os="ios") as s:
    r = s.get("https://httpbin.org/headers")
    print("chrome/ios    :", r.json()["headers"]["User-Agent"][:55])

# 4. mobile app fingerprints: OS is derived automatically
#    okhttp4_android_13 -> android okhttp UA; nike_ios_mobile -> ios webview UA
for identifier in ("okhttp4_android_13", "nike_ios_mobile", "firefox_148", "safari_ios_26_0"):
    with Session(client_identifier=identifier) as s:
        r = s.get("https://httpbin.org/user-agent")
        print(f"{identifier:20s}:", r.json()["user-agent"][:60])

# 5. preview a baseline without a session
print(default_headers("chrome_152", "windows")["sec-ch-ua"])
print(default_headers("firefox_148", "android")["user-agent"])

# 6. any default header can be overridden per session or per request
with Session(client_os="android") as s:
    r = s.get("https://httpbin.org/headers", headers={"User-Agent": "override/9"})
    assert r.json()["headers"]["User-Agent"] == "override/9"
