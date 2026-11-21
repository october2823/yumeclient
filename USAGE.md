# yumeclient guide

**English** | [Русский](USAGE.ru.md)

A practical guide: how to solve common tasks, with examples. Each topic is described in full in
the [reference](docs/index.md), and ready-to-run scripts are in [examples/](examples/).

- [Installation](#installation)
- [First request](#first-request)
- [Sessions](#sessions)
- [Profiles: which client to impersonate](#profiles-which-client-to-impersonate)
- [Headers](#headers)
- [Parameters and request body](#parameters-and-request-body)
- [Response](#response)
- [Cookies](#cookies)
- [Timeouts and errors](#timeouts-and-errors)
- [Large responses: streaming](#large-responses-streaming)
- [Proxies](#proxies)
- [HTTP/2 and HTTP/3](#http2-and-http3)
- [Checking the fingerprint](#checking-the-fingerprint)
- [Custom TLS fingerprint](#custom-tls-fingerprint)
- [Recipes](#recipes)

## Installation

```bash
pip install yumeclient
```

Prebuilt wheels are available for Windows x64, Linux x86-64/aarch64 (glibc 2.17+) and macOS 11+
(Intel and Apple Silicon), Python 3.11+. There are no other dependencies. Building from source
and other platforms are covered in [Installation](docs/installation.md).

## First request

```python
import yumeclient

r = yumeclient.get("https://httpbin.org/get", params={"q": "test"})
print(r.status_code)       # 200
print(r.json()["args"])    # {'q': 'test'}
print(r.http_version)      # '2'
```

`yumeclient.get`, `post`, `put`, `patch`, `delete`, `head`, `options` and `request` create a
session for a single request. The request goes out as if from the latest Chrome (`chrome_152`):
its ClientHello, its HTTP/2 and its headers.

## Sessions

For several requests, use a session: it keeps connections, cookies and headers.

```python
from yumeclient import Session

with Session(client_identifier="chrome_152", timeout=20) as s:
    s.get("https://example.com/login")
    r = s.post("https://example.com/login", data={"user": "me", "password": "secret"})
    r = s.get("https://example.com/account")   # the login cookie is already in the session
```

The async variant is `AsyncSession`, with the same parameters and methods:

```python
import asyncio
from yumeclient import AsyncSession

async def main():
    async with AsyncSession(timeout=20) as s:
        pages = await asyncio.gather(*(s.get(f"https://httpbin.org/get?page={i}") for i in range(10)))
        print([r.status_code for r in pages])

asyncio.run(main())
```

- Close the session (`with` or `s.close()`): otherwise the connections stay open.
- One `Session` can be used from several threads.
- Transport settings (profile, default proxy, `verify`, `http_version`, ...) are set when the
  session is created and do not change afterwards. Per request you can pass `proxy`,
  `timeout`, `headers`, `cookies`, `allow_redirects` and others; see [Requests](docs/requests.md).
- Cancelling an asyncio task also cancels the network request; Ctrl+C interrupts a sync request.

Details: [Sessions](docs/sessions.md).

## Profiles: which client to impersonate

`client_identifier` selects the client whose fingerprint is reproduced: ClientHello, HTTP/2,
HTTP/3 and QUIC, default headers.

```python
from yumeclient import ALL_IDENTIFIERS, Profiles, Session, find

print(len(ALL_IDENTIFIERS))           # 93
print(find("firefox"))                # ['firefox_102', ..., 'firefox_148']

Session(client_identifier="firefox_148")
Session(client_identifier=Profiles.SAFARI_IOS_18_5)
Session(client_identifier="okhttp4_android_13")   # an Android app on okhttp
```

| You need | Profile |
|---|---|
| Desktop Chrome | `chrome_152` (default), `chrome_146`, ... |
| Edge, Brave, Opera | `edge_131`, `brave_146`, `opera_91` |
| Firefox | `firefox_148`, `firefox_147`, ... |
| Safari on Mac / iPhone / iPad | `safari_macos_26_0`, `safari_ios_18_5`, `safari_ipad_15_6` |
| Android app | `okhttp4_android_13`, `okhttp4_conscrypt` |
| Tor Browser | `tor_145` |

`client_os` changes the platform in the headers (`User-Agent`, `sec-ch-ua-platform`) without
touching TLS:

```python
Session(client_identifier="chrome_152", client_os="macos")
Session(client_identifier="chrome_152", client_os="android")
```

Details: [Profiles](docs/profiles.md): the full list, and what was taken from browser captures
and what was not.

## Headers

A session starts with the headers that the profile's browser sends when it opens a page, in the
browser's order. You can add to them, change them and remove them:

```python
with Session(client_identifier="chrome_152") as s:
    print(s.headers["User-Agent"])                 # header names are case-insensitive

    s.headers["Referer"] = "https://example.com/"  # for all following requests
    s.headers.update({"Accept-Language": "ru-RU,ru;q=0.9"})

    s.get(url, headers={"X-Request-Id": "42"})     # only for this request
    s.get(url, headers={"Accept-Encoding": None})  # None: do not send the header
    s.get(url, header_order=["X-Request-Id", "User-Agent"])  # these go first

    s.headers = {"User-Agent": "my-bot/1.0"}       # replace the whole set
```

- Browser headers are sent in the browser's spelling over HTTP/1.1 (`User-Agent`), and in lower
  case over HTTP/2 and HTTP/3, as the protocol requires.
- `User-Agent` is not added on its own: if you removed it from the session, it is not sent.
- If `Accept-Encoding` is not set, the transport adds `gzip, deflate, br`; the response is
  decompressed automatically.

To see the default headers without a session: `yumeclient.default_headers("firefox_148")`.
Details: [Requests → Headers](docs/requests.md#headers), [Profiles](docs/profiles.md#default-headers).

## Parameters and request body

```python
s.get(url, params={"q": "text", "tag": ["a", "b"]})       # ?q=text&tag=a&tag=b
s.post(url, json={"name": "yume"})                         # application/json
s.post(url, data={"login": "me", "password": "x"})          # form-urlencoded
s.post(url, data=b"\x00\x01")                               # bytes as is (octet-stream)
s.post(url, data="raw text", headers={"Content-Type": "text/plain"})
s.post(url, files={"file": ("report.pdf", open("report.pdf", "rb"), "application/pdf")},
       data={"title": "Report"})                            # multipart/form-data
```

`files` accepts the same forms as in `requests`: `bytes`, a file object, `(name, content)`,
`(name, content, type)` and `(name, content, type, headers)`.

Redirects are followed automatically (up to 20, as in a browser), with the method handled as in
a browser (POST → GET on 301/302/303; 307/308 keep the method and body).
`allow_redirects=False` returns the 3xx itself.

Details: [Requests](docs/requests.md).

## Response

```python
r = s.get("https://httpbin.org/json")

r.status_code, r.ok           # 200, True (ok: status 200–399)
r.json()                      # parsed JSON
r.text                        # str (encoding from Content-Type, otherwise UTF-8)
r.content                     # bytes
r.headers["Content-Type"]     # ['application/json']: a list of values
r["content-type"]             # 'application/json': values joined with ", ", case-insensitive
r.url                         # final URL after redirects
r.history                     # redirect responses
r.cookies                     # dict: session cookies that match the final URL
r.elapsed                     # seconds for the whole request (with stream=True: until the headers)
r.http_version                # '1.1', '2' or '3'
r.raise_for_status()          # HTTPStatusError on 4xx/5xx
```

`r.connection_info` holds the addresses, connection reuse, TLS version, cipher and stage
timings. Details: [Responses](docs/responses.md).

## Cookies

Cookies from responses are stored in `s.cookies` and sent on by browser rules (domain, path,
`Secure`, public suffixes).

```python
import json
from yumeclient import CookieJar, Session

with Session() as s:
    s.get("https://httpbin.org/cookies/set?session=abc")
    print(s.cookies.to_dict())                      # {'session': 'abc'}

    s.cookies.set("consent", "yes", domain="httpbin.org")
    s.get(url, cookies={"preview": "1"})            # only for this request, not stored in the jar

    saved = s.cookies.export()                      # a list of dicts (Cookie-Editor format)

# in another session or after a restart
with Session(cookies=CookieJar(saved)) as s:
    ...
```

Importing from a browser: export the cookies with the Cookie-Editor extension (JSON) and pass
the list to `CookieJar(...)`. Details: [Cookies](docs/cookies.md).

## Timeouts and errors

By default the whole request gets 30 seconds. Stages can be limited separately:

```python
from yumeclient import Session, TimeoutConfig

Session(timeout=10)                                    # 10 s for the whole request
Session(timeout=(5, 20))                               # 5 s to connect, 20 s between data
Session(timeout=TimeoutConfig(total=60, connect=5, read=15))
s.get(url, timeout=120)                                # for one request
```

Errors are subclasses of `yumeclient.RequestError`. Each one has `kind` (a machine-readable
code), `stage`, `url`, `elapsed` and `retryable`:

```python
import yumeclient

try:
    r = s.get(url)
    r.raise_for_status()
except yumeclient.Timeout as e:           # ConnectTimeout, ReadTimeout, WriteTimeout
    print("slow:", e.stage, e.elapsed)
except yumeclient.ProxyError as e:        # proxy unreachable or refused
    ...
except yumeclient.ConnectError as e:      # DNS, connection refused, TLS (TLSError)
    ...
except yumeclient.HTTPStatusError as e:   # from raise_for_status()
    print(e.response.status_code)
except yumeclient.RequestError as e:      # any other network error
    print(e.kind, e)
```

Configuration errors (`SessionConfigurationError`) are raised when the session is created,
before any network access. The library itself retries a request only on a new connection when
the old one was closed (for example, a connection from the pool), and only if the request
definitely did not reach the server or is idempotent (GET, HEAD, OPTIONS, TRACE, a request with
`Idempotency-Key`); any other retries are up to you. An example of retries with backoff is in
[examples/errors_and_retries.py](examples/errors_and_retries.py).
Details: [Timeouts, errors and cancellation](docs/timeouts-and-errors.md).

## Large responses: streaming

```python
with s.get("https://example.com/big.iso", stream=True) as r:
    r.raise_for_status()
    with open("big.iso", "wb") as f:
        for chunk in r.iter_bytes(1 << 20):
            f.write(chunk)
```

In asyncio: `async for chunk in r.aiter_bytes()` and `await r.aread()`. To limit the response
size (after decompression): `max_content_size=10_000_000` on the session or the request →
`ResponseTooLarge`. Details: [Responses → Streaming](docs/responses.md#streaming).

## Proxies

```python
Session(proxy="http://user:pass@proxy.example:8080")
Session(proxy="socks5://user:pass@127.0.0.1:1080")    # socks5 also carries HTTP/3 (UDP)

s.get(url, proxy="socks5://127.0.0.1:1081")            # a different proxy for one request
s.get(url, proxy="")                                   # no proxy
```

Supported schemes: `http`, `https`, `socks5`, `socks5h`, `socks4`, `socks4a`. Which proxy the
connection went through, and how long that took, is in `r.connection_info`.
Details: [Proxies and network](docs/proxies.md).

## HTTP/2 and HTTP/3

By default (`http_version="auto"`) the protocol is chosen as in a browser, via ALPN: HTTP/2 if
the server supports it, otherwise HTTP/1.1.

```python
Session(http_version="2")     # HTTP/2 only; without it: ProtocolError, not a silent fallback
Session(http_version="1.1")   # HTTP/1.1 only
Session(http_version="3")     # HTTP/3 (QUIC) racing TCP, like Chrome
```

With `http_version="3"`, 53 profiles (Chrome, Edge, Brave, Opera, Firefox) use a QUIC handshake
and HTTP/3 captured from real browsers. Through a proxy, HTTP/3 works only through SOCKS5:
`proxy="socks5://..."` or a separate `udp_proxy`. Details: [Protocols](docs/protocols.md) and
[Proxies](docs/proxies.md#http3-through-a-proxy).

## Checking the fingerprint

Every response carries the fingerprint of what actually went out on the wire:

```python
r = s.get("https://tls.peet.ws/api/all")
print(r.fingerprint["ja4"])                  # t13d1517h2_8daaf6152771_...
print(r.fingerprint["ja3"])
print(r.fingerprint["akamai_fingerprint"])   # HTTP/2
```

To compare two clients: `yumeclient.fingerprint_diff(a, b)`; to save a client's settings:
`s.export_profile()` and `Session.from_profile(...)`; a trace that is safe to share in a bug
report: `r.trace()`. Details: [Diagnostics](docs/diagnostics.md).

## Custom TLS fingerprint

If the client you need is not among the profiles, you can set the ClientHello with a JA3 string.
The rest (signature algorithms, key share, ALPN, HTTP/2) is taken from Chrome or set explicitly:

```python
JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"

with Session(ja3_string=JA3) as s:
    r = s.get("https://tls.peet.ws/api/all")
```

All parameters (signatures, key share, ECH, HTTP/2 SETTINGS, pseudo-header order, ...) are in
[Custom TLS fingerprint](docs/custom-tls.md); an example of a Firefox-like setup is
[examples/custom_ja3.py](examples/custom_ja3.py).

## Recipes

**Limit the number of concurrent requests in asyncio**

```python
limit = asyncio.Semaphore(10)

async def fetch(s, url):
    async with limit:
        return await s.get(url)
```

By default `AsyncSession` has a pool for 64 concurrent requests per process; for more, call
`AsyncSession.configure_executor(workers=256)` before the first request.

**Retry a request on a network error**

```python
for attempt in range(3):
    try:
        r = s.get(url)
        break
    except yumeclient.RequestError as e:
        if not e.retryable or attempt == 2:
            raise
        time.sleep(2 ** attempt)
```

Retry like this only idempotent requests (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS` or with
`Idempotency-Key`): a POST may have reached the server before the error.

**Pretend to be an Android app**

```python
with Session(client_identifier="okhttp4_android_13") as s:
    r = s.post("https://api.example.com/v1/login",
               json={"user": "me"},
               headers={"User-Agent": "MyApp/5.2.0 (Android 14; Pixel 8)", "X-App-Version": "5.2.0"})
```

okhttp profiles build the request like okhttp 4: without browser headers, with `Host`,
`Connection: Keep-Alive`, `Accept-Encoding: gzip` and their own `User-Agent` if you did not set
one.

**Reset connections** (for example, after a network change): `s.reset_connection()`.

**Find out what is not supported**: [Limitations](docs/limitations.md).
