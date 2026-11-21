# yumeclient

**English** | [Русский](https://github.com/october2823/yumeclient/blob/main/README.ru.md)

[![PyPI](https://img.shields.io/pypi/v/yumeclient)](https://pypi.org/project/yumeclient/)
[![Python](https://img.shields.io/pypi/pyversions/yumeclient)](https://pypi.org/project/yumeclient/)
[![test](https://github.com/october2823/yumeclient/actions/workflows/test.yml/badge.svg)](https://github.com/october2823/yumeclient/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/october2823/yumeclient/blob/main/LICENSE)

A Python HTTP client that sends requests the way real browsers and mobile apps do: the same
TLS ClientHello, the same HTTP/2 and HTTP/3/QUIC handshake, the same headers in the same
order. Sync and asyncio APIs in the style of `requests`.

```python
from yumeclient import Session

with Session(client_identifier="chrome_152") as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.http_version, r.fingerprint["ja4"])
```

## Features

- **93 client profiles**: Chrome 103–152, Edge, Brave, Opera, Firefox 102–148, Safari on
  macOS, iOS and iPadOS, Tor Browser, Android apps on okhttp. Each profile is a ClientHello,
  HTTP/2 settings, and a set of default headers for the browser and its OS.
- **HTTP/3 and QUIC captured from real browsers** for 53 profiles: QUIC ClientHello,
  transport parameters, packet layout, HTTP/3 SETTINGS, priorities and QPACK streams.
- **HTTP/1.1, HTTP/2, HTTP/3 and h2c.** Protocol selection is strict: asking for HTTP/2 never
  falls back to HTTP/1.1 without telling you.
- **Sync `Session` and asyncio `AsyncSession`.** Cancelling an asyncio task cancels the
  request on the wire, and Ctrl+C interrupts a blocking call.
- **Typed errors and timeouts.** Split connect, read, write and total timeouts, and streaming
  responses.
- **Cookies like a browser.** An RFC 6265 cookie jar with the public suffix list, which you
  can export and import (Cookie-Editor JSON).
- **Proxies.** HTTP(S), SOCKS4/4a/5/5h, and QUIC through SOCKS5 with the same fingerprint.
- **Custom TLS.** A ClientHello from a JA3 string, low-level TLS, HTTP/2 and ECH options.
- **Diagnostics.** Every response carries the fingerprint that actually went out (JA3, JA4,
  Akamai). You can also diff two fingerprints, save a client setup as a JSON profile, and
  get a redacted trace for bug reports.
- **Prebuilt wheels** with no Python dependencies.

## Install

```bash
pip install yumeclient
```

Wheels are published for Windows x64, Linux x86-64 and aarch64 (glibc 2.17+), and macOS 11+
(universal2), all for Python 3.11+. Other platforms can build the native library from
source; see [installation](https://github.com/october2823/yumeclient/blob/main/docs/installation.md).

## Quickstart

```python
import yumeclient

# one request with the default profile (the latest Chrome)
r = yumeclient.get("https://httpbin.org/get", params={"q": "test"})
print(r.json()["args"])

# a session keeps connections, cookies and headers
with yumeclient.Session(client_identifier="firefox_148", timeout=20) as s:
    s.headers["Referer"] = "https://example.com/"
    r = s.post("https://httpbin.org/post", json={"name": "yume"})
    r.raise_for_status()
    print(r.http_version, r.json()["json"])
```

```python
import asyncio
from yumeclient import AsyncSession

async def main():
    async with AsyncSession(client_identifier="safari_ios_18_5") as s:
        responses = await asyncio.gather(*(s.get(f"https://httpbin.org/get?i={i}") for i in range(10)))
        print([r.status_code for r in responses])

asyncio.run(main())
```

```python
from yumeclient import Session, TimeoutConfig, ReadTimeout, ProxyError

with Session(proxy="socks5://user:pass@127.0.0.1:1080",
             timeout=TimeoutConfig(total=60, connect=5, read=15),
             http_version="3") as s:            # HTTP/3 racing TCP, like Chrome
    try:
        with s.get("https://example.com/large.bin", stream=True) as r:
            for chunk in r.iter_bytes(1 << 20):
                ...
    except (ReadTimeout, ProxyError) as e:
        print(e.kind, e.stage, e.retryable)
```

## Documentation

The documentation is in English and Russian; every page links to its translation at the top.

- **[USAGE.md](https://github.com/october2823/yumeclient/blob/main/USAGE.md)**: a guide with examples for common tasks.
- **[docs/](https://github.com/october2823/yumeclient/blob/main/docs/index.md)**: the reference, one page per topic:
  - [sessions](https://github.com/october2823/yumeclient/blob/main/docs/sessions.md), [requests](https://github.com/october2823/yumeclient/blob/main/docs/requests.md) and [responses](https://github.com/october2823/yumeclient/blob/main/docs/responses.md);
  - [profiles](https://github.com/october2823/yumeclient/blob/main/docs/profiles.md) and [protocols](https://github.com/october2823/yumeclient/blob/main/docs/protocols.md);
  - [custom TLS](https://github.com/october2823/yumeclient/blob/main/docs/custom-tls.md), [timeouts and errors](https://github.com/october2823/yumeclient/blob/main/docs/timeouts-and-errors.md),
    [cookies](https://github.com/october2823/yumeclient/blob/main/docs/cookies.md) and [proxies](https://github.com/october2823/yumeclient/blob/main/docs/proxies.md);
  - [diagnostics](https://github.com/october2823/yumeclient/blob/main/docs/diagnostics.md), [limitations](https://github.com/october2823/yumeclient/blob/main/docs/limitations.md) and
    [development](https://github.com/october2823/yumeclient/blob/main/docs/development.md).
- **[examples/](https://github.com/october2823/yumeclient/tree/main/examples/)**: runnable scripts. All of them run in CI against a local server.
- **[CHANGELOG.md](https://github.com/october2823/yumeclient/blob/main/CHANGELOG.md)**: release notes.

The API itself has docstrings and type hints (`py.typed`).

## Contributing

Bug reports, fingerprint captures and pull requests are welcome, in English or Russian. See
[CONTRIBUTING.md](https://github.com/october2823/yumeclient/blob/main/CONTRIBUTING.md). Report vulnerabilities privately, as described in
[SECURITY.md](https://github.com/october2823/yumeclient/blob/main/SECURITY.md). Everyone taking part follows the
[Code of Conduct](https://github.com/october2823/yumeclient/blob/main/CODE_OF_CONDUCT.md).

## How it works

The Python package is a thin layer: sessions, headers, the cookie jar, validation and
errors. It calls a Go library through `ctypes`. The Go side is built on
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client),
[uTLS](https://github.com/refraction-networking/utls) and
[quic-go](https://github.com/quic-go/quic-go). Those modules are vendored with patches in
`native/third_party/`, and CI checks that the copies match upstream plus the patches. The Go
side builds each profile's handshakes, keeps connection pools, follows redirects with
per-hop cookies, and measures the fingerprint of what it sent.

The library reproduces what a client sends over the network. It does not reproduce the
TCP/IP stack of another OS, JavaScript, or browser behaviour. See
[limitations](https://github.com/october2823/yumeclient/blob/main/docs/limitations.md).

## Development

```bash
./scripts/build-native.ps1        # Windows; Linux/macOS: sh ./scripts/build-native.sh
pip install -e ".[test]"
python -m pytest -q               # offline: local HTTP/1.1, HTTP/2, HTTP/3 and proxy servers
```

Building needs Go 1.24.1+ and a C compiler. See [development](https://github.com/october2823/yumeclient/blob/main/docs/development.md) for
patching upstream modules, recording browser fingerprints, and releases.

## License

MIT, see [LICENSE](https://github.com/october2823/yumeclient/blob/main/LICENSE). The native library includes code from bogdanfinn/tls-client
(a BSD-style license, [UPSTREAM-LICENSE](https://github.com/october2823/yumeclient/blob/main/UPSTREAM-LICENSE)), Go's `net/http` and uTLS
(BSD 3-clause), and quic-go and qpack (MIT). This product includes software developed by
Bogdan Finn. Details are in [THIRD_PARTY_NOTICES.md](https://github.com/october2823/yumeclient/blob/main/THIRD_PARTY_NOTICES.md).

Use it for testing, research and interoperability, and follow the terms of the services you
send requests to.

Contributors: [randomtempusername123](https://github.com/randomtempusername123).
