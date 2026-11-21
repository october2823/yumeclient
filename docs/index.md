# yumeclient documentation

**English** | [Русский](ru/index.md)

yumeclient is a Python HTTP client with a `requests`-style API that sends requests the way real
browsers and mobile apps send them: the same TLS ClientHello, the same HTTP/2 and HTTP/3/QUIC
parameters, the same headers in the same order. Under the hood it is a Go library based on
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) and
[uTLS](https://github.com/refraction-networking/utls), loaded through `ctypes`.

The easiest place to start is the [guide with examples](../USAGE.md). This section is a
reference: each page covers one topic completely.

## Sections

| Page | Contents |
|---|---|
| [Installation](installation.md) | wheels, platforms, building from source, `YUMECLIENT_LIBRARY` |
| [Sessions](sessions.md) | `Session` and `AsyncSession`, all constructor parameters, lifecycle, one-shot functions |
| [Requests](requests.md) | request parameters, body (form, JSON, files), headers and their order, redirects |
| [Responses and streaming](responses.md) | `Response`, redirect history, `connection_info`, `fingerprint`, streaming |
| [Profiles](profiles.md) | profile list, `client_os`, default headers, okhttp HTTP layer |
| [Protocols](protocols.md) | `http_version`, HTTP/2, h2c, HTTP/3 and QUIC, ALPN, protocol racing |
| [Custom TLS fingerprint](custom-tls.md) | `ja3_string` and low-level TLS, HTTP/2 and HTTP/3 parameters |
| [Timeouts, errors and cancellation](timeouts-and-errors.md) | `TimeoutConfig`, exception hierarchy, retries, cancellation and Ctrl+C |
| [Cookies](cookies.md) | `CookieJar`, RFC 6265 rules, import and export |
| [Proxies and network](proxies.md) | HTTP(S) and SOCKS proxies, `udp_proxy`, `local_address`, the HTTPS proxy certificate |
| [Diagnostics](diagnostics.md) | `export_profile`/`from_profile`, `fingerprint_diff`, `Response.trace()` |
| [Limitations](limitations.md) | what is deliberately not supported and how that shows |
| [Development](development.md) | building, tests, patches to upstream modules, capturing browser fingerprints, releases |

## How it works

```
Python (yumeclient/)                       Go (native/, c-shared library)
──────────────────────                     ──────────────────────────────────────────
Session / AsyncSession                      yumeclient_call(json) ─► profile: uTLS ClientHello,
  headers, cookies (CookieJar),                                      HTTP/2 SETTINGS, QUIC/HTTP3
  parameter validation, exceptions ──ctypes──► redirect hops, RFC 6265 cookies on every hop
Response (buffer or stream)       ◄─────────  body, history, timings, fingerprint on the wire
```

- **Python** holds the session state: headers, cookie jar, parameters. Each request gets a
  snapshot of the jar; Go picks the cookies for each redirect hop and returns only the changes.
- **Go** holds the connections (pooled per session), builds the profile's ClientHello with
  uTLS, speaks HTTP/1.1, HTTP/2 and HTTP/3, goes through proxies and computes the fingerprint
  (JA3, JA4, Akamai) of what actually went out on the wire.
- Upstream modules (`fhttp`, `tls-client`, `utls`, `quic-go-utls`, `qpack`) live in
  `native/third_party` with patches; see [Development](development.md).

## Conventions

- Times are in seconds (`float`), sizes in bytes.
- Invalid configuration raises `SessionConfigurationError` when the session is created, before
  any network activity. An invalid request raises `InvalidRequestError` before it is sent.
- "Profile" means a `client_identifier` value (`"chrome_152"`, `"firefox_148"`, ...).
- Examples use `https://httpbin.org`. Without internet access, use the local replacement from
  the repository: `python tests/httpbin_local.py 8080`, then `HTTPBIN=http://127.0.0.1:8080`
  for the scripts in [`examples/`](../examples/).
