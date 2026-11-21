# Sessions

**English** | [Русский](ru/sessions.md)

A session is a client profile (TLS, HTTP/2, HTTP/3, headers), a connection pool, a cookie jar
and a set of default parameters. Requests in one session reuse connections and cookies, like
tabs of one browser.

```python
from yumeclient import Session, AsyncSession

with Session(client_identifier="chrome_152") as s:
    r = s.get("https://httpbin.org/get")


async def main():
    async with AsyncSession(client_identifier="firefox_148") as s:
        r = await s.get("https://httpbin.org/get")
```

## Session and AsyncSession

| | `Session` | `AsyncSession` |
|---|---|---|
| Call | `r = s.get(url)` | `r = await s.get(url)` |
| Context manager | `with Session() as s:` | `async with AsyncSession() as s:` |
| Concurrency | threads (`concurrent.futures`) | `asyncio.gather`, `TaskGroup` |
| Where it runs | in the calling thread | a shared thread pool, `AsyncSession.configure_executor(n)` |
| Closing | `s.close(grace=5.0)` | `await s.close(grace=5.0)` |
| Resetting connections | `s.reset_connection()` | `await s.reset_connection()` |

Both classes are facades over the same engine: parameters, headers, cookies and transport
behavior are the same. In asyncio code use only `AsyncSession`: a sync `Session` blocks the
event loop for the duration of the request.

Methods of both classes: `request(method, url, **kwargs)`, `get`, `head`, `post`, `put`,
`patch`, `delete`, `options`. Request parameters are in [Requests](requests.md).

`Session` is thread-safe: one session can be used from several threads, and requests run in
parallel over a shared connection pool.

## Constructor parameters

All parameters are keyword-only. The defaults are chosen so that the session looks like a
current Chrome on Windows.

### Profile and headers

| Parameter | Default | Description |
|---|---|---|
| `client_identifier` | `"chrome_152"` | client profile: TLS ClientHello, HTTP/2, HTTP/3, default headers. List in [Profiles](profiles.md) |
| `client_os` | from the profile | `"windows"`, `"macos"`, `"android"`, `"ios"`. Changes only the default headers (User-Agent, client hints), not TLS |
| `header_style` | from the profile | `"okhttp"`: the okhttp 4.x HTTP layer (the default for `okhttp4_*` and Conscrypt profiles); `"raw"`: headers exactly as passed |
| `headers` | `None` | session headers: added to the profile's default headers (`update`); to replace the whole set, assign `s.headers = {...}` after creation |
| `header_order` | `None` | header order on the wire; by default, the insertion order of `session.headers` |
| `cookies` | `None` | initial cookies: a `dict`, a list of dicts (a browser export) or a `CookieJar` |
| `random_tls_extension_order` | `True` | shuffle ClientHello extensions for each connection, like Chromium. Has no effect on non-Chromium profiles; does affect `ja3_string`, see [Custom TLS fingerprint](custom-tls.md) |

### Protocol

| Parameter | Default | Description |
|---|---|---|
| `http_version` | `"auto"` | `"auto"`, `"1.1"`, `"2"`, `"3"` (also `1`, `2`, `3`, `"h2"`, `"h3"`, `"quic"`). See [Protocols](protocols.md) |
| `force_http1` | `False` | same as `http_version="1.1"` |
| `keep_alpn` | `False` | with `http_version="1.1"`: keep the profile's ALPN (`h2,http/1.1`) in the ClientHello |
| `disable_http3` | `False` | disallow HTTP/3 |
| `disable_session_tickets` | `False` | do not resume TLS sessions (every connection does a full handshake) |

### Network

| Parameter | Default | Description |
|---|---|---|
| `proxy` | `None` | `http://`, `https://`, `socks5://`, `socks5h://`, `socks4://`, `socks4a://`, with `user:pass@`. See [Proxies and network](proxies.md) |
| `udp_proxy` | `None` | a separate proxy for QUIC: `socks5://` or `socks5h://` |
| `timeout` | `30` | a number (limit for the whole exchange), `(connect, read)`, `TimeoutConfig` or `None`. See [Timeouts](timeouts-and-errors.md) |
| `verify` | `True` | verify the server certificate |
| `server_name_overwrite` | `None` | name to send in SNI instead of the host from the URL; the certificate is verified for this name |
| `local_address` | `None` | local address for outgoing connections, `"IP:port"` (port `0` means any) |
| `max_content_size` | `None` | maximum size of the decompressed response body in bytes (`ResponseTooLarge`) |

### Custom TLS fingerprint

Only together with `ja3_string` (and without `client_identifier`): `ja3_string`,
`supported_signature_algorithms`, `supported_versions`,
`key_share_curves`, `key_share_data`, `alpn_protocols`, `alps_protocols`,
`cert_compression_algos`, `trust_anchors_payload`, `tls_extension_order`, `ech_config_list`,
`grease`, `psk_mode`, `h2_settings`, `h2_settings_order`, `connection_flow`,
`pseudo_header_order`, `priority_frames`, `header_priority`. Without `ja3_string` they raise
`SessionConfigurationError`. `fill_custom_with_chrome_defaults` (default `True`) is simply not
used without `ja3_string`. Details in [Custom TLS fingerprint](custom-tls.md).

### Parameter validation

Parameters are validated in the constructor, before any network activity. An unknown profile
or OS, conflicting protocol settings (`force_http1=True` with `http_version="2"`,
`http_version="3"` with an HTTP proxy, and so on), custom JA3 parameters without `ja3_string`,
invalid values: all raise `SessionConfigurationError` (a subclass of `ValueError`) with an
explanation:

```python
from yumeclient import Session, SessionConfigurationError

try:
    Session(client_identifier="chrome_999")
except SessionConfigurationError as e:
    print(e)    # unknown client_identifier 'chrome_999'; did you mean: chrome_109, chrome_152, chrome_150
```

## What you can change on a live session

The session transport is fixed: profile, protocol, proxy, TLS parameters, default timeout.
Assigning such an attribute raises `AttributeError` instead of being silently ignored:

```python
s = Session()
s.proxy = "socks5://127.0.0.1:1080"   # AttributeError: proxy is fixed for the lifetime of a session
```

These can be changed freely:

- `s.headers`, the header dict (`s.headers.update(...)`, `s.headers["X"] = ...`,
  `del s.headers["X"]`, `s.headers = {...}`);
- the contents of `s.cookies` (`CookieJar`).

For a different configuration, create a new session. To move the identity (profile, headers,
TLS parameters) into a session with a different proxy, use
`Session.from_profile(s.export_profile(), proxy=...)`; see [Diagnostics](diagnostics.md).

A single request can be given `proxy=`, `timeout=`, `headers=`, `cookies=`, `header_order=`,
`allow_redirects=`, `stream=`, `max_content_size=`, `host_override=`. A request with `proxy=`
goes through a separate native client with its own connection pool; the profile, headers and
cookies come from the session.

## Properties

| Property | Type | |
|---|---|---|
| `s.client_identifier` | `str` | profile (`""` for `ja3_string`) |
| `s.client_os` | `str` | OS of the default headers |
| `s.header_style` | `str` | `"okhttp"` or `"raw"` |
| `s.headers` | `Headers` | session headers, a case-insensitive dict |
| `s.cookies` | `CookieJar` | the session cookie jar |

## Lifecycle

### Closing

`with`/`async with` close the session automatically. Explicitly:

```python
s.close()               # sync
await a.close()         # async
```

`close(grace=5.0)` gives requests that are still running in other threads or tasks `grace`
seconds to finish, then cancels them (`RequestCancelled`); `grace=None` waits until they
finish. Open streaming responses are closed and connections are released. After closing, any
request raises `SessionConfigurationError("session is closed")`. Calling `close()` again does
nothing.

A session that was not closed releases its connections when the garbage collector collects
it (since 0.8.1; before that they stayed open until the process exited). When that happens is
not known in advance, so close sessions explicitly.

### New connections

`s.reset_connection()` (`await a.reset_connection()` for async) closes the session's
connections: the next request opens a new connection with a new handshake. Cookies and
headers stay. This is useful after a network change or when a connection has "hung" without
an RST (see [Limitations](limitations.md)).

### AsyncSession thread pool

`AsyncSession` runs native calls in a shared pool of 64 threads: up to 64 requests from all
`AsyncSession`s in the process can be in flight at once, the rest wait in a queue. To change
the size, do it before the first request:

```python
from yumeclient import AsyncSession

AsyncSession.configure_executor(256)
```

After requests have started, the call raises `SessionConfigurationError`.
`await yumeclient.close_runtime()` stops the pool when the program exits (optional).

### Cancellation and Ctrl+C

- Cancelling an asyncio task (`task.cancel()`, `asyncio.wait_for`, `asyncio.timeout`,
  `TaskGroup`) aborts the native request immediately, at any stage: DNS, connecting, TLS,
  waiting for the response, reading the body.
- Ctrl+C in the main thread interrupts a sync request and stream reading immediately
  (`KeyboardInterrupt`); the native request is cancelled and the connection is closed.

## One-shot functions

For single requests without a session:

```python
import yumeclient

r = yumeclient.get("https://httpbin.org/get", client_identifier="firefox_148", timeout=10)
r = yumeclient.post("https://httpbin.org/post", json={"a": 1})


async def main():
    r = await yumeclient.aget("https://httpbin.org/get")
```

Functions: `request`, `get`, `head`, `post`, `put`, `patch`, `delete`, `options` and the async
variants `arequest`, `aget`, `ahead`, `apost`, `aput`, `apatch`, `adelete`, `aoptions`. They
accept both session parameters and request parameters; each one creates a session and closes
it after the response. With `stream=True` the session is closed together with the response.

For a series of requests to one site, one-shot functions are slower and more noticeable: each
call is a new connection and a full TLS handshake, and cookies are not kept.
