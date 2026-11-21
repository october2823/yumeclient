# Timeouts, errors and cancellation

**English** | [Русский](ru/timeouts-and-errors.md)

## Timeouts

The timeout is set for the session (`Session(timeout=...)`) and can be overridden for a single
request (`s.get(url, timeout=...)`). It is not part of the session's transport settings, so
changing the timeout in a request does not create new connections.

| Value | Meaning |
|---|---|
| `30` (default) | `total` = 30 s for the whole exchange |
| a number `x` | `total` = `x` |
| `(connect, read)` | stage limits without an overall limit; `None` in the tuple means no limit for that stage |
| `TimeoutConfig(total=..., connect=..., read=..., write=...)` | any combination |
| `None` | no limits |

Values are positive numbers in seconds. `0`, negative numbers, strings and a tuple of another
length raise `SessionConfigurationError`, for example
`timeout total must be a positive number or None, got 0`.

```python
from yumeclient import Session, TimeoutConfig

with Session(timeout=TimeoutConfig(connect=5, read=30, total=120)) as s:
    s.get("https://httpbin.org/get")
    s.get("https://httpbin.org/delay/2", timeout=3)               # only for this request
    s.get("https://httpbin.org/drip?duration=20", timeout=(5, 2))  # a pause in the body > 2 s is an error
```

### Stages

| Stage | What it limits |
|---|---|
| `connect` | DNS, the proxy connection and CONNECT or the SOCKS handshake, TCP, TLS. Counted separately for each new connection, including on redirect hops |
| `write` | sending the request headers and body |
| `read` | waiting for the response headers and the **pause** between body chunks. A slow but live response is not cut off |
| `total` | the whole exchange, including redirects and reading the body |

- `stream=True`: `total` applies until the headers arrive. After that, the body is limited by
  the `read` pause, or, if `read` is not set, by a pause as long as `total`. The total download
  time is not limited.
- The stages are the same for HTTP/1.1, HTTP/2 and HTTP/3. For HTTP/3, `connect` is the QUIC
  handshake. In HTTP/3 and TCP racing (`http_version="3"`) the TCP connection starts after
  300 ms, so a `connect` below 300 ms expires before TCP can start.
- A reused connection does not go through `connect`: the stage timeout counts only when a new
  connection is opened.
- Even without timeouts, opening a TCP connection (with DNS) and the CONNECT exchange with an
  HTTP(S) proxy take at most 240 s each; a `connect` above 240 s does not extend these steps.

The exception tells you which stage expired: `ConnectTimeout`, `WriteTimeout`, `ReadTimeout`
(attribute `stage`: `read` means it waited for the headers, `body` means it waited for the next
body chunk) or `Timeout` for `total`.

## Exception hierarchy

```
RuntimeError
└── TLSClientError                         library errors, base class
    ├── SessionConfigurationError (+ ValueError)   invalid session parameters, before the network
    └── RequestError                       error of a specific request
        ├── InvalidRequestError (+ ValueError)     request rejected before the network
        ├── ConnectError (+ ConnectionError)       connection not established
        │   ├── ProxyError
        │   ├── TLSError
        │   ├── ProtocolError
        │   └── ConnectTimeout (+ Timeout)
        ├── ConnectionClosed (+ ConnectionError)   connection dropped after it was established
        ├── Timeout (+ TimeoutError)
        │   ├── ConnectTimeout
        │   ├── ReadTimeout
        │   └── WriteTimeout
        ├── RequestCancelled                       request cancelled
        ├── ResponseTooLarge                       body larger than max_content_size
        ├── TooManyRedirects                       more than 20 redirects
        ├── StreamClosed                           stream already read or closed
        └── HTTPStatusError                        Response.raise_for_status()
```

Thanks to the built-in base classes, code written for the standard exceptions works too:
`except TimeoutError`, `except ConnectionError`, `except ValueError`.

### `kind` and when it is raised

| Class | `kind` | When |
|---|---|---|
| `ConnectError` | `connect`, `dns` | connection refused, host not found, network unreachable |
| `ProxyError` | `proxy` | proxy unreachable, CONNECT/SOCKS refused, wrong proxy credentials |
| `TLSError` | `tls` | handshake failed, certificate failed verification, server rejected the ClientHello |
| `ProtocolError` | `protocol` | the server picked the wrong protocol: `http_version="2"` → HTTP/1.1, `keep_alpn` → h2, h2c not supported. The request was not sent |
| `ConnectionClosed` | `connection_closed` | connection closed or reset after it was established, the server cut off the response |
| `Timeout` | `timeout` | `total` expired |
| `ConnectTimeout` | `connect_timeout` | `connect` expired |
| `ReadTimeout` | `read_timeout` | `read` expired |
| `WriteTimeout` | `write_timeout` | `write` expired |
| `RequestCancelled` | `cancelled` | `close(grace=...)` closed the session while the request was in flight. A cancelled asyncio task gets `asyncio.CancelledError`, not this exception |
| `ResponseTooLarge` | `body_too_large` | the decompressed body is larger than `max_content_size` |
| `TooManyRedirects` | `too_many_redirects` | more than 20 redirects in a row |
| `InvalidRequestError` | `invalid_request`, `configuration` | invalid URL, method or header; the session cannot be built (for example, a JA3 with an unsupported extension) |
| `StreamClosed` | `stream_closed`, `stream_not_read` | reading a stream that is already closed; `r.content` on an async stream before `await r.aread()` |
| `HTTPStatusError` | `http_status` | `r.raise_for_status()` with a status of 400–599 |

### `RequestError` attributes

| Attribute | What it holds |
|---|---|
| `kind` | machine-readable error kind (table above) |
| `stage` | `connect`, `write`, `read`, `body`, `request` (an error in the request itself: invalid URL or method, too many redirects) or `None` |
| `method`, `url` | the request. The username and password are removed from the URL |
| `elapsed` | seconds from the start of the request to the error |
| `request_id` | native request id, the same as `Response.request_id` |
| `retryable` | `True` for timeouts, `connect`, `dns`, `proxy`, `connection_closed` |
| `detail` | the error text without the request context |
| `response` | the response (only for `HTTPStatusError`) |
| `__cause__` | the original Go error text |

Usernames, passwords, and `Basic` and `Bearer` tokens are cut out of the error text, so the
message is safe to write to a log.

## Retries

`retryable=True` means the error is temporary and the same request may succeed. It does not
mean a retry is safe: with `connection_closed`, `read_timeout` and `timeout` the server may
have already processed the request. Retry automatically only idempotent requests (GET, HEAD,
PUT, DELETE, OPTIONS) or requests with `Idempotency-Key`.

```python
import time
from yumeclient import RequestError, Session

def get_with_retries(s: Session, url: str, attempts: int = 3):
    for attempt in range(attempts):
        try:
            return s.get(url, timeout=10)
        except RequestError as e:
            if not e.retryable or attempt == attempts - 1:
                raise
            time.sleep(0.5 * 2 ** attempt)
```

The library itself retries a request only where a browser does:

- a connection from the pool turned out to be closed by the server: the request is retried on a
  new connection if nothing from it was written to the old one (then any method, and the body
  is sent again) or if it is idempotent;
- with `http_version="3"`, the HTTP/3 connection did not open or closed before sending: the
  request goes through protocol racing again (details in
  [Protocols](protocols.md#http3-and-quic)).

The library retries a request that may have reached the server only if it is idempotent: GET,
HEAD, OPTIONS, TRACE or a request with an `Idempotency-Key` header (as Go's `net/http` does;
PUT and DELETE are not retried by the library).

## HTTP status codes

4xx and 5xx responses are not exceptions: `s.get(...)` returns a `Response`. To check the
status:

```python
r = s.get("https://httpbin.org/status/404")
print(r.ok)              # False (ok = 200–399)
r.raise_for_status()     # HTTPStatusError: 404 ...; the response is in e.response
```

## Cancellation

- **asyncio.** Cancelling the task (`task.cancel()`, `asyncio.wait_for`, `asyncio.timeout`,
  `TaskGroup`) aborts the request in Go right away, both while connecting and while reading
  the body. The connection is closed, and the task gets `CancelledError`.
- **Closing the session.** `close(grace=5.0)` waits `grace` seconds for in-flight requests,
  then cancels them (`RequestCancelled`). With `grace=None`, closing waits until all requests
  finish. New requests to a closed session raise `SessionConfigurationError("session is closed")`.
- **Ctrl+C.** In synchronous code on the main thread, `KeyboardInterrupt` interrupts a request
  and stream reading right away, not after the response arrives. The native request is
  cancelled as well.

```python
import asyncio
from yumeclient import AsyncSession

async def main():
    async with AsyncSession() as s:
        try:
            await asyncio.wait_for(s.get("https://httpbin.org/delay/10"), 1)
        except asyncio.TimeoutError:
            print("cancelled after 1 s, connection closed")

asyncio.run(main())
```

## Body size limit

`max_content_size` (in the session or in a request) limits the **decompressed** body in bytes.
It protects against compression "bombs": a gigabyte of zeros in gzip takes about a megabyte.

```python
with Session(max_content_size=10 * 1024 * 1024) as s:
    s.get("https://example.com/huge")                          # ResponseTooLarge if larger than 10 MiB
    s.get("https://example.com/huge", max_content_size=2**30)  # a custom limit for this request
```

With `stream=True` the limit is checked as the body is read. `max_content_size=None` in a
request means "same as the session"; by default there is no limit.

## Configuration errors

`SessionConfigurationError` inherits from `ValueError` and is raised in the constructor: an
unknown profile or OS, conflicting protocol settings, invalid TLS parameter values. The message
names the parameter and suggests a fix:

```
unknown client_identifier 'chrome_999'; did you mean: chrome_109, chrome_152, chrome_150
force_http1=True conflicts with http_version='2'
grease requires ja3_string
```

If the native library is not found, the first request raises `TLSClientError` with the path
where it was looked for ([Installation](installation.md#custom-native-library)).
