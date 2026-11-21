# Limitations

**English** | [Русский](ru/limitations.md)

What the library does not do, or does differently from a browser. If you run into one of these
limitations, open an issue that describes your scenario.

## What is emulated and what is not

yumeclient reproduces what a client sends over the network at the TLS, HTTP/1.1, HTTP/2, QUIC
and HTTP/3 levels: the ClientHello, frame parameters and order, headers and their order,
compression, cookies. Out of scope:

- **The TCP/IP fingerprint** (TTL, window size, TCP options: what p0f and similar tools see). It
  is determined by the OS the process runs on, not by the profile.
- **Browser behavior:** JavaScript, loading subresources, request timing and order, Service
  Workers, the HTTP cache. The library sends exactly the requests you make.
- **Client certificates (mTLS)** are not supported.

## HTTP/3 and QUIC

- **53 profiles have HTTP/3 fingerprints** (`profiles.HTTP3_FINGERPRINTS`): Chrome/Chromium
  103–152, Edge, Brave, Opera 89–91, Firefox 102–148. They were captured from real browsers.
- **Safari (macOS, iOS, iPadOS) and mobile apps** (`mesh_*`, `mms_*`, `nike_*`,
  `zalando_*`, `confirmed_*`) have no captures: that would need the devices. They work with
  `http_version="3"`, but emit a warning, and their QUIC and HTTP/3 layers get the library's
  default parameters, that is, a hybrid fingerprint.
- **Clients without HTTP/3** (`profiles.NO_HTTP3`: OkHttp, Conscrypt, cloudscraper, Tor Browser)
  raise `SessionConfigurationError` with `http_version="3"`: the real client does not send
  QUIC.
- **QUIC session resumption and 0-RTT are not emulated.** Every QUIC connection does a full
  handshake. A browser that has a ticket from the server sends `pre_shared_key` and early data.
  For TLS over TCP, resumption works (the `_PSK` profiles).
- **QUIC through SOCKS5 resolves DNS locally:** the UDP relay takes a destination address, not
  a name.

## Safari and app headers

The default headers of Safari (`safari_*`, `mms_*`) and of the mobile apps were not captured
from devices: they are a short plausible set in lower case, without `Sec-Fetch-*` and
`Priority`. The TLS and HTTP/2 fingerprints of these profiles do not depend on this. For
details and how to set the headers yourself, see [Profiles](profiles.md#default-headers).

## Connections

- **A connection that silently disappears** (NAT, a network change, no RST) is noticed only by
  the OS kernel. Until then, requests on such an HTTP/1.1 or HTTP/2 connection end with a
  timeout, and a timeout does not reset the connection. A periodic PING on idle (like
  `ReadIdleTimeout` in Go) is not enabled: the server sees it and it does not look like a
  browser. `session.reset_connection()` helps.
- **h2c is prior knowledge only** (`http_version="2"` on `http://`). Upgrading through
  `Upgrade: h2c` is not supported. Without `http_version="2"`, `http://` always goes over
  HTTP/1.1, as in browsers.
- **WebSocket, HTTP/2 server push and HTTP/1.1 pipelining** are not supported.
- **DNS** uses the system resolver (through Go). DNS-over-HTTPS and a custom resolver cannot be
  configured.

## Proxies

- HTTP proxy authentication is Basic only. Digest, NTLM and Negotiate are not supported.
- SOCKS4 resolves the name locally and does not send a user id. Use `socks4a://` or
  `socks5://`.
- The HTTPS proxy's certificate is not verified (see [Proxies and network](proxies.md)).
- The environment variables `HTTP_PROXY`, `NO_PROXY` and so on are not read; there is no
  exception list.

## Request and response bodies

- **The request body is held in memory in full.** `data=`, `json=` and `files=` are assembled
  into bytes before sending (multipart too); there is no streaming upload. The body is passed
  to the native part as base64 inside JSON, so peak memory use is about 2–3 times the body
  size.
- **Without `stream=True`, the response body is read in full.** For large responses use
  `stream=True` and `iter_bytes()`; to protect against responses that are too large, use
  `max_content_size` (see [Responses and streaming](responses.md)).

## Custom JA3

- **`X25519MLKEM768` without a key share for it.** If the JA3 declares group `4588` but no key
  share is sent for it (for example, the JA3 has no X25519), and the server picks it through a
  HelloRetryRequest, the handshake fails: utls, like Go, does not support ML-KEM in HRR.
  Chrome always declares X25519 and sends a key share for ML-KEM; set it up the same way.
- **Extensions that the JA3 mapper does not know** (the full list is in
  [Custom TLS fingerprint](custom-tls.md)) raise `InvalidRequestError` on the first request.

## AsyncSession

`AsyncSession` runs native calls in a thread pool (64 threads per process by default; use
`AsyncSession.configure_executor(workers=...)` before the first request). Each request holds a
thread until the response headers are received (without `stream`, until the body is read).
No more requests run at once than there are threads in the pool; the rest wait in a
queue.

## Platforms

Prebuilt wheels: Windows x86-64, Linux x86-64 and aarch64 (glibc 2.17+, manylinux2014),
macOS 11+ (universal2: arm64 and x86-64). Python 3.11+.

There are no prebuilt builds for Alpine/musl, Windows on ARM and 32-bit systems. On them you
can build the native library from source (Go 1.24.1+ and a C compiler); see
[Installation](installation.md).

## Network stack

It is built on the `fhttp`, `tls-client`, `utls`, `quic-go-utls` and `qpack` modules with
patches. Their copies live in `native/third_party`, and the changes in
`native/third_party/patches/*.patch`. CI compares the copies with upstream and checks that
there are no unrelated changes: `python scripts/third_party.py check` (see
[Development](development.md)).
