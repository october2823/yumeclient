# CHANGELOG

**English** | [Русский](CHANGELOG.ru.md)

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.2] — 2026-11-21

### Added
- **English documentation.** Every page now exists in English and Russian. English pages are at
  the usual paths (`README.md`, `USAGE.md`, `CHANGELOG.md`, `docs/*.md`, `examples/README.md`),
  Russian ones next to them (`*.ru.md`, `docs/ru/*.md`). Each page links to its translation
  under the title. `tests/test_docs_i18n.py` checks that both versions have the same structure
  (headings, code blocks, tables, lists, links), that English pages contain no Russian text and
  that every `#anchor` in links exists.
- **Contributing guide and security policy**: `CONTRIBUTING.md` and `SECURITY.md` (with Russian
  versions), issue forms (bug report, fingerprint mismatch, feature request) and a pull request
  template. Vulnerabilities are reported privately through GitHub security advisories.

### Changed
- The Russian pages moved: `docs/X.md` to `docs/ru/X.md`, `USAGE.md` to `USAGE.ru.md`,
  `CHANGELOG.md` to `CHANGELOG.ru.md`, `examples/README.md` to `examples/README.ru.md`. Old
  links (from PyPI and `pyproject.toml`) now open the English version.
- The sdist includes every `.md` file from the repository root.

### Fixed
- **Opening a connection was cut at 30 s** although the request allowed more. The session's
  dialers got their limit from the first request (`max(30 s, connect)`), so `timeout=None`, a
  larger `connect` in a later request, or a proxy that answers CONNECT slowly ended in
  `ConnectTimeout` after 30 s. Now opening one connection (DNS, TCP, the proxy tunnel) is limited
  only by the request's timeouts and by a fixed 240 s.
- **`local_address` was ignored** for `https://` requests through an `https://` proxy: the
  connection to the proxy was not bound.
- **An `http://` proxy that never answered CONNECT** kept the connection open for 30 s after
  the request had already failed with a timeout or was cancelled. The CONNECT exchange now
  ends together with the request. A refused CONNECT through an `https://` proxy now reports
  `Proxy responded with non 200 code: ...`, as with an `http://` proxy.
- `LICENSE` lacked the last paragraph of the MIT license ("IN NO EVENT SHALL ..."), so GitHub
  did not recognize the license.
- Documentation links to headings that did not exist: from `protocols.md` to `development.md`
  and from `responses.md` to `diagnostics.md`.
- `custom-tls.md`: PRIORITY frames after SETTINGS are sent by the `firefox_102`–`firefox_123`
  profiles, not by "Firefox before 135".
- This changelog: the dates of 0.1.6–0.5.1 now match the PyPI uploads (0.2.0–0.2.4 were
  dated a month late), the missing 0.4.3 and 0.4.4 are added, and the version headings link
  to the releases.

## [0.8.1] — 2026-11-21

### Added
- **Documentation.** A `docs/` reference (14 pages: sessions, requests, responses, profiles,
  protocols, custom TLS fingerprint, timeouts and errors, cookies, proxies, diagnostics,
  limitations, installation, development), `USAGE.md` rewritten as a guide with examples,
  an English README for GitHub and PyPI, and `THIRD_PARTY_NOTICES.md` with the licenses of
  the upstream modules.
- **Examples** in `examples/` (10 scripts: quickstart, asyncio, profiles and headers,
  cookies, streaming, file upload, errors and retries, proxies, fingerprint, custom JA3).
  All of them run in the tests against a local httpbin replacement (`tests/httpbin_local.py`);
  Python snippets in the documentation are checked for syntax, and links for existence.
- `TooManyRedirects` (`kind="too_many_redirects"`): more than 20 redirects. Previously a
  `RequestError` without a type.
- `h2_settings` and `h2_settings_order` accept any SETTINGS identifier: RFC 9113 names,
  `ENABLE_CONNECT_PROTOCOL`, `NO_RFC7540_PRIORITIES` (sent by Firefox), `UNKNOWN_SETTING_<n>`
  and numbers (`9`, `"0x9"`).

### Fixed
- **Custom JA3 with extensions 22 (encrypt_then_mac) and 51764 (trust anchors)**, such as the
  JA3 of `chrome_146`/`chrome_152` and `cloudscraper` taken from their own fingerprint, failed
  with a confusing `TLSError: unknown ClientHelloID: Custom-ja3`. They work now. A JA3 with an
  extension that cannot be built raises `InvalidRequestError` with the extension number. JA3
  parsing no longer prints `attention ...` to stdout.
- **`trust_anchors_payload` and `ech_config_list` were ignored** since the first version. Now
  the first one goes into extension 51764, and the second one enables real ECH (the inner
  ClientHello is encrypted with the server's key; without it ECH stays GREASE). Both are
  validated when the session is created.
- **`CookieJar` lost cookies under parallel requests**: `AsyncSession` applies responses
  from pool threads, and concurrent changes overwrote each other (8 threads × 400 cookies
  left 585 of 3200 in the jar). The jar is now thread-safe; `copy.deepcopy` and `pickle`
  work.
- **Redirects like in a browser.** On every hop Go added its own `Referer` with the redirect
  URL (browsers and `requests` do not change it); now it does not, and your `Referer` is
  carried over as is. When the method changes to GET, `Content-Type`, `Content-Encoding`,
  `Content-Language`, `Content-Location`, `Content-Length` and `Origin` are dropped together
  with the body (as in Chromium). 301 and 302 change only `POST` to GET (Fetch standard);
  previously `PUT`, `PATCH` and `DELETE` were also turned into a GET without a body.
- **Response headers as the server sent them.** Over HTTP/1.1 (when the request had gzip in
  `Accept-Encoding`, which is almost always) and over HTTP/3, `Content-Length` and
  `Content-Encoding` were missing from the response; over HTTP/2 they stayed. The body is
  still decompressed.
- **`supported_signature_algorithms`** with `"0x0403"` failed on the first request; now
  names, numbers and hex with or without `0x` are accepted, and an unknown name raises
  `SessionConfigurationError`.
- **`pseudo_header_order`** with a typo, or an incomplete one, sent requests without
  `:authority` and `:scheme`. Now all four pseudo-headers are required (`":method"`,
  `"method"` or `"m"`).
- **`tls_extension_order`** put ECH, ALPS (old and new), NPN, PSK and a number of other
  extensions at the end: their numbers were mapped incorrectly.
- **`h2_settings` without `h2_settings_order`** were sent in random order; now they are sent
  in dict order.
- **`connection_flow` without `ja3_string`** was silently ignored; now it raises
  `SessionConfigurationError`, like the other custom TLS parameters.
- **`udp_proxy`** with custom JA3 also replaced the TCP proxy, with profiles it was ignored,
  and `http_version="3"` with an HTTP proxy was rejected even together with `udp_proxy`. Now
  QUIC goes through `udp_proxy` (SOCKS5), and TCP through `proxy`.
- **QUIC through SOCKS5 gave itself away**: a 4-byte Source Connection ID (Chrome uses 0), no
  `google_initial_rtt` and no stage timeouts. Now the handshake through a proxy is the same
  as a direct one.
- **An invalid request URL** (not `http(s)://`, no host, an invalid port) raised
  `ConnectError` with `retryable=True`, so retry code based on `retryable` retried it forever.
  Now it raises `InvalidRequestError` (`stage="request"`) before touching the network.
- **A custom JA3 with `X25519MLKEM768` (4588)**, that is, the JA3 of any modern Chrome,
  silently stayed on TCP with `http_version="3"`. Now HTTP/3 works: the QUIC ClientHello is
  taken from the Chrome capture (or from quic-go with `fill_custom_with_chrome_defaults=False`),
  not from the JA3.
- **An unclosed session** held its connections until the process exited. Now the garbage
  collector releases them (closing the session explicitly is still the right thing to do).
- `default_headers()` for Safari, apps and okhttp returned a plain `dict` (case-sensitive
  lookup); now it always returns `Headers`.
- **An invalid proxy URL** (no scheme, `ftp://`, no port for SOCKS, a malformed port) raised
  `InvalidRequestError: client creation failed` on the first request; now it raises
  `SessionConfigurationError` with a clear message when the session is created (and for a
  per-request `proxy=`).
- `http://` through an `https://` proxy verified the proxy certificate, while `https://` did
  not. Now neither does (the proxy certificate was never verified for HTTPS targets; the
  target is verified according to `verify`).

### Changed
- **The redirect limit is 20, as in browsers** (Fetch standard, Chromium). Previously Go's
  limit applied: an error on the 10th redirect, so only 9 were followed.
- `udp_proxy` accepts only `socks5://` and `socks5h://` (`udp://` was accepted but did not
  work).
- Package metadata: description, classifiers, keywords, documentation links, the license in
  SPDX format (`MIT`), and the upstream license files in the wheel.
- The old examples (`basic_requests.py`, `cookies_flow.py`, `profiles_and_os.py`) were
  replaced with new ones.

## [0.8.0] — 2026-11-20

### Added
- **Browser-like HTTP/3 and QUIC for 53 profiles.** Previously the QUIC handshake of every
  profile was quic-go's: its ClientHello (the same JA4 `q…` for all), its transport
  parameters, its Initial packets; only 13 profiles had HTTP/3 parameters. Now, for
  Chrome 103–152, Edge 99/101/131/latest, Brave 146, Opera 89–91 and Firefox 102–148
  (including `_PSK`), everything is taken from captures of the browsers themselves
  (`native/h3profiles.json`):
  - the ClientHello inside QUIC (QUIC has its own: TLS 1.3 only, no GREASE in Chromium),
    extension shuffling as in Chromium (Firefox since 135), ECH GREASE;
  - transport parameters: the set, the values, the order (shuffled in Chromium and Firefox
    104–135), the GREASE parameter, `version_information`, `google_connection_options`,
    `google_initial_rtt` on repeat connections;
  - Initial packets: Connection ID lengths (random in Firefox), the first packet number
    (random in Firefox 146+, as in neqo), the datagram size (1250 in Chromium, 1357/1252
    in Firefox), padding (PADDING frames in Chromium, zeros after the packet in Firefox),
    how the ClientHello is laid out across packets: Chromium chaos protection (≤122,
    124–131, 133+: three different schemes) and Firefox 146+ SNI slicing;
  - HTTP/3: SETTINGS and their order, the GREASE frame, the order in which QPACK streams
    are opened, PRIORITY_UPDATE in Chromium, the `priority` header, pseudo-header order.
  The test `tests/test_h3_fingerprints.py` compares every profile with the browser capture
  on an aioquic server. The captures are produced by `scripts/h3_browsers.py` (downloads
  the required browser version), `scripts/h3_capture.py` (recording server) and
  `scripts/h3_profiles.py` (builds `h3profiles.json`).
- **HTTP/2 without TLS (h2c, prior knowledge) for `http_version="2"` on `http://`**, like
  `Protocol.H2_PRIOR_KNOWLEDGE` in OkHttp and gRPC: SETTINGS, WINDOW_UPDATE, priorities and
  pseudo-header order come from the profile. A server without h2c raises `ProtocolError`.
- **HTTP/3 broken on the server side is handled like in Chrome.** If an HTTP/3 connection was
  established and then closed with an HTTP/3, QPACK or QUIC error code (by the server, or by
  the client because of a protocol violation), HTTP/3 for that address is marked broken for
  5 minutes (twice as long on each repeat, up to 2 days); the request, if it can be retried,
  goes over TCP right away, and the following requests also go over TCP, with no UDP attempt
  and no racing delay. Previously every request won with HTTP/3 again and failed. A close
  without an error (QUIC NO_ERROR, H3_NO_ERROR, code 0, unknown and reserved codes, per
  RFC 9114 §8.1, and the transport APPLICATION_ERROR in which a close during the handshake
  arrives), the server resetting a single request, a refusal of a too-large response,
  timeouts, and a connection the server has forgotten (idle timeout, stateless reset) do not
  mark HTTP/3 broken: the next request goes over a new QUIC connection.
- `yumeclient.profiles.HTTP3_FINGERPRINTS` (profiles with a browser capture) and
  `yumeclient.profiles.NO_HTTP3` (clients without HTTP/3, with the reason).

### Fixed
- **HTTP/3 with servers that use the QPACK dynamic table** (google.com and others):
  every request failed with `qpack: expected Required Insert Count to be zero`, because the
  profiles advertised a 64 KiB table but the decoder did not support it. A dynamic table
  decoder (RFC 9204) with encoder/decoder streams is implemented.
- **A redirect from `http://` to `https://` did not use the profile**: `http://` requests
  went through a separate client, and the `https://` hop after the redirect opened TLS with
  Go's stack (its ClientHello instead of the profile's, system certificate verification
  despite `verify=False`). Now all hops go through the session: `https://` with the profile,
  `http://` with the session's plain transport.
- `http://` requests ignored `local_address` and took the proxy from the
  `HTTP_PROXY`/`HTTPS_PROXY` environment variables (`https://` requests did not). Now both use
  only the session's `proxy=` and its address.
- **The HTTP/3 response header size limit did not apply** for profiles that do not send
  `SETTINGS_MAX_FIELD_SECTION_SIZE` themselves (`firefox_147`/`148` already sent it in 0.7.0;
  in 0.8.0 all profiles with a browser capture do): a HEADERS frame that announced 2^40 bytes
  made the client allocate that much memory (the process crashed with `out of memory`), and
  a single dynamic table entry repeated 2000 times produced 120 MB of headers. Now the limit
  advertised by the profile applies (Chrome: 256 KiB), otherwise 10 MB, and trailers are
  covered too.
- Trailers that waited for a QPACK dynamic table entry waited for it longer than any timeout.
  QPACK: cancelled and rejected sections and responses abandoned before the end are cancelled
  at the encoder (Stream Cancellation, once per stream), a broken encoder stream closes the
  connection (H3_CLOSED_CRITICAL_STREAM), and an invalid instruction on it leads to
  QPACK_ENCODER_STREAM_ERROR.
- A server that gave no flow control credit to our unidirectional streams held requests
  longer than any timeout: QPACK acknowledgments (Section Acknowledgment) and Chrome's
  PRIORITY_UPDATE were written on the request path. Now they are sent from a background
  queue; a full queue (64 KiB) closes the connection (H3_EXCESSIVE_LOAD). The order across
  streams is unchanged: PRIORITY_UPDATE goes before the HEADERS of its request (as in
  Chrome), and Firefox's QPACK stream types before SETTINGS; a stream without credit delays a
  request by no more than 50 ms.
- A server `max_idle_timeout` below 5 seconds was raised to 5 seconds (and 0, "no timeout",
  became 5 seconds): after the server closed an idle connection, the next request waited up
  to 5 seconds on a dead connection. Now, as in Chrome and Firefox, the advertised value
  applies and the request goes straight to a new connection; keep-alive for profiles without
  a QUIC fingerprint is sent at most once per second.
- A response with `Content-Encoding: deflate` that was read completely over HTTP/3, but whose
  end of stream (FIN) arrived after the last DATA, was closed as abandoned: STOP_SENDING and
  QPACK section cancellation, which browsers do not do. A deflate body is now read up to the
  end of the stream, like gzip.
- `http://` through `socks5h://` and `socks4://` was sent to the proxy as a request to an
  HTTP proxy (`GET http://...` in plain text); now it goes through SOCKS, like `https://`.
- **HTTP/3 stage timeouts** (`connect`, `write`, `read`) did not work: `read=0.5` waited 2 s
  for a response, and `connect=0.5` with silent UDP ended in `ConnectError` after 5 s.
- The `priority: u=0, i` header is sent over HTTP/2 since Chrome 124 (Chrome 99–152
  captures): `chrome_124`, `chrome_130_PSK`, `chrome_131`, `chrome_133` (+`_PSK`),
  `edge_131` and `edge_latest` did not send it.
- Edge profiles sent the HTTP/2 SETTINGS of Chrome 107–116 for any version: `edge_131`/
  `edge_latest` had an extra `MAX_CONCURRENT_STREAMS`, and `edge_99`/`edge_101` an extra
  `ENABLE_PUSH`. Now they match Chromium of the same version.
- `chrome_116_PSK_PQ` advertises X25519Kyber768 over QUIC, like Chrome 116 with
  PostQuantumKyber.
- **Browser headers are checked against captures of the browsers themselves** (Chromium
  99–152, Opera 89–91, Firefox 102–148; `tests/fixtures/browser_headers.json`):
  - HTTP/1.1: `Host` was sent last (now first, as with any client), names were in lower
    case (now written as the browser does: `User-Agent`, `Sec-Fetch-Mode`, and in Chromium
    `sec-ch-ua`), Chrome and Firefox did not send `Connection: keep-alive`;
  - `Sec-CH-UA` was `"Not(A:Brand";v="24"` in one order for all versions; now it follows the
    Chromium algorithm: the GREASE brand, its version and the brand order are specific to
    each version (Chrome, Edge, Brave; Opera uses the values of release builds);
  - Chrome: `Accept` with `signed-exchange;v=b3;q=0.9` before 109, `zstd` in
    `Accept-Encoding` only since 123 (previously in all versions);
  - Opera: the User-Agent had the Opera version instead of the Chromium version
    (`Chrome/91.0.0.0` instead of `Chrome/105.0.0.0`) and the wrong `OPR/`;
  - Firefox: the position of `Accept-Encoding`, the `Accept`/`Accept-Language`/`Accept-Encoding`
    values per version, `Priority: u=0, i` since 128, `te: trailers` only over HTTP/2 and on
    all OSes (previously over all protocols and only on Windows), `rv:109.0` for Firefox
    110–119;
  - the HTTP/2 HEADERS of `firefox_132`/`133`/`135` carried Chrome's priority (exclusive,
    weight 256) instead of Firefox's (weight 42); `tor_145` now has the SETTINGS, priority
    and headers of Firefox 128 ESR (the base of Tor Browser 14), not of Firefox 133+.
- The Akamai fingerprint printed the `NO_RFC7540_PRIORITIES` (9) SETTING as `0:1`.

### Changed
- `http_version="3"` with a client that has no HTTP/3 (`okhttp4_*`, `okhttp4_conscrypt`,
  `conscrypt_android_latest`, `cloudscraper`, `tor_145`) raises `SessionConfigurationError`
  (previously a warning and a quic-go QUIC handshake). For profiles without a browser capture
  (Safari, iOS and Android apps) the warning remains.
- `http_version="2"` on `http://` uses h2c instead of HTTP/1.1 (with `"auto"`, `"1.1"` or
  `"3"`, `http://` still uses HTTP/1.1).
- HTTP/3 with a browser capture does not use 0-RTT (the browser handshake has no early data).
- `default_headers()` and the initial `session.headers` of browser profiles write names the
  way the browser does over HTTP/1.1 (`User-Agent` instead of `user-agent`).
  `default_headers()` returns `Headers`: reading, writing, `del`, `pop` and `setdefault` are
  case-insensitive and keep the original spelling (`h["user-agent"] = ...` replaces
  `User-Agent`).
- Over HTTP/1.1, `Host` goes first even when you set it yourself (`headers={"Host": ...}`)
  without `header_order`; an order with `Host` in `header_order` is kept as is.
- `edge_latest`: Edge 131 headers (`Edg/131`, the Edge 131 `Sec-CH-UA`, `zstd`), matching its
  Chromium 131 TLS and HTTP/2 profile; previously Edge 120.
- Removed the undocumented debug variable `YUMECLIENT_UPSTREAM_JA3` (https did not work with
  it since 0.7.0).

## [0.7.0] — 2026-11-20

### Added
- **`response.history`**: the responses of the followed redirects (status, headers,
  Set-Cookie, URL, protocol, time of the hop, body up to 64 KiB), and `response.is_redirect`.
  Previously the list was always empty. A redirect body is read only while it keeps coming
  (a pause > 0.5 s or reading > 2 s → `b""`), and it does not delay the hop. The history
  contains all followed redirects, including chains of 307/308 with a body.
- **Chrome filling for custom JA3 works.** `fill_custom_with_chrome_defaults=True`
  (the default) previously did not reach the network layer. Now anything not set explicitly
  (sigalgs, versions, key shares, ALPN/ALPS, certificate compression, ECH, HTTP/2, HTTP/3)
  is taken from `chrome_152`; `False` uses generic values.
- **Chrome HTTP/3 parameters for `chrome_146`–`chrome_152` (+`_PSK`) and `brave_146`**:
  upstream does not set them, and only `SETTINGS_H3_DATAGRAM` was sent. Now SETTINGS,
  pseudo-header order and priority match Chrome 157 on the wire
  (`tests/fixtures/chrome_157_wire.json`, a test on an aioquic server).
- Chromium profiles send `priority: u=0, i` over HTTP/2, like Chrome.
- `headers={"X": None}` removes a header (as in requests), including headers added by the
  network layer: `Accept-Encoding`, `priority` over HTTP/2 and HTTP/3, the `okhttp`-style
  defaults, and `application/octet-stream` for `data=bytes`.
- Linux wheels are checked in CI on manylinux2014 (glibc 2.17).

### Fixed
- **Protocol racing (`http_version="3"`) sent the request twice**: over HTTP/3 and, after
  300 ms, over HTTP/2 as well; if HTTP/3 took longer than 300 ms to respond, a POST reached
  the server twice (both attempts read the same body). Now the race is for the connection:
  the request is sent only by the protocol that established a connection first (HTTP/3 after
  the full handshake), or over an already open connection. Every racing request opened a new
  QUIC connection; now the winning one is reused. After an error of the remembered protocol,
  and for HTTP/3 also after a timeout or cancellation (silent UDP cannot be told apart from a
  slow server), the next race uses new connections; after a timeout or cancellation on
  HTTP/1.1/HTTP/2 the protocol and the pool are kept (the HTTP/2 connection keeps working).
  A header that HTTP/2 does not carry (`Connection: Upgrade`, `Upgrade`, `Transfer-Encoding`
  other than `chunked`) raises `InvalidRequestError` without losing the connection (and
  outside racing the session is no longer reset). The request itself is retried by the race
  if it is idempotent (GET/HEAD/OPTIONS/TRACE or with `Idempotency-Key`) and there is time
  left, or if the connection closed without sending it. A response slower than 10 s during
  racing no longer turns into an error; if no protocol connected, the error comes from TCP.
- **A closed session did not close its connections**: HTTP/2 connections stayed open until
  the server dropped them; for HTTP/3, the UDP socket, the QUIC connection and goroutines
  stayed (the transport that won the race was not stored or closed at all). Concurrent first
  requests of one session each created their own native client, and all but the last one
  were never closed. Now a session has a single client, and it is closed (both after a
  request error and on `close()`) once the requests still running through it finish,
  including their redirects.
- **A response with `Content-Encoding: deflate` over HTTP/1.1 hung** until the timeout (fhttp
  read the whole body inside the connection's read loop: a deadlock). A deflate body was
  also read entirely into memory before the response was returned, bypassing streaming and
  `max_content_size`. Now decompression is lazy; raw deflate (RFC 1951) that does not start
  with `0x78` was previously returned compressed.
- Closing a partially read zstd body could hang: the decoder waited for its own body read,
  which was closed after it.
- **`cloudscraper` against OpenSSL with CBC**: the handshake failed with `bad record MAC`,
  because utls advertised encrypt_then_mac but did not implement it. RFC 7366 is implemented.
- **`Go-http-client/2.0` during HTTP/3 racing** (`http_version="3"`) in a session without
  `User-Agent`. An empty `User-Agent` key now means "do not send" for HTTP/2 as well.
- **Additional HTTP/2 connections** (when the first one is busy or closed) were opened
  without the request context: no cancellation, no connect timeout, no `timings["proxy"]`.
- Custom JA3: `priority_frames` and `header_priority` did not reach the wire; a JA3 with
  extension 27 without `cert_compression_algos` failed (`unknown ClientHelloID`, and upstream
  printed to stdout); record_size_limit was sent with the value 0.
- Numeric `key_share_curves`: GREASE values (`10794` and others) and `25497`
  (X25519Kyber768) were turned into X25519MLKEM768 (a second ML-KEM key share broke the
  handshake), and `31` into P521 (P521 is `25`). Unknown values of `key_share_curves`,
  `supported_versions` and `cert_compression_algos` silently dropped out of the hello; now
  they raise `SessionConfigurationError`.
- The Akamai fingerprint of `firefox_102`–`firefox_123` did not include their PRIORITY
  frames.
- **A header with the value `None` was sent empty** (`User-Agent: `, `X-Token: `) instead of
  being removed.
- A custom JA3 without X25519 in its groups (for example `23-24`) got an X25519 key share, for
  a group it did not advertise, and OpenSSL aborted the handshake (`illegal_parameter`). Key
  shares are now generated only for groups from the JA3; the ML-KEM hybrid only together with
  X25519. With key shares like `X25519MLKEM768, P-384, X25519`, a server response with ML-KEM
  aborted the handshake (`invalid server key share`: utls took the key of the first classical
  group).
- A request waiting for an additional HTTP/2 connection that another request was opening did
  not react to its own cancellation and timeout until that connection setup finished.
- The Linux x86_64 wheel was tagged `manylinux1` (glibc 2.5), although the Go runtime needs
  Linux 3.2+; now it is `manylinux2014`.

### Changed
- `fhttp`, `tls-client` and `utls` are built from `native/third_party` with patches
  (`native/third_party/patches/*.patch`; `python scripts/third_party.py check` compares the
  copies with upstream + patch and rejects any extra files).
- The "no browser HTTP/3 parameters" warning is shown for all profiles without them, not
  only for `chrome_150`/`152`.
- A header with an invalid name or a control character in its value (except tab) is rejected
  before sending with `InvalidRequestError` (`ValueError`). Previously the request failed in
  the network layer with `ConnectError` (kind `connect`), and the session lost its
  connections; `except ConnectError` no longer catches these errors.

## [0.6.0] — 2026-11-20

### Added
- **TLS configuration diagnostics** (`yumeclient.diagnostics`):
  - `session.export_profile()`: a versioned JSON snapshot of the session identity
    (profile, OS, header style, `http_version`, all explicit ClientHello/HTTP/2 parameters,
    default headers in wire order, the last observed fingerprint). Proxies, timeouts,
    cookies, `verify`, CA, the local address and headers with credentials are not exported
    (the latter are exported with `include_secrets=True`).
  - `Session.from_profile(profile, **overrides)` / `AsyncSession.from_profile(...)`:
    restores the session, with exact headers (order and removed ones); a foreign format, a
    newer version or an unknown parameter raises `SessionConfigurationError`.
  - `fingerprint_diff(expected, actual)`: compares fingerprints (`Response`, profile or
    dict) field by field: `value` / `missing` / `order` / `set`; GREASE is ignored, and JA3
    is compared by component.
  - `response.trace()`: a redacted request trace: header order on the wire, protocol, ALPN,
    TLS version and cipher, timings, JA3/JA4/Akamai, length and SHA-256 of the bodies; the
    values of `Authorization`/`Cookie`/`Set-Cookie`/`*token*`/`*secret*`/`*key*`/... and the
    query (including in `Location`, `Referer`, `Link`, `Refresh`) are hidden.
  - `tests/fixtures/profiles.json` + `tests/test_profile_fixtures.py`: a reference
    ClientHello for each of the 93 profiles (JA3/JA4/JA4_r, ALPN, extension order, Akamai,
    header order); `python scripts/profile_fixtures.py [--update]`.
- `connection_info["tls_cipher"]` and `timings["proxy"]` (the part of `connect` spent on the
  path through the proxy).
- `ProtocolError` (`ConnectError`, `kind="protocol"`).
- `yumeclient.__version__`.

### Fixed
- **`http_version="2"` silently fell back to HTTP/1.1** if the server chose `http/1.1`.
  Now the connection is closed right after the handshake, the request is not sent, and
  `ProtocolError` is raised. `keep_alpn` with the server choosing `h2` also raises
  `ProtocolError` (previously a generic `ConnectError`).
- **Contradictory protocol settings** were accepted and silently resolved in favor of one of
  them: `force_http1=True` + `http_version="2"` (HTTP/1.1 was sent), `alpn_protocols=["h2"]`
  + `http_version="1.1"` (ALPN was rewritten to `http/1.1`), and so on. Now they raise
  `SessionConfigurationError` in the constructor, before any network activity (the list is
  in [Protocols](docs/protocols.md#conflicting-settings)).
- **Assigning session transport parameters was ignored** (`s.proxy = ...`,
  `s.http_version = ...` were written to the wrapper object and had no effect, although
  USAGE promised that the client would be recreated); now it raises `AttributeError` with a
  hint.
- **`session.headers` was case-insensitive only on write**: `s.headers["user-agent"]` and
  `del` raised `KeyError`, `"user-agent" in s.headers` was `False`, and
  `s.headers.pop("user-agent", None)` removed nothing, so the header kept being sent. Now
  `[]`, `in`, `get`, `pop` and `del` are case-insensitive.
- **Without `User-Agent`, `User-Agent: Go-http-client/1.1` was sent** (`…/2.0` on h2): Go's
  fingerprint instead of the profile's, and `USER-AGENT` in a different case was sent as a
  second header next to `Go-http-client`. Now there is no such header at all (HTTP/1.1,
  HTTP/2, HTTP/3; the exception was racing with `http_version="3"`, fixed
  in 0.7.0); okhttp profiles still add `okhttp/4.12.0`.
- `Headers |= {...}` and `Headers | {...}` ignored case and produced two headers.
- Request warnings (`HTTP/2-only selection ...`) pointed to the internals of
  `concurrent.futures` instead of the calling code.
- **Ctrl+C did not interrupt a sync request**: the blocking ctypes call held the main thread
  until the response arrived. Now `KeyboardInterrupt` is raised immediately (< 0.1 s), the
  native request is cancelled and the connection is closed; the same applies to reading a
  sync stream.
- **A cookie for a public suffix** (`Domain=com`, `co.uk`, `github.io`) was stored and sent
  to all sites under that suffix. Now it is dropped (Mozilla PSL, as in browsers); on the
  suffix host itself it is host-only. `Domain=` on an IP address is host-only.
- **The `nike_android_mobile` profile could not connect to OpenSSL servers** (nginx, Apache,
  HAProxy) with TLS 1.3: `illegal_parameter`, because the upstream spec sends a GREASE key
  share without GREASE in supported_groups (RFC 8446 4.2.8). The extra key share is removed;
  JA3/JA4 do not change.

### Changed
- `http_version="2"` is strict (see Fixed); `http://` stays on HTTP/1.1 with any
  `http_version` (h2c is not supported).
- Session transport parameters are immutable (see Fixed); per request you can pass `proxy=`,
  `timeout=`, `headers=`, `cookies=`, `header_order=`, `allow_redirects=`, `stream=`,
  `max_content_size=`.
- `session.headers` no longer holds duplicate names in different case:
  `Headers({"A": 1, "a": 2})` → `{"A": 2}`.

## [0.5.1] — 2026-11-19

### Fixed
- **Python 3.14: log noise on cancellation.** Every cancelled async task (and every
  interrupted `aiter_bytes()` read) reached the event loop exception handler as
  `RequestCancelled exception in shielded future` with a traceback: in 3.14 `asyncio.shield`
  reports the inner future's error after the outer one is cancelled. The executor future is
  now awaited through `asyncio.wrap_future`; cancellation behavior is unchanged.

## [0.5.0] — 2026-11-19

### Added
- **Response streaming.** `request(..., stream=True)` (and `await` in `AsyncSession`): the
  body stays in the native layer and is read in chunks straight into a Python buffer, without
  base64/JSON: `iter_bytes(chunk_size)`, `iter_content()`, `read()`, `close()`, a `with`
  block; async: `aiter_bytes()`, `aread()`, `aclose()`, `async with`. A 64 MiB response is
  read with a peak Python memory use below 8 MiB. Leaving the loop early, `close()`, closing
  the session and garbage collection release the native stream. `is_stream_consumed`.
- **Native cancellation.** Every request has a `request_id`; cancelling an asyncio task
  (`wait_for`, `TaskGroup`, `task.cancel()`) aborts the request in Go at any stage
  (DNS/proxy/TCP/TLS, waiting for headers, reading the body) and returns control in
  < 0.5 s instead of waiting for the response. A late result of a cancelled request does not
  touch the jar.
- **Separate timeouts**: `TimeoutConfig(total, connect, read, write)`; `timeout=` accepts a
  number (total), a `(connect, read)` tuple, a `TimeoutConfig` or `None`. `connect` is
  DNS + proxy + TCP + TLS of each hop, `read` is the wait for headers and the pause between
  body chunks, `write` is sending the request.
- **Structured errors** (all are subclasses of `RequestError`, with the attributes `kind`,
  `stage`, `method`, `url`, `elapsed`, `request_id`, `retryable`, `detail`): `ConnectError`
  (+ `ProxyError`, `TLSError`), `ConnectionClosed`, `Timeout` (+ `ConnectTimeout`,
  `ReadTimeout`, `WriteTimeout`), `RequestCancelled`, `ResponseTooLarge`, `StreamClosed`,
  `InvalidRequestError`, `HTTPStatusError` (from `raise_for_status()`, with the response in
  `.response`). `Timeout` is also a `TimeoutError`, and `ConnectError`/`ConnectionClosed` are
  also `ConnectionError`. Logins/passwords from URLs and Basic/Bearer tokens are stripped from
  error messages.
- **`response.connection_info`**: connection reuse, ALPN, TLS version, resumption, socket
  addresses, phase timings of the last hop (`connect`, `write`, `wait`, `body`, `redirects`,
  `first_byte`, `total`; the phases add up to `total`).
- **`max_content_size`** (session or request): a limit on the decompressed body; above it,
  `ResponseTooLarge`.
- **`close(grace=5.0)`** on `Session`/`AsyncSession`: requests in flight get `grace`
  seconds, then they are cancelled; open streams are closed.
- **`CookieJar.for_url(url)`**, `to_dict(url=...)`, the `host_only` flag (`hostOnly` in
  `export()`/import).
- **Wheels:** `py3-none`: one wheel per platform for any Python ≥ 3.11 (instead of
  cp311…cp314): Windows x64, Linux x86_64 and **aarch64** (manylinux_2_28), macOS
  **universal2** (arm64 + x86_64, macOS 11+). A release is published only after the contents
  of every wheel are checked and the installed wheel passes a smoke test on
  Linux/Windows/macOS (arm64 and Intel) × Python 3.11–3.14.

### Fixed
- **`AsyncSession` cancellation waited for the native request** (`wait_for(..., 0.1)`
  returned after 1.5 s, together with the slow response).
- **`http://` ignored the session timeout** (a hard 30 s): `Session(timeout=1)` waited 3 s
  for a response.
- **A per-request `timeout=` was ignored** if the Go session already existed (the timeout
  was fixed when the client was created).
- **A per-request `proxy=` was ignored** after the session's first request: the request went
  through the session proxy or **directly**. Now a separate native session is used for a
  different proxy.
- **Cookies: scoping.** Cookies are selected per RFC 6265 on every hop: domain / host-only,
  path (longest path first), Secure only over https, expiry. Previously the tls-client jar
  returned all cookies of the "two-label domain" regardless of Path/Secure (a Secure cookie
  from https://a.example.com was sent to http://b.example.com, and a cookie with
  `Path=/admin` to `/public`), a server could set a cookie for another domain, and same-name
  cookies with different paths overwrote each other.
- **A cookie removed in Python** (`session.cookies.remove(...)`) kept being sent and came
  back into the jar: the session's Go jar lived separately. Now `session.cookies` is the
  single source of truth: every request gets its own jar from a snapshot, and only changes
  come back (`Set-Cookie`, deletion via `Max-Age=0` or an expired `Expires`). Parallel
  requests of one session no longer overwrite each other's cookies.
- **Wheels:** the Windows wheel contained a second PE image named `yumeclient.so`; the macOS
  wheel contained only arm64 with `minos 26.0` (it did not install on macOS < 26 or on
  Intel).

### Changed
- `timeout=0` / negative → `SessionConfigurationError` (previously 0 meant "30 s").
- Error messages now include `[METHOD url]`; timeout/connection exceptions inherit from
  `OSError` (via `TimeoutError`/`ConnectionError`).
- `close()` cancels in-flight requests after `grace` seconds (previously it waited without a
  limit; the old behavior is `close(grace=None)`).
- `Response` is a regular class with `__slots__` (not a dataclass); the positional
  constructor is unchanged.
- Changing `timeout` no longer recreates the Go session; an invalid request error
  (URL/method) no longer resets its connections.
- Cookies without a domain (`jar["k"] = "v"`) are still sent to any host (as in requests),
  but they do not override a same-name cookie bound to a host/domain.
- A Secure cookie set over `http://` is stored, but sent only over https.

## [0.4.7] — 2026-11-17

### Added
- **okhttp 4.x HTTP layer (`header_style="okhttp"`)**, the default for
  `okhttp4_android_7…13`, `okhttp4_conscrypt`, `conscrypt_android_latest`. Every request
  (including redirect hops) is built the way BridgeInterceptor + Http1ExchangeCodec build it:
  application headers as passed → `Content-Type` → `Content-Length` → `Host` (without the
  default port) → `Connection: Keep-Alive` → `Accept-Encoding: gzip` → `Cookie` (from the
  jar) → `User-Agent: okhttp/4.12.0` (if the application did not set its own).
  Host/Connection/Accept-Encoding/User-Agent set by the application stay in their place;
  with `Range` there is no `Accept-Encoding`; 302/303 → GET without body headers and without
  `Referer`. Checked byte for byte against real okhttp 4.12.0 (13 requests, the same
  server): identical.
  The pool is like okhttp's `ConnectionPool`: keep-alive, 5 idle connections, 5 minutes.
  A request up to 8 KiB goes out as one write, in one TLS record (like Conscrypt after an
  Okio flush): without a separate flush of the headers (fhttp did not recognize the
  `io.NopCloser` of Go ≥ 1.20) and without Go's dynamic record sizing (first records
  ~1.2 KiB).
  `header_style="raw"` keeps the old behavior.
- **`keep_alpn=True`** (together with `http_version="1.1"`): the hello keeps the profile's
  ALPN (`h2,http/1.1`, JA4 `…h2_…`), and requests go over HTTP/1.1 if the server chose
  `http/1.1`. If the server chose `h2`, the connection is closed right after the handshake
  (not a single HTTP byte is sent) and `RequestError` is raised. Without `keep_alpn`,
  `http_version="1.1"`/`force_http1` still rewrites ALPN to `http/1.1` (JA4 `…h1_…`).
- **`Response.fingerprint`**: `alpn_offered`, `alpn_negotiated`, `tls_version`,
  `tls_resumed`, `http_protocol`, `connection_reused`, `request_headers` (the header fields
  in exactly the order and case in which the transport wrote them to the connection).

### Fixed
- **h2 of the conscrypt/okhttp profiles = okhttp.** It was
  `1:4096;2:0;4:65535;6:262144|0|m,a,s,p` with Chrome priority in HEADERS; now it is like
  okhttp's `Http2Connection`: SETTINGS `4:16777216`, WINDOW_UPDATE `16711681`, pseudo-headers
  `:method,:path,:authority,:scheme`, HEADERS without priority, first stream 3 (Akamai
  `4:16777216|16711681|0|m,p,a,s`), checked against okhttp 4.12.0 via tls.peet.ws.
- **http:// keeps keep-alive.** The plain HTTP transport is cached per session (and proxy)
  instead of being created anew for every request.

### Changed
- `session.headers` of okhttp profiles starts empty (okhttp has no default application
  headers; `Accept-Encoding`/`User-Agent` are added by the network layer). The old set
  (`user-agent`, `accept: */*`, `accept-encoding`) is available with `header_style="raw"`.
- okhttp style: `data=bytes` without an implicit `Content-Type: application/octet-stream`.

## [0.4.6] — 2026-11-16

### Fixed
- **Cipher order of the conscrypt/okhttp profiles = Conscrypt's order on the wire.**
  It was `c02b,c02f,c02c,c030,cca9,cca8`, now it is `c02b,c02c,cca9,c02f,c030,cca8`
  (first ECDHE-ECDSA AES128/AES256/CHACHA, then ECDHE-RSA). JA4 sorts the ciphers and
  matched before as well; now JA3 matches too: `f79b6bad2ad0641e1921aef10262856b`
  (= tshark on a capture of the real app), and JA3_full and JA4_r match byte for byte.
- **`disable_session_tickets` is applied.** The flag was passed from Python, but the
  patched builders (profiles and the ja3 path) did not apply it, so resumption could not be
  turned off.

- **Extension shuffling only for Chromium.** `random_tls_extension_order`
  (Python default `True`) shuffled the order for any profile, including upstream Safari,
  Firefox, `okhttp4_android_*` and mobile apps, although the real clients send a fixed
  order. Now the flag affects only `chrome_*`, `brave_*`, `opera_*`, `edge_*`. Side effect:
  upstream `okhttp4_android_10` … `_13` now produce exactly the Conscrypt hello
  (JA3 `f79b6bad…`).

### Added
- **TLS 1.3 resumption for conscrypt/okhttp.** `pre_shared_key` (41) is added to the spec
  as the last extension: it is not sent in a fresh hello (record 512, handshake 508,
  padding 21); on a repeat connection with a stored ticket the hello carries PSK:
  `…,51,45,43,41` instead of padding, like variant B on the phone.

## [0.4.5] — 2026-11-16

### Fixed
- **Extra profiles went out on the wire as Chrome.** `createPatchedClient` sent all extra
  identifiers (`okhttp4_conscrypt`, `conscrypt_android_latest`, `edge_*`, `tor_145`,
  `safari_macos_*`) to upstream `CreateClient`, which knows only
  `profiles.MappedTLSClients` and silently substituted `DefaultClientProfile` (Chrome_150:
  GREASE, X25519MLKEM768, ext 27/ECH/ALPS, shuffled order, hs_len ~1718). Now extra
  profiles go through the manual builder, and their own hello goes out on the wire.
  Conscrypt: 15 ciphers without GREASE, exts `0,23,65281,10,11,35,16,5,13,51,45,43,21`,
  groups 29-23-24, key share X25519 32b, hs_len 508, JA4
  `t13d1513h2_8daaf6152771_eca864cca44a` (= tshark reference).
- **Fixed extension order for non-Chromium extra profiles.**
  `random_tls_extension_order` (default `True`) no longer shuffles conscrypt/okhttp,
  tor_145 and safari_macos_*: real Conscrypt, Firefox and Apple do not shuffle. Edge
  (Chromium) shuffles as before.
- **The Conscrypt spec is built anew for every handshake** (the same class of bug as the
  fresh-spec fix in 0.4.3: extension objects shared between connections).
- **JA4 per the FoxIO specification** (matches Wireshark 4.x `tls.handshake.ja4`):
  extension hash = sorted hex ids without SNI/ALPN + `_` + signature algorithms in wire
  order; ALPN tag = first + last character of the first value (`http/1.1` → `h1`,
  previously `t`); the version is the maximum of supported_versions.
  The old `..._02bdef6adf81` was computed over the ids in wire order, without sigalgs.

### Changed
- **`Response.fingerprint` reads the wire.** Every TLS connection of the session goes
  through a capturing dialer that stores the first TLS record (ClientHello) exactly as it
  went into the socket: after ApplyPreset, GREASE, padding, shuffling and the `force_http1`
  ALPN rewrite. JA3/JA4 are computed from these bytes, by the response's host:port. New
  fields: `source` (`"wire"` / `"config"`), `client_hello_len`, `ja4_r`, `tls_extensions`,
  `handshakes`, `config_ja3_hash_md5` / `config_ja4` (the configured values alongside; a
  mismatch means the session sends something other than what is configured).
  `akamai_fingerprint` is still taken from the h2 configuration.
- The proxy leg is unchanged: https:// uses the same insecure CONNECT dialer; http:// and
  socks5:// use upstream's own dialer (taken from the probe client) in a wrapper.
  `source: "config"` remains only for HTTP/3 racing through a proxy and for `udp_proxy` on
  top of a non-socks5 proxy: there upstream must own the proxy URL itself (the h3 transport
  reads it from the config), otherwise QUIC would bypass the proxy.

## [0.4.4] — 2026-11-16

### Added
- **Profile `conscrypt_android_latest`** (alias `okhttp4_conscrypt`): the ClientHello of an
  Android app that connects through the platform Conscrypt with TLS 1.3: 15 cipher suites,
  13 extensions (with padding), no GREASE, the HTTP/2 settings of okhttp
  (`1:4096;2:0;4:65535;6:262144`). The upstream `okhttp4_android_7`–`13` profiles offer only
  TLS 1.2. In this version the profile still went out with the Chrome hello (fixed in 0.4.5).

## [0.4.3] — 2026-11-16

### Changed
- **`grease=True` places GREASE the way iOS CFNetwork does**: an empty GREASE extension before
  SNI and one with a single `0x00` byte at the end, a GREASE value first in the cipher suites,
  `supported_groups`, `key_share` (with a one-byte key `0x00`) and `supported_versions`.
  `grease=False` removes GREASE from all of them.
- An explicit `tls_extension_order` turns off the random extension order, and GREASE is placed
  after the order is applied, so the GREASE positions do not move.

### Fixed
- **A session failed on its second host** with `local error: tls: internal error`: the
  ClientHello spec was shared between handshakes, and the second one reused the key share of
  the first. The spec is now built anew for every handshake.
- The JA3 in `Response.fingerprint` drops GREASE, and its fifth field is the point formats,
  not the signature algorithms.

## [0.4.2] — 2026-11-12

### Fixed
- **MLKEM key share generation from the advertised groups (HRR crash).**
  A ja3 with curve 4588 (X25519MLKEM768) in `supported_groups`, but without a matching key
  share, made Cloudflare send a HelloRetryRequest, and the go-tls rebuild path rejected the
  curve: `tls: CurvePreferences includes
  unsupported curve`. peet.ws silently fell back to X25519 (without HRR) and masked the bug.
  `ensureKeyShare` now derives the shares from the **advertised** supported_groups (the
  first two non-GREASE groups + an X25519 fallback, Chrome style); utls 1.7.8 generates the
  ML-KEM share itself (mlkem 1184b + X25519 32b = 1216b) in ApplyPreset.
  Verified on the wire: `group=4588 data=1216 bytes` next to `group=29 data=32`.

### Added
- **Mimic path for key shares**: the parameter `key_share_data={group_int: raw_bytes}`
  overrides auto-generation with captured share bytes (passed as base64 across the
  boundary; covers the upstream hint "To mimic it, fill the Data(key) field manually").

### Changed
- **Decimal heuristic for signature algorithms**: the string `"1027"` (digits only, no
  leading zero) is treated as decimal and converted to hex `"403"`; `"0403"` (with a leading
  zero) stays hex as is. This resolves the conflict between decimal copies of ja3 and hex
  phone profiles.

### Verified
- Full phone profile (PHONE_JA3 + `psk_mode="psk"` + brotli/zlib + explicit extension
  order): cloudflare.com **200** on repeat requests (previously a CurvePreferences crash),
  httpbin.org 200, ja4 `t13d1313h2_*`.


## [0.4.1] — 2026-11-12

### Fixed
- **`invalid input` on numeric ja3 arguments**: the upstream ja3 mapper expects named/hex
  strings; ints from curl_cffi-style calls became JSON numbers and broke the Go unmarshal.
  The facade now normalizes: `key_share_curves` (29→X25519, 4588→X25519MLKEM768),
  `supported_versions` (772→"1.3", 771→"1.2"), signature algorithms (int → hex without a
  prefix). `None` lists stay `None` (without a false "custom options require
  ja3_string").
- **JA4 brought in line with the specification**: `t13d<cc><ec><alpn>_<cipher_hash>_<ext_hash>`.
  Counters without GREASE; the cipher hash is sorted and without GREASE; the extension hash
  is in wire order but excludes SNI(0), ALPN(16) and GREASE; the extra 4th segment with
  signature algorithms is removed (that is JA4S territory).
  chrome_131: `t13d1516h2_8daaf6152771_...`; the cipher hash matches peet.ws.
- **akamai_fingerprint in the canonical format**
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` with pseudo-header letters; it is
  computed from the h2 settings actually applied to the profile: ja3 sessions without
  explicit `h2_settings` get Chrome-like defaults + the default pseudo order + connection
  flow 15663105, so the fingerprint = the real state of the wire, not the declared one.
- **extensionID extended with the utls types** needed for JA4 and extension order:
  UtlsGREASE, UtlsPadding(21), FakeRecordSizeLimit(28), DelegatedCredentials(34),
  ApplicationSettingsNew/Old(17613/13172), GREASEEncryptedClientHello(17513). Previously
  they were mapped to 0xFFFF and broke the counters/hashes.
- **MLKEM curves disable h3 racing** in ja3 sessions (quic-go rejects them with
  "CurvePreferences includes unsupported curve"); h1/h2 are not affected.

## [0.4.0] — 2026-11-12

### Added
- **Advanced ClientHello controls** (require `ja3_string`):
  - `tls_extension_order`: an explicit wire order of TLS extensions;
  - `grease`: True adds GREASE cipher/ext, False removes all of it;
  - `psk_mode`: `"psk"` adds the pre-shared-key ext, `"no_psk"` strips it;
  - `ech_config_list`: raw ECH config bytes in the custom payload;
  - `udp_proxy`: socks5:// for HTTP/3 racing.
- **`Response.fingerprint` / `session.last_fingerprint`**: JA3 (string + md5), JA4, Akamai
  h2 fingerprint from the final ClientHello, exactly what is compared against a pcap (GREASE
  wire values are randomized per handshake, as in a browser).
- **Additional TLS profiles**: `edge_99`/`edge_101`/`edge_131`/`edge_latest` (Chromium TLS
  stack, JA4 identical to chrome_131), `safari_macos_17_0`/`18_0`/`26_0` (Apple's
  ClientHello has been stable since 16), `tor_145` (Firefox ESR 128, 15 extensions).
  91 profiles in total.

### Fixed
- **ja3_string sessions now go through `buildJa3Client`** in the adapter: the upstream ja3
  parser is reused via the public `GetSpecFactoryFromJa3String`, the spec is adjusted by the
  controls above and rebuilt into a ClientProfile. Empty SupportedVersions, KeyShare,
  SignatureAlgorithms, Curves and ALPN are filled in automatically; previously empty values
  from ja3 produced "invalid Versions field" / "error decoding message".
- `fill_custom_with_chrome_defaults=False`: ja3 goes out as is, without mixing in Chrome
  (needed for CFNetwork/phone profiles).
- `UTLSIdToSpec` fallback for utls-native IDs (Safari/Edge) with a nil SpecFactory:
  fingerprint works for them too.

### Target
- The ClientHello of iOS 26 CFNetwork/3860.700.2 is reproducible (the profile
  `safari_ios_26_0` is Safari, not CFNetwork, and got a CF 403).

## [0.3.1] — 2026-11-12

### Fixed
- **`close()` actually releases connections** for all session types: previously only the
  sessionId was removed from the Go maps, without `CloseIdleConnections`, so keep-alive
  sockets lived until the timeout. The native builder now creates all identifier clients,
  and `yumeclient_close` drops the idle connections of each of them.
- `AsyncSession.close()` marks the session as closed synchronously: a forgotten `await` no
  longer leaves the session working.
- close-vs-request race: the flag is rechecked after acquiring the lock.
- A double `close()` and `close()` after a failed request are silent.

## [0.3.0] — 2026-11-11

### Added
- **`client_os`**: windows / android / ios / macos: a default header set for the
  profile+OS (UA, client hints); the OS is derived from the identifier automatically.
  Chrome+iOS → CriOS without client hints.
- **Browser default headers** for every session (user-agent, sec-ch-ua, accept,
  sec-fetch-*, accept-encoding, accept-language), consistent with the profile; no more
  `Go-http-client/2.0`.
- `Headers`: a case-insensitive ordered dict: `update()`, replacement, per-request
  override; dict order = wire order.
- One-shot API: `yumeclient.get/post/...` and `await yumeclient.aget/...`.

### Changed
- Sync `Session` and async `AsyncSession` are wrappers over one engine: cookies, headers
  and transport behavior are identical.

## [0.2.5] — 2026-11-11

### Fixed
- **http:// targets respect the session proxy** (leak fixed): schemeGuard built a plain
  HTTP/1.1 client on a bare DefaultTransport without Proxy, so http:// requests bypassed
  the proxy and went out from the real IP. This is exactly what caused the intermittent
  `EOF` errors on proxy pools: dead nodes, half-closed keep-alive connections and node
  rotation surfaced as raw transport EOF. The guard now remembers the session proxy and
  sets it in Transport.Proxy.

## [0.2.4] — 2026-10-18

### Fixed
- **The https:// proxy leg is not verified** (in the spirit of curl/requests/browsers):
  verify=False applied only to the target certificate, and the certificate of a proxy
  addressed by IP without an IP SAN failed even with verify=False. The CONNECT dialer
  now always skips verification of the proxy certificate; verify for the target works as
  before.

## [0.2.3] — 2026-10-18

### Fixed
- **`verify=False` for https:// proxies**: upstream connect.go built the proxy TLS with a
  hard-coded tls.Config without InsecureSkipVerify. For https:// proxies the client is now
  built by the adapter with its own CONNECT dialer, whose InsecureSkipVerify follows the
  session flag. socks5/http proxies and the target's uTLS fingerprints are untouched.

## [0.2.2] — 2026-10-18

### Added
- **`multipart.py` as a separate module** (`encode_multipart`, `choose_boundary`): it can be
  edited without touching the core, and `__init__` re-exports it.

### Fixed
- **http/https scheme collision in one session**: upstream keys the transport cache by
  host:443 regardless of the scheme, so an h2/h3 transport cached from an https call was
  handed to an http:// request to the same host ("protocol negotiated" / "http2: unsupported
  scheme", symptom: "forces https"). schemeGuard: http:// always goes through a dedicated
  HTTP/1.1 transport with the same cookie jar and redirect policy.

## [0.2.1] — 2026-10-18

### Added
- **multipart: requests-compatible file specs** (inspired by
  FlorianREGAZ/Python-Tls-Client): tuple arities 2..4, bare file objects/bytes/str, the name
  from `.name`, Content-Type via mimetypes, percent-escaping of CR/LF/quotes as in urllib3.

## [0.2.0] — 2026-10-18

### Added
- **Sync + async engine**: `Session` (with) / `AsyncSession` (async with), the same
  requests-style syntax; one-shot helpers.
- **`client_os`** (windows/android/ios) and default header sets per profile.
- **examples/**: basic syntax, profiles/OS, cookie flow.

### Fixed
- **requestCookies are actually put into the Go jar**: upstream cffi ignored them, so
  cookies from Python were not sent at all.
- **Cookies from redirect hops are saved**: the adapter returns a jarDump (all hosts) after
  every request, and it is merged into `session.cookies`.
- One-off per-request cookies no longer stick to the session jar.
- `CookieJar.set` without a domain updates the most specific same-name cookie instead of
  creating a duplicate; domains are normalized (port/dot/case).

## [0.1.6] — 2026-10-15

### Added
- First public package on PyPI: an async facade over bogdanfinn/tls-client v1.16.0 through
  a cgo c-shared adapter, upstream profiles, CookieJar, multipart encoder, CI (tests on
  three OSes + release wheels for py3.11–3.14).

[0.8.2]: https://github.com/october2823/yumeclient/releases/tag/v0.8.2
[0.8.1]: https://github.com/october2823/yumeclient/releases/tag/v0.8.1
[0.8.0]: https://github.com/october2823/yumeclient/releases/tag/v0.8.0
[0.7.0]: https://github.com/october2823/yumeclient/releases/tag/v0.7.0
[0.6.0]: https://github.com/october2823/yumeclient/releases/tag/v0.6.0
[0.5.1]: https://github.com/october2823/yumeclient/releases/tag/v0.5.1
[0.5.0]: https://github.com/october2823/yumeclient/releases/tag/v0.5.0
[0.4.7]: https://github.com/october2823/yumeclient/releases/tag/v0.4.7
[0.4.6]: https://github.com/october2823/yumeclient/releases/tag/v0.4.6
[0.4.5]: https://github.com/october2823/yumeclient/releases/tag/v0.4.5
[0.4.4]: https://github.com/october2823/yumeclient/releases/tag/v0.4.4
[0.4.3]: https://github.com/october2823/yumeclient/releases/tag/v0.4.3
[0.4.2]: https://github.com/october2823/yumeclient/releases/tag/v0.4.2
[0.4.1]: https://github.com/october2823/yumeclient/releases/tag/v0.4.1
[0.4.0]: https://github.com/october2823/yumeclient/releases/tag/v0.4.0
[0.3.1]: https://github.com/october2823/yumeclient/releases/tag/v0.3.1
[0.3.0]: https://github.com/october2823/yumeclient/releases/tag/v0.3.0
[0.2.5]: https://github.com/october2823/yumeclient/releases/tag/v0.2.5
[0.2.4]: https://github.com/october2823/yumeclient/releases/tag/v0.2.4
[0.2.3]: https://pypi.org/project/yumeclient/0.2.3/
[0.2.2]: https://pypi.org/project/yumeclient/0.2.2/
[0.2.1]: https://pypi.org/project/yumeclient/0.2.1/
[0.2.0]: https://pypi.org/project/yumeclient/0.2.0/
[0.1.6]: https://pypi.org/project/yumeclient/0.1.6/
