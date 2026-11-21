# Protocols

**English** | [Русский](ru/protocols.md)

`http_version` sets which HTTP versions the session may use. After the handshake the server
picks the protocol from the ALPN list that the client offered in the ClientHello (RFC 7301).
If the server picks a version that the session does not allow, the library does not silently
downgrade. It closes the connection before sending the request and raises `ProtocolError`.

| Value | ALPN in ClientHello | What happens |
|---|---|---|
| `"auto"` (default) | as in the profile, usually `h2, http/1.1` | HTTP/2 or HTTP/1.1, whichever the server picked, like a browser |
| `"2"` | as in the profile | HTTP/2 only. If the server picked `http/1.1` or sent no ALPN: `ProtocolError`, the request is not sent. Over `http://`: h2c ([below](#http-without-tls)) |
| `"1.1"` or `force_http1=True` | rewritten to `http/1.1` | HTTP/1.1; the ClientHello no longer matches the browser (a different JA4) |
| `"1.1"` and `keep_alpn=True` | as in the profile | HTTP/1.1 with the browser's ClientHello. If the server picked `h2`: `ProtocolError`, not a single HTTP byte is sent |
| `"3"` | as in the profile + QUIC | HTTP/3 and TCP racing, like in Chrome ([below](#http3-and-quic)) |

`1`, `2`, `3`, `"h1"`, `"h2"`, `"h3"`, `"quic"` and `None` (= `"auto"`) are accepted too.

```python
from yumeclient import Session, ProtocolError

with Session(http_version="2") as s:
    r = s.get("https://httpbin.org/get")
    print(r.http_version)                                  # '2'
    print(r.connection_info["alpn_negotiated"])            # 'h2'

with Session(http_version="1.1", keep_alpn=True) as s:   # HTTP/1.1, but the browser's JA4
    try:
        s.get("https://www.google.com/")
    except ProtocolError:
        pass                                               # the server picked h2
```

`r.used_protocol` and `r.connection_info["http_protocol"]` always match;
`connection_info["alpn_negotiated"]` is what the server picked.

## Conflicting settings

The constructor rejects these with `SessionConfigurationError`, before any network access:

- `force_http1=True` together with `http_version="2"` or `"3"`; `disable_http3=True` with `"3"`;
- `keep_alpn=True` without `http_version="1.1"`, together with `udp_proxy`, or with
  `alpn_protocols` that lack `http/1.1`;
- `alpn_protocols` (a custom JA3) with forced HTTP/1.1, if the list is not `["http/1.1"]`
  (the ClientHello would offer something else; to keep the list, use `keep_alpn=True`);
- `http_version="2"` with `alpn_protocols` that lack `h2`; an empty `alpn_protocols`;
- `http_version="3"` with a proxy that is not `socks5://`;
- `http_version="3"` with a client that has no HTTP/3 (`profiles.NO_HTTP3`).

## HTTP without TLS

Over `http://` there is no ALPN. With `"auto"`, `"1.1"` and `"3"` requests go over HTTP/1.1,
because browsers use only HTTP/1.1 over plain HTTP. With `http_version="2"` it is HTTP/2 with
prior knowledge (h2c, RFC 9113 §3.3, like `Protocol.H2_PRIOR_KNOWLEDGE` in OkHttp or gRPC):
the client sends the HTTP/2 preface right away. A server that does not speak h2c gives
`ProtocolError`.

Requests over `http://` go through the same session transport as `https://`: the same proxy,
`local_address`, cookies. Redirects between `http://` and `https://` stay in the session, and
every `https://` hop uses the profile's TLS.

## HTTP/2

HTTP/2 parameters come from the profile: SETTINGS and their order, the connection
WINDOW_UPDATE, PRIORITY frames, the priority in HEADERS, the pseudo-header order. Together they
make the Akamai fingerprint (`r.fingerprint["akamai_fingerprint"]`). For Chrome:

```
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

You can override them only for a custom TLS fingerprint (`ja3_string` + `h2_settings` and so
on, [Custom TLS fingerprint](custom-tls.md)).

## HTTP/3 and QUIC

```python
with Session(client_identifier="chrome_152", http_version="3") as s:
    r = s.get("https://cloudflare-quic.com/")
    print(r.http_version)          # '3' if the server supports HTTP/3
```

### Connection racing

With `http_version="3"` the session does what Chrome does when it knows the Alt-Svc:

1. It starts the QUIC handshake; after 300 ms (or right away if QUIC failed) it starts TCP in
   parallel.
2. The request goes out **once**, over the protocol that set up a connection first (or over an
   already open connection). The winning protocol is remembered for the host.
3. After an error of the remembered protocol, the next requests race again on new connections.
   For HTTP/3 this also applies to a timeout or a cancellation (silent UDP); for HTTP/1.1 and
   HTTP/2 a timeout or a cancellation does not reset the protocol and the pool.
4. A failed request is retried with racing if it is idempotent (GET, HEAD, OPTIONS, TRACE or
   with an `Idempotency-Key` header) and there is time left, or if it was definitely not sent.

### Broken HTTP/3

If an HTTP/3 connection was closed with an HTTP/3, QPACK or QUIC error code (by the server or
because of a protocol violation), HTTP/3 is marked broken for that address, as in Chrome: for 5
minutes, twice as long on each repeat, up to 48 hours. The request is retried over TCP, and the
next requests go over TCP right away.

These do not count as broken: a close without an error (`NO_ERROR`, `H3_NO_ERROR`, unknown
codes), the server resetting a single request, a response that is too large, timeouts, a
connection that the server forgot (idle timeout, stateless reset). The next request simply goes
over a new QUIC connection.

### QUIC and HTTP/3 fingerprint

For 53 profiles (`profiles.HTTP3_FINGERPRINTS`) QUIC and HTTP/3 reproduce captures of the
browsers themselves: Chrome 103–152, Opera 89–91, Firefox 102–148; Edge and Brave use Chromium
of the same version:

- **ClientHello inside QUIC.** It differs from the TCP one: TLS 1.3 only, and no GREASE in
  Chromium. Extension shuffling and ECH GREASE follow the browser.
- **Transport parameters**: the set, values, order, the GREASE parameter,
  `version_information`, `google_connection_options`, `google_initial_rtt` on repeat
  connections.
- **Initial packets**: Connection ID lengths, the first packet number, the datagram size, the
  padding method (PADDING frames, or zeros after the packet in Firefox), the layout of the
  ClientHello across packets (Chromium chaos protection, Firefox 146+ SNI slicing).
- **HTTP/3**: SETTINGS and their order, the GREASE frame, the order and types of QPACK streams,
  PRIORITY_UPDATE, the `priority` header, the pseudo-header order.
- **QPACK**: a decoder dynamic table, as in browsers (without it, requests to servers that
  compress headers through the table failed, google.com for example).

For profiles without a capture (Safari, iOS and Android apps) `http_version="3"` works, but
with a warning: their QUIC and HTTP/3 use the library's values, not the device's. A custom JA3
with Chrome padding takes the QUIC and HTTP/3 of that Chrome.

How to capture a browser and add the capture: [Development](development.md#http3-and-quic).

### Proxies and HTTP/3

QUIC runs over UDP, so HTTP/3 is possible only through SOCKS5 (UDP ASSOCIATE):
`proxy="socks5://..."` or a separate `udp_proxy=` (`socks5://` or `socks5h://`). With an HTTP
proxy and no `udp_proxy`, `http_version="3"` raises `SessionConfigurationError`. For responses
over HTTP/3 (with or without a proxy) `r.fingerprint["source"]` is `"config"`: the QUIC
ClientHello is not recorded, and the values are computed from the configuration.

## Timeouts by protocol

Timeout stages are the same for HTTP/1.1, HTTP/2 and HTTP/3; for HTTP/3, `connect` is the QUIC
handshake. In racing, TCP starts after 300 ms, so a `connect` below 300 ms runs out before TCP
can start. See [Timeouts](timeouts-and-errors.md) for details.

## If the server picks the wrong protocol

If the server gives the app `http/1.1` but gives you `h2` with the same ClientHello, the server
is looking at something else, and no client setting will fix that. Compare
`r.fingerprint["alpn_offered"]` and `connection_info["alpn_negotiated"]` with the reference.
In TLS 1.3 the server's ALPN reply is encrypted; in a tshark capture it is visible only with a
keylog:

```sh
tshark -o tls.keylog_file:keys.log -Y "tls.handshake.type==8" -T fields -e tls.handshake.extensions_alpn_str
```
