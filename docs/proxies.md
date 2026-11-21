# Proxies and network

**English** | [Русский](ru/proxies.md)

A proxy is given as a URL: for the whole session (`Session(proxy=...)`) or for a single request
(`s.get(..., proxy=...)`).

```python
from yumeclient import Session

with Session(proxy="http://user:pass@203.0.113.10:3128") as s:
    print(s.get("https://httpbin.org/ip").json())
```

## Schemes

| URL | Protocol | Target DNS name resolved | Authentication |
|---|---|---|---|
| `http://host:port` | HTTP proxy: `CONNECT` for `https://`, absolute-form for `http://` | by the proxy | Basic (`Proxy-Authorization`) |
| `https://host:port` | the same over TLS to the proxy | by the proxy | Basic |
| `socks5://host:port` | SOCKS5 (RFC 1928) | by the proxy (the name is sent to the proxy) | username/password (RFC 1929) |
| `socks5h://host:port` | the same as `socks5://` | by the proxy | username/password |
| `socks4://host:port` | SOCKS4 | **locally**, the proxy gets an IPv4 address | none |
| `socks4a://host:port` | SOCKS4a | by the proxy | none |

- The username and password go in the URL: `scheme://user:pass@host:port`. Percent-encode
  special characters: the password `p@ss` is written as `p%40ss` (`urllib.parse.quote(password, safe="")`).
- `socks5://` and `socks5h://` behave the same: the host name is always sent to the proxy, and
  there is no lookup in the local DNS. The exception is HTTP/3 through SOCKS5 (see below).
- A port is required for SOCKS. For `http://` and `https://` without a port, 80 and 443 are used.
- The environment variables `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` are not read.
  A proxy is used only when it is passed explicitly.

The URL is checked when the session is created and in every request with `proxy=`. The error is
`SessionConfigurationError` (a subclass of `ValueError`), and nothing is sent to the network.
Credentials are hidden in the error text.

```text
proxy '127.0.0.1:8080' has no scheme; write it as http://host:port (or https://, socks5://, ...)
proxy 'ftp://127.0.0.1:21': unsupported scheme 'ftp'; use one of http://, https://, socks5://, ...
proxy 'socks5://127.0.0.1': a SOCKS proxy needs a port (usually 1080)
```

Before 0.8.1, these errors appeared only on the first request, as `InvalidRequestError` with the
text `client creation failed: ...`.

## HTTP and HTTPS proxies

- **`https://` targets.** The client opens a tunnel with `CONNECT example.com:443 HTTP/1.1`. It
  carries the host name, not the IP. The TLS handshake with the server runs inside the tunnel
  with the profile's fingerprint: the proxy sees the ClientHello just as the server would see it.
- **`http://` targets.** The whole request goes to the proxy: `GET http://example.com/path HTTP/1.1`.
  The headers and their order are the profile's.
- **Authorization.** If the URL contains a username and password, the
  `Proxy-Authorization: Basic ...` header is sent right away, without waiting for a 407
  response. Digest, NTLM and Negotiate are not supported.
- **407 response.** With an `https://` target, the tunnel is not opened, and the request fails
  with `ProxyError`: `Proxy responded with non 200 code: 407 Proxy Authentication Required`. With
  an `http://` target, 407 arrives as a normal response: `r.status_code == 407`, as in requests.
- **The HTTPS proxy's certificate is not verified**, neither with `verify=True` nor with
  `verify=False`. Most clients do the same: the operator chooses the proxy, and proxy
  certificates are often issued for a name rather than an IP. The target server's certificate is
  verified according to `verify` as usual. Before 0.8.1, requests to `http://` through an HTTPS
  proxy did the opposite: they verified the proxy's certificate and failed on a self-signed one.

## SOCKS

- **SOCKS5** supports anonymous access and username/password. A wrong password gives
  `ProxyError`: `username/password authentication failed`.
- **SOCKS4** passes only an IPv4 address to the proxy: the name is resolved by the local DNS. If
  the local resolver must not see the name, use `socks4a://` or `socks5://`. A username in a
  SOCKS4 URL is ignored: the user id field is sent empty.
- **`http://` goes through SOCKS too.** Before 0.8.0, `http://` through `socks5h://` and
  `socks4://` was sent to the proxy as a plain HTTP request and did not work.

## HTTP/3 through a proxy

QUIC runs over UDP, and only SOCKS5 tunnels UDP (the UDP ASSOCIATE command).

| Settings | TCP (HTTP/1.1, HTTP/2) | QUIC (HTTP/3) |
|---|---|---|
| `proxy="socks5://..."` | through the proxy | through the same proxy's UDP relay |
| `proxy="http://..."` | through the proxy | configuration error with `http_version="3"` |
| `proxy="http://...", udp_proxy="socks5://..."` | through `proxy` | through `udp_proxy` |
| `udp_proxy="socks5://..."` without `proxy` | direct | through `udp_proxy` |

```python
from yumeclient import Session

with Session(client_identifier="chrome_144", http_version="3",
             proxy="http://user:pass@203.0.113.10:3128",       # TCP racing and the HTTP/2 fallback
             udp_proxy="socks5://user:pass@203.0.113.20:1080",  # QUIC
             ) as s:
    r = s.get("https://cloudflare-quic.com/")
    print(r.http_version)
```

- `udp_proxy` accepts only `socks5://` and `socks5h://`. It is incompatible with `keep_alpn`.
- **DNS for QUIC through SOCKS5 is local.** The UDP relay takes a destination address, so the
  host name is resolved on your machine and the proxy gets the IP. TCP connections of the same
  session still send the name to the proxy.
- **The QUIC fingerprint through a proxy is the same as without one.** This covers the
  connection ID length, the transport parameters and the first packet. Before 0.8.1, QUIC
  through SOCKS5 went through the standard dialer: a 4-byte source connection ID (Chrome uses 0),
  no `google_initial_rtt`, no events for stage timeouts.
- Profiles without HTTP/3 (`NO_HTTP3`: OkHttp, conscrypt, cloudscraper, tor) do not use QUIC,
  with a proxy either.

## Per-request proxy

`proxy=` in a request selects a proxy for that request only:

| `proxy=` | What happens |
|---|---|
| not passed or `None` | the session's proxy (or a direct connection if the session has none) |
| `"socks5://..."`, `"http://..."` | the given proxy |
| `""` | **direct connection**, even if the session has a proxy |

```python
with Session(proxy="socks5://127.0.0.1:1080") as s:
    s.get("https://example.com/")                          # through 127.0.0.1:1080
    s.get("https://example.com/", proxy="http://10.0.0.2:3128")  # through another proxy
    s.get("https://example.com/", proxy="")                # no proxy
```

The session has a separate native client with its own connections for each proxy. TLS sessions,
the HTTP/3 protocol cache and the connection pool are not shared between proxies. Cookies are
shared: there is one jar per session. There is no exception list (`NO_PROXY`): use `proxy=""` in
the requests that need it.

## Local address

`local_address="IP:port"` binds outgoing TCP connections to a local address. Port `0` means any
free port. With a proxy, the connection to the proxy is bound. This works with all proxy
schemes.

```python
with Session(local_address="192.0.2.15:0") as s:
    s.get("https://example.com/")
```

## Diagnostics

- `r.connection_info["remote_address"]` is the address the connection was made to. With a proxy,
  this is the proxy's address.
- `r.connection_info["timings"]["proxy"]` is the time to set up the tunnel (`CONNECT` or the SOCKS
  handshake) in seconds; without a proxy, `None`.
- Proxy errors are `ProxyError` (`kind="proxy"`, `stage="connect"`, `retryable=True`): the proxy
  does not respond, refuses the connection, authentication fails, or the tunnel does not open.
  The original error text is in `str(exc)` (with credentials hidden) and in `exc.__cause__`.

```python
from yumeclient import ProxyError, Session

try:
    with Session(proxy="http://127.0.0.1:1") as s:
        s.get("https://example.com/")
except ProxyError as exc:
    print(exc.kind, exc.stage, exc.retryable)   # proxy connect True
```
