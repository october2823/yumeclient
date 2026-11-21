# Responses and streaming

**English** | [Русский](ru/responses.md)

```python
r = s.get("https://httpbin.org/json")
r.status_code        # 200
r.ok                 # True for 200–399
r["Content-Type"]    # 'application/json'
r.json()             # dict
r.http_version       # '2'
r.elapsed            # 0.148 (seconds)
```

## `Response` attributes

| Attribute | Type | Description |
|---|---|---|
| `status_code`, `status` | `int` | response status code |
| `ok` | `bool` | `200 <= status_code < 400` |
| `headers` | `dict[str, list[str]]` | response headers: name → list of values. Values are as the server sent them; names are canonicalized (`x-lower-case` → `X-Lower-Case`) |
| `r["Name"]` | `str` | header values joined with `", "`, case-insensitive; `KeyError` if the header is missing |
| `cookies` | `dict[str, str]` | cookies for the final URL after the exchange: the matching session and request cookies plus the ones set by responses (`Set-Cookie` of all hops), minus deleted ones. The whole jar is in `s.cookies` |
| `content` | `bytes` | the body, already decompressed (gzip, deflate, br, zstd) |
| `text` | `str` | the body as text: the encoding from `charset` in `Content-Type`, otherwise `encoding`; errors are replaced |
| `encoding` | `str` | the encoding for `text` when the server did not specify one; default `"utf-8"`, can be assigned |
| `json()` | | `json.loads(r.text)`; invalid JSON raises `json.JSONDecodeError` (`ValueError`) |
| `url` | `str` | the final URL after redirects |
| `history` | `list[Response]` | followed redirects, from first to last |
| `is_redirect` | `bool` | a 3xx response with `Location` (when the redirect was not followed) |
| `elapsed` | `float` | request duration in seconds, including redirects; without `stream=True` it includes reading the body, with `stream=True` it ends at the headers |
| `http_version` | `str` | `"1.1"`, `"2"` or `"3"` |
| `used_protocol` | `str` | the transport's protocol string: `"HTTP/1.1"`, `"HTTP/2.0"`, `"HTTP/3.0"` |
| `connection_info` | `dict` | connection, TLS, addresses, timings ([below](#connection_info)) |
| `fingerprint` | `dict` | the fingerprint of what went out on the wire ([below](#fingerprint)) |
| `request_id` | `str` | the request id in the native layer (exceptions have it too) |
| `attempts` | `int` | how many times the request was sent: `1`, or more with [retries](timeouts-and-errors.md#automatic-retries) |
| `raise_for_status()` | | `HTTPStatusError` for codes outside 200–399; the response is in `e.response` |
| `trace()` | | a description of the request without secrets ([Diagnostics](diagnostics.md#responsetrace)) |

`repr(r)` is `<Response [200] 148ms>`.

`r.headers` holds the headers as the server sent them, including `Content-Encoding` and the
`Content-Length` of the compressed body, while `r.content` is already decompressed, the same
as in `requests`. You do not need to decompress the body again.

## Redirect history

```python
r = s.get("https://httpbin.org/redirect/2")
[h.status_code for h in r.history]   # [302, 302]
r.history[0].headers["Location"]
r.url                                # https://httpbin.org/get
```

Each `history` item has `status_code`, `headers`, `cookies` (its `Set-Cookie`), `url`,
`used_protocol`, `elapsed` (from sending this hop to its headers) and `content`, the
decompressed redirect body.

A redirect body is read only while it arrives quickly: if it is larger than 64 KiB, the server
is silent for longer than 0.5 s (or longer than the `read` timeout, if that is smaller),
reading takes more than 2 s, or the body does not decompress, then `content` is `b""`, and the
redirect is still followed.

With `allow_redirects=False` or without redirects, `history == []`.

## connection_info

```python
{
    "connection_reused": False,
    "alpn_negotiated": "h2",
    "tls_version": "1.3",
    "tls_cipher": "TLS_AES_128_GCM_SHA256",
    "tls_resumed": False,
    "http_protocol": "HTTP/2.0",
    "remote_address": "203.0.113.5:443",
    "local_address": "192.168.1.10:51123",
    "timings": {"redirects": 0.0, "connect": 0.081, "proxy": None, "write": 0.0002,
                "wait": 0.064, "body": 0.003, "first_byte": 0.145, "total": 0.148},
}
```

- Everything refers to the last hop (after redirects).
- `connection_reused`: the request went over an already open connection (keep-alive, HTTP/2
  or HTTP/3 multiplexing).
- `alpn_negotiated`: what the server chose (`""` means no ALPN was sent). For `http://` and
  for HTTP/3 there are no TLS fields and no `alpn_negotiated`: the QUIC handshake is not
  recorded.
- Through a proxy, `remote_address` is the address of the proxy.

Timings, in seconds:

| Field | What it measures |
|---|---|
| `redirects` | time until the start of the last hop: previous hops and request preparation |
| `connect` | DNS, proxy, TCP (or QUIC) and TLS of the last hop; `None` if the connection was reused |
| `proxy` | the part of `connect` spent on the path through the proxy (TCP to the proxy, CONNECT or SOCKS); `None` without a proxy or when the connection was reused |
| `write` | sending the headers and the body |
| `wait` | waiting for the response headers after sending |
| `body` | reading the body |
| `first_byte` | from the start of the request to the response headers |
| `total` | the whole request; `redirects + connect + write + wait + body` |

## fingerprint

`r.fingerprint` is the fingerprint of the connection the request went over. It is computed
from the ClientHello bytes that actually went into the socket and matches what Wireshark or
tshark show (`tls.handshake.ja3`, `tls.handshake.ja4`).

| Field | Description |
|---|---|
| `ja3`, `ja3_hash_md5` | JA3 and its MD5 |
| `ja4`, `ja4_r` | JA4 (FoxIO) and its raw form |
| `tls_extensions` | ClientHello extensions in order (GREASE included) |
| `alpn_offered` | ALPN offered in the ClientHello |
| `akamai_fingerprint`, `akamai_hash_sha256_96` | HTTP/2 fingerprint (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-headers) |
| `http_protocol` | the response protocol |
| `connection_reused` | the request went over an open connection |
| `request_headers` | `[[name, value], ...]`: headers in the order and case in which the transport wrote them to the connection; for HTTP/2 and HTTP/3 including pseudo-headers |
| `source` | `"wire"`: computed from the recorded TCP ClientHello; `"config"`: there was none (a request over `http://`, any response over HTTP/3), so the values are computed from the configuration |

A reused connection had no ClientHello: the TLS fields refer to the handshake that started that
connection. `s._core.last_fingerprint` holds the fingerprint of the session's last request.

To compare a fingerprint with a reference, use `fingerprint_diff()`
([Diagnostics](diagnostics.md)).

## Streaming

With `stream=True`, the request returns the response as soon as the headers have arrived, and
the body stays in the native layer until you read it. Memory use is bounded by the chunk size.

```python
with s.get(url, stream=True) as r:
    r.raise_for_status()
    with open("file.bin", "wb") as f:
        for chunk in r.iter_bytes(256 * 1024):
            f.write(chunk)
```

```python
async with AsyncSession() as s:
    async with await s.get(url, stream=True) as r:
        async for chunk in r.aiter_bytes():
            ...
```

| Sync | Async | |
|---|---|---|
| `r.iter_bytes(chunk_size=65536)` | `r.aiter_bytes(chunk_size=65536)` | chunks of up to `chunk_size` bytes |
| `r.iter_content(chunk_size, decode_unicode=False)` | | as in `requests`; `decode_unicode=True` yields strings |
| `r.read()` | `await r.aread()` | read the rest into `r.content` |
| `r.close()` | `await r.aclose()` | close without reading the rest |
| `with r:` | `async with r:` | close on exit |
| `r.is_stream_consumed` | | the body has been read to the end or closed |

- Leaving an `iter_bytes`/`aiter_bytes` loop (including `break` and an exception) closes the
  stream. Reading a closed stream again raises `StreamClosed`.
- For a sync response, accessing `r.content` reads the rest of the body. For an async response
  you first need `await r.aread()`; otherwise `r.content` raises `StreamClosed`
  (`kind="stream_not_read"`).
- With `stream=True`, the `total` timeout ends at the headers; after that the body is limited
  by the `read` timeout as the pause between chunks ([Timeouts](timeouts-and-errors.md)).
- `max_content_size` applies to streams too: exceeding it raises `ResponseTooLarge` during
  reading.
- Closing the session closes its open streams. An abandoned stream is released by the garbage
  collector, but until then the connection stays busy, so close streams explicitly.
