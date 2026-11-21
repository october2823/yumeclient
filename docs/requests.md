# Requests

**English** | [Русский](ru/requests.md)

```python
r = s.request("GET", "https://httpbin.org/get", params={"q": "yume"}, timeout=10)
r = s.get(url)
r = s.post(url, json={"name": "yume"})
```

`request(method, url, **kwargs)` and the wrapper methods `get`, `head`, `post`, `put`, `patch`,
`delete`, `options` exist on `Session`, on `AsyncSession` (with `await`) and at module level
(`yumeclient.get(...)`, `await yumeclient.aget(...)`). The method can be any token
(`"PROPFIND"`, `"PURGE"`); it is sent in upper case.

## Request parameters

| Parameter | Type | Description |
|---|---|---|
| `params` | `dict`, list of pairs | query string; lists of values are expanded (`{"a": [1, 2]}` → `a=1&a=2`) and appended to an existing `?` |
| `data` | `dict`, list of pairs, `bytes`, `str` | body: a form, raw bytes or text ([below](#request-body)) |
| `json` | any JSON-serializable object | JSON body, `Content-Type: application/json` |
| `files` | `dict` or list of pairs | multipart/form-data ([below](#files-multipart)) |
| `headers` | `dict` | headers for this request on top of the session headers; `None` removes a header |
| `cookies` | `dict`, list of dicts, `CookieJar` | cookies for this request only; they do not go into the session jar |
| `timeout` | number, tuple, `TimeoutConfig`, `None` | replaces the session timeout ([Timeouts](timeouts-and-errors.md)) |
| `proxy` | `str` | a proxy for this request only ([Proxies](proxies.md)) |
| `allow_redirects` | `bool`, default `True` | follow redirects |
| `header_order` | list of names | header order for this request |
| `host_override` | `str` | value of the `Host` header (`:authority` for HTTP/2 and HTTP/3); the connection, SNI and certificate verification use the host from the URL |
| `stream` | `bool`, default `False` | do not read the body right away ([Streaming](responses.md#streaming)) |
| `max_content_size` | `int` | limit on the decompressed body for this request |
| `retries` | `int`, `Retry` | replaces the session's retries for this request ([Retries](timeouts-and-errors.md#automatic-retries)) |

An unknown parameter raises `TypeError`, as with any function. An invalid URL (not `http://` or
`https://`, no host, an invalid port or control characters), method or header raises
`InvalidRequestError` (`kind="invalid_request"`, `stage="request"`) before any network access.
Before 0.8.1, an invalid URL raised `ConnectError` with `retryable=True`.

## Request body

```python
s.post(url, data={"login": "yume", "remember": "1"})   # application/x-www-form-urlencoded
s.post(url, data=[("tag", "a"), ("tag", "b")])        # form with repeated fields
s.post(url, json={"items": [1, 2, 3]})                # application/json, compact: {"items":[1,2,3]}
s.post(url, data=b"\x00\x01binary")                   # application/octet-stream
s.post(url, data="plain text")                        # UTF-8, no Content-Type
s.post(url, data=b"...", headers={"Content-Type": "image/png"})
```

| `data` / `json` | Default `Content-Type` | Encoding |
|---|---|---|
| `json=` | `application/json` | `json.dumps` without spaces (like `JSON.stringify`) |
| `data=dict` or list of pairs | `application/x-www-form-urlencoded` | `urlencode(doseq=True)` |
| `data=bytes` | `application/octet-stream` (none in okhttp style) | as is |
| `data=str` | none | UTF-8 |

A `Content-Type` you set always wins over the default. `headers={"Content-Type": None}`
removes the default for `bytes`; for a form, JSON and multipart the type is set anyway,
because without it the server cannot parse the body (`requests` behaves the same way).

The transport computes `Content-Length`. The body is sent in one piece: there is no streaming
upload (generators, files in chunks); pass `bytes`.

## Files (multipart)

```python
with open("report.pdf", "rb") as f:
    r = s.post(url, data={"title": "Report"}, files={"file": f})

r = s.post(url, files=[
    ("photos", ("a.jpg", jpg_bytes, "image/jpeg")),
    ("photos", ("b.jpg", other_bytes, "image/jpeg")),
    ("meta", ("meta.json", b'{"v": 1}', "application/json", {"X-Part": "1"})),
])
```

The file spec is the same as in `requests`:

| Value | File name | Part Content-Type |
|---|---|---|
| `bytes`, `str` or an open file | `name` of the open file; for `bytes` and `str`, the field name | by extension (`mimetypes`) |
| `(name, content)` | as given | by extension |
| `(name, content, type)` | as given | as given |
| `(name, content, type, {headers})` | as given | as given, plus extra part headers |

- `files` and `data` can be passed together: the `data` fields come first.
- Lists of pairs keep the order of parts and allow repeated names.
- `str` is encoded as UTF-8; quotes, CR and LF in names are escaped, as browsers do.
- The boundary is the same as Chrome's: `----WebKitFormBoundary` and 16 hex characters.

The encoder is available separately:

```python
from yumeclient import encode_multipart, choose_boundary

body, content_type = encode_multipart({"a": "1"}, {"file": ("x.txt", b"hi")})
```

## Headers

From the first request, a session has the profile's default headers: `User-Agent`,
`sec-ch-ua`, `Accept`, `Sec-Fetch-*`, `Accept-Encoding`, `Accept-Language`, the ones the
browser sends when navigating to a page, in its order
([Profiles](profiles.md#default-headers)).

```python
s.headers                                  # Headers: a case-insensitive dict
s.headers["Accept"] = "application/json"   # replace the value (the order does not change)
s.headers.update({"X-Token": "abc"})       # append at the end
del s.headers["Upgrade-Insecure-Requests"]
s.headers = {"User-Agent": "my-app/1.0"}   # replace the whole set

s.get(url, headers={"Accept": "text/css"})         # for this request only
s.get(url, headers={"User-Agent": None})           # no User-Agent in this request
```

### Case and `Headers`

`s.headers` and the result of `default_headers()` (for any profile) are `Headers`, a subclass
of `dict` in which all operations (`[]`, `get`, `in`, `del`, `pop`, `setdefault`, `update`,
`|`) are case-insensitive. A name is stored in the spelling it was first added with:
`h["user-agent"] = ...` replaces the value of `User-Agent` without changing its spelling.

Over HTTP/1.1, names go out spelled as they are in the dict (the browser writes `User-Agent`,
but `sec-ch-ua`). HTTP/2 and HTTP/3 lower-case the names, because the protocol requires it.

### Removing: `None`

`None` in request (or session) headers removes the header entirely, including headers the
transport would otherwise add:

- `Accept-Encoding` and `priority`, which the network layer adds;
- okhttp-style defaults: `User-Agent: okhttp/4.12.0`, `Connection`, `Accept-Encoding`.

Exceptions, as in `requests`: `Content-Type` for a form, JSON and multipart stays,
`{"Cookie": None}` removes only your header (cookies from the jar are still sent), and `Host`
and `Content-Length` are always sent.

### Validation

A header name must be an RFC 9110 token, and a value must not contain control characters (tab
and non-ASCII are allowed). Otherwise you get `InvalidRequestError` before sending. Over HTTP/2
and HTTP/3 you cannot send `Connection` (except `keep-alive` and `close`, which the transport
simply does not send), `Upgrade`, or `Transfer-Encoding` (except `chunked`); these also raise
`InvalidRequestError`, and the connection stays usable.

### Order

- Without `header_order`, headers go out in dict order: session headers first, then new ones
  from the request.
- `header_order=[...]` on the session or the request sets the order explicitly; headers not in
  the list come after the listed ones, in dict order.
- Over HTTP/1.1, `Host` goes first, as in all browsers, unless you put it elsewhere in
  `header_order`.
- The transport adds its own fields where the browser puts them: `Content-Length`, `Cookie`,
  `priority` for Chromium (last over HTTP/2 and HTTP/3), `te: trailers` for Firefox over
  HTTP/2.
- If `Accept-Encoding` is in neither the session nor the request, the transport appends
  `Accept-Encoding: gzip, deflate, br` (`gzip` in okhttp style). To leave it out, pass
  `{"Accept-Encoding": None}`. The transport does not add `User-Agent` by itself (except in
  okhttp style).

What actually went out is in `r.fingerprint["request_headers"]`, a list of pairs in wire order
and wire case ([Responses](responses.md#fingerprint)).

## Redirects

A request follows at most 20 redirects, like a browser (the Fetch standard); on the 21st it
raises `TooManyRedirects`. Before 0.8.1, the limit was Go's: an error on the 10th redirect,
so 9 were followed.
`allow_redirects=False` returns the 3xx response itself.

The method of the next request is chosen as in browsers (the Fetch standard):

| Code | Method and body of the next request |
|---|---|
| 301, 302 | `POST` becomes `GET` without a body; other methods are kept together with the body |
| 303 | everything except `GET` and `HEAD` becomes `GET` without a body |
| 307, 308 | the method and body are kept |

- When the method changes, `Content-Type`, `Content-Encoding`, `Content-Language`,
  `Content-Location`, `Content-Length` and `Origin` are dropped together with the body (as in
  Chromium).
- Before 0.8.1, on 301/302 any method (including `PUT`, `PATCH`, `DELETE`) became `GET`
  without a body, as in Go.
- `Referer` is not added on hops automatically (the browser keeps the original referrer, and so
  does `requests`); your `Referer` is carried over as is.
- On a move to another host or port (except a subdomain of the original host with the same
  port), `Authorization` and your `Cookie` header are dropped. Ports are compared with defaults
  taken into account, so a move from `http://host/` to `https://host/` (80 → 443) drops them
  too. Cookies from the jar are selected again for the new address.
- Every hop uses the profile's TLS and HTTP/2 parameters, including moves between `http://`
  and `https://`.
- Cookies set on any hop go into the jar.
- Followed redirects are in `r.history` ([Responses](responses.md#redirect-history)).

## Request cookies

```python
s.get(url, cookies={"ab_test": "b"})
```

Request cookies are added to the cookies from the session jar (on a name clash they win) and
are not saved in the jar. Whatever the server sets in the response goes into the jar as usual.
More in [Cookies](cookies.md).
