# Cookies

**English** | [Русский](ru/cookies.md)

All session cookies are stored in `s.cookies`, a `CookieJar` object. It is the only store: each
request gets a snapshot of it. On every hop, including redirects, the native part selects
cookies according to RFC 6265 and returns only the changes. The changes are visible in
`s.cookies` right away.

```python
from yumeclient import Session

with Session() as s:
    s.get("https://httpbin.org/cookies/set?session=abc")   # Set-Cookie on a redirect → into the jar
    print(s.cookies["session"])                            # 'abc'
    print(s.get("https://httpbin.org/cookies").json())     # {'cookies': {'session': 'abc'}}
```

## Which cookies are sent with a request

A cookie is sent to a URL if all of these conditions hold:

- **domain.** A cookie without a `Domain` attribute (host-only) is sent only to the host that
  set it. A cookie with `Domain=example.com` is sent to `example.com` and all its subdomains;
- **path.** The request path starts with the cookie's `Path` (by segments: `/a` matches `/a/b`,
  but not `/ab`);
- **Secure.** A cookie with `Secure` is sent only over `https://`. If it was set over
  `http://`, it is stored but not sent over `http://`;
- **expiry.** The cookie has not expired. A cookie without `Expires`/`Max-Age` lives until the
  end of the session.

The order in the `Cookie` header is the same as in browsers: cookies with a longer path first,
and for equal paths, older ones first.

A server cannot set a cookie:

- for someone else's domain: a response from `a.com` with `Domain=b.com` is dropped;
- for a public suffix (`Domain=com`, `co.uk`, `github.io`, per the Mozilla Public Suffix List,
  as in browsers): such a cookie is dropped. The exception is the suffix host itself, for which
  the cookie becomes host-only;
- with `Domain=` on an IP address: the cookie becomes host-only.

Deletion by the server (`Max-Age=0` or `Expires` in the past) removes the cookie from the jar.

## Manually set cookies

```python
s.cookies["token"] = "x"                           # no domain: sent to any host
s.cookies.set("sid", "1", domain="example.com")    # example.com and subdomains
s.cookies.set("sid", "1", domain="example.com", host_only=True)   # example.com only
s.cookies.set("pref", "dark", domain="example.com", path="/app",
              secure=True, http_only=True, same_site="Lax",
              expires=1767225600)                  # Unix time in seconds
```

A cookie without a domain behaves as in `requests`: it is sent to any host. If there is a
cookie with the same name and a domain for the host, that one is sent instead of the cookie
without a domain.

`s.cookies[name] = value` changes the value of an existing cookie with this name and path `/`.
If there are several, the one with the longest domain is changed. If there is none, a cookie
without a domain is created. To set a cookie for a specific domain, use `set(..., domain=...)`.

A cookie without a domain is not the same as a cookie the server would have set. The server can
override it with its own cookie for the host, but cannot delete it with `Max-Age=0`: deletion
applies to its host's cookies. `requests` behaves the same way. Delete such cookies yourself:
`s.cookies.remove(name)`.

## Single-request cookies

```python
s.get(url, cookies={"temp": "1"})
```

These cookies are sent only with this request and replace session cookies with the same name.
They do not go into the jar unless the server sets them itself. Accepted values are a `dict`, a
`CookieJar` (the cookies for this URL are taken) and a list of dicts
`{"name": ..., "value": ...}`.

A manually set `Cookie` header (`headers={"Cookie": "a=1"}`) is sent as is, and cookies from
the jar are appended after it in the same header: `Cookie: a=1; sid=...`. On a redirect to
another host the manual header is removed, and cookies from the jar are selected again for the
new host. Usually `cookies=` or `s.cookies.set(...)` is more convenient.

## `CookieJar` API

| Method | What it does |
|---|---|
| `CookieJar(initial=None)` | `initial`: a `dict` name → value (cookies without a domain) or a list of dicts in the browser export format |
| `jar[name]`, `jar.get(name, default=None)` | the value; with several cookies of the same name, the one with the longest domain. Expiry is not checked (an expired cookie is not sent, but you can read it). `jar[name]` with no such cookie raises `KeyError` |
| `name in jar` | whether there is a cookie with this name |
| `jar[name] = value` | see [above](#manually-set-cookies) |
| `jar.set(name, value, *, domain="", path="/", expires=None, secure=False, http_only=False, same_site=None, host_only=False)` | with `domain`: add or replace the cookie with the same `(name, domain, path)`. Without `domain`: like `jar[name] = value`, the value of an existing cookie with this name and path (the one with the longest domain) is changed, and the other arguments except `expires` are not applied; if there is none, a cookie without a domain is created |
| `jar.update(values, *, domain="")` | several cookies: a `dict` (each one like `set(name, value, domain=domain)`) or a list of dicts |
| `jar.load("a=1; b=2", *, domain="")` | parse a `Cookie` header value |
| `jar.remove(name, *, domain=None, path=None)` | delete; without `domain`/`path`, all cookies with this name |
| `jar.clear_domain(domain)` | delete the cookies with this domain (subdomain cookies are not affected) |
| `jar.for_url(url)` | the `list[JarCookie]` that will be sent to `url`, in header order |
| `jar.to_dict(*, url=None, domain=None)` | name → value: for `url`, by all the rules; for `domain`, by host only; without arguments, all unexpired cookies |
| `jar.get_cookie(name)` | `http.cookiejar.Cookie` or `None` |
| `jar.export()` | a list of dicts for saving |
| `len(jar)`, `for c in jar` | the number of cookies; iteration over `JarCookie` |

`JarCookie` is a dataclass with the fields `name`, `value`, `domain`, `path`, `expires` (Unix
time or `None`), `secure`, `http_only`, `same_site`, `host_only`.

A `CookieJar` can be used from several threads and from several `AsyncSession` tasks at once.
It supports `copy.deepcopy` and `pickle`.

## Import and export

`export()` produces the format of browser extensions (Cookie-Editor, EditThisCookie): `name`,
`value`, `domain`, `path`, `expirationDate`, `secure`, `httpOnly`, `sameSite`, `hostOnly`. The
`CookieJar` constructor and `update()` accept the same format. Instead of `expirationDate` you
can give `expires`.

```python
import json
from yumeclient import CookieJar, Session

with Session() as s:
    s.get("https://httpbin.org/cookies/set?a=1")
    json.dump(s.cookies.export(), open("cookies.json", "w"))

jar = CookieJar(json.load(open("cookies.json")))
with Session(cookies=jar) as s:
    print(s.get("https://httpbin.org/cookies").json())   # {'cookies': {'a': '1'}}
```

Cookies exported from a browser are moved the same way: export them to JSON with an extension
and pass the list to `CookieJar(...)`.

## Where else cookies show up

- `r.cookies`: a `dict` of cookies for the final URL after the exchange: the matching session
  and request cookies plus the ones set by responses, minus deleted ones.
- `r.history[i].cookies`: only the `Set-Cookie` of that hop.
- `r.headers["Set-Cookie"]`: the raw headers of the last response.
