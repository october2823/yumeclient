# Yume Client


```python
from yumeclient import Session, AsyncSession

with Session() as s:                       # sync
    r = s.get("https://httpbin.org/get")

async with AsyncSession() as s:            # async — same syntax, awaited
    r = await s.get("https://httpbin.org/get")
```

Sessions start with browser-plausible **default headers per profile and OS**
(`client_identifier` x `client_os`: windows / android / ios / macos), keep
RFC 6265-scoped cookies across redirect hops, and support `headers.update()`,
per-request overrides, one-shot `yumeclient.get(...)` / `await yumeclient.aget(...)` calls.

```python
from yumeclient import TimeoutConfig, ConnectTimeout

with Session(timeout=TimeoutConfig(connect=5, read=30)) as s:
    with s.get("https://example.com/big.bin", stream=True) as r:   # bounded memory
        for chunk in r.iter_bytes(1 << 20):
            ...
```

Async task cancellation aborts the native request immediately; errors are typed
(`ConnectTimeout`, `ReadTimeout`, `ProxyError`, `TLSError`, ...); `r.connection_info`
reports reuse, ALPN, TLS and phase timings. `http_version="2"` never falls back to
HTTP/1.1 silently, and conflicting protocol options fail before any network I/O.

```python
profile = s.export_profile()                       # versioned, JSON-safe TLS/HTTP identity
s2 = Session.from_profile(profile, proxy="socks5://127.0.0.1:1080")
yumeclient.fingerprint_diff(profile, s2.get(url))  # [] when the wire fingerprint matches
r.trace()                                          # redacted, shareable request trace
```

Wheels: Windows x64, Linux x86_64/aarch64, macOS universal2, any Python ≥ 3.11.


## Docs & examples

- [USAGE.md](USAGE.md) — полный справочник: API, профили, client_os, cookies, транспорт, multipart, ограничения (на русском).
- `examples/basic_requests.py` — базовый синтаксис: sync/async, headers, cookies, все методы.
- `examples/profiles_and_os.py` — выбор `client_identifier` и `client_os`.
- `examples/cookies_flow.py` — поведение cookie-jar: redirect-хопы, разовые куки, экспорт/импорт.

Tests: `python -m pytest tests -q` (offline, local HTTP server); add `--run-online` for live httpbin.org checks.

Upstream license: MIT; see `UPSTREAM-LICENSE`. Profile names and JSON field spellings track upstream v1.16.0.

Changelog: [CHANGELOG.md](CHANGELOG.md).

Contributors: [randomtempusername123](https://github.com/randomtempusername123).
