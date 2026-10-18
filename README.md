# Yume Client

Sync & async `requests`-style Python client over `github.com/bogdanfinn/tls-client` v1.16.0. The Python layer never substitutes another TLS implementation: it calls the upstream Go `cffi_src` client through a small cgo shared-library adapter. The Go client remains responsible for uTLS fingerprints, HTTP/2/3, proxies, cookies and profiles.

```python
from yumeclient import Session, AsyncSession

with Session() as s:                       # sync
    r = s.get("https://httpbin.org/get")

async with AsyncSession() as s:            # async — same syntax, awaited
    r = await s.get("https://httpbin.org/get")
```

Sessions start with browser-plausible **default headers per profile and OS**
(`client_identifier` x `client_os`: windows / android / ios / macos), keep
cookies across redirect hops, and support `headers.update()`, per-request
overrides, one-shot `yumeclient.get(...)` / `await yumeclient.aget(...)` calls.

## Install

Requires Go 1.24.1, a C compiler, and network access for Go modules. The importable Python package lives in `yumeclient/`; build from the `native/` directory:

```sh
cd native && go build -buildmode=c-shared -o ../yumeclient/yumeclient.so .
cd .. && python -m pip install -e .
```

On Windows use `-o ../yumeclient/yumeclient.dll`; on macOS use `.dylib`. Set `YUMECLIENT_LIBRARY` to the resulting library path if it is elsewhere. The shared library must be built for the host OS/architecture.

## Docs & examples

- [USAGE.md](USAGE.md) — полный справочник: API, профили, client_os, cookies, транспорт, multipart, ограничения (на русском).
- `examples/basic_requests.py` — базовый синтаксис: sync/async, headers, cookies, все методы.
- `examples/profiles_and_os.py` — выбор `client_identifier` и `client_os`.
- `examples/cookies_flow.py` — поведение cookie-jar: redirect-хопы, разовые куки, экспорт/импорт.

Tests: `python -m pytest tests -q` (offline, local HTTP server); add `--run-online` for live httpbin.org checks.

Upstream license: MIT; see `UPSTREAM-LICENSE`. Profile names and JSON field spellings track upstream v1.16.0.
