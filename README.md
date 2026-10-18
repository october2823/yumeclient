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
cookies across redirect hops, and support `headers.update()`, per-request
overrides, one-shot `yumeclient.get(...)` / `await yumeclient.aget(...)` calls.


## Docs & examples

- [USAGE.md](USAGE.md) — полный справочник: API, профили, client_os, cookies, транспорт, multipart, ограничения (на русском).
- `examples/basic_requests.py` — базовый синтаксис: sync/async, headers, cookies, все методы.
- `examples/profiles_and_os.py` — выбор `client_identifier` и `client_os`.
- `examples/cookies_flow.py` — поведение cookie-jar: redirect-хопы, разовые куки, экспорт/импорт.

Tests: `python -m pytest tests -q` (offline, local HTTP server); add `--run-online` for live httpbin.org checks.

Upstream license: MIT; see `UPSTREAM-LICENSE`. Profile names and JSON field spellings track upstream v1.16.0.

Contributors: [randomtempusername123](https://github.com/randomtempusername123).
