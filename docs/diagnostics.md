# Диагностика: профили, сравнение отпечатков, трейсы

Три инструмента:

- **`export_profile` / `from_profile`** — сохранить конфигурацию сессии в JSON и восстановить
  её на другой машине;
- **`fingerprint_diff`** — проверить, что запрос ушёл с ожидаемым отпечатком;
- **`Response.trace()`** — описать запрос и ответ без секретов, чтобы приложить к баг-репорту.

Отпечаток отдельного ответа (`r.fingerprint`) и сведения о соединении (`r.connection_info`)
описаны в [Ответ](responses.md).

```python
import json
from yumeclient import Session, fingerprint_diff

with Session(client_identifier="chrome_146", http_version="2") as s:
    s.get("https://example.com/")
    profile = s.export_profile()

with open("profile.json", "w") as f:
    json.dump(profile, f, indent=1)

# позже, на другой машине
with open("profile.json") as f:
    profile = json.load(f)
with Session.from_profile(profile, proxy="socks5://127.0.0.1:1080") as s:
    r = s.get("https://example.com/")
    problems = [d for d in fingerprint_diff(profile, r) if d["kind"] != "order"]
    print(problems or "тот же отпечаток")
    print(json.dumps(r.trace(), indent=1))
```

## `export_profile`

```python
profile = session.export_profile(include_fingerprint=True, include_secrets=False)
```

Возвращает словарь, который можно сериализовать в JSON:

```python
{
    "format": "yumeclient.profile",
    "version": 1,
    "yumeclient": "0.8.1",
    "transport": {                       # параметры, определяющие отпечаток
        "client_identifier": "chrome_146",
        "client_os": "windows",
        "header_style": "raw",
        "http_version": "auto",
        # + все явно переданные параметры ClientHello / HTTP/2 / HTTP/3
    },
    "headers": [["Connection", "keep-alive"], ["sec-ch-ua", "..."], ...],  # в порядке отправки
    "omitted_headers": ["Authorization", "X-Api-Key"],
    "fingerprint": {                     # последний отпечаток сессии (если был запрос)
        "ja3": "...", "ja3_hash_md5": "...", "ja4": "...", "ja4_r": "...",
        "akamai_fingerprint": "...", "alpn_offered": [...], "tls_extensions": [...],
        "header_order": [...], "source": "wire",
    },
}
```

**Что попадает в `transport`:** профиль, ОС, стиль заголовков, `http_version`, а также явно
заданные параметры отпечатка: `ja3_string`, списки ClientHello, `h2_settings`,
`pseudo_header_order`, `random_tls_extension_order`, `force_http1`, `disable_http3`,
`keep_alpn`, `trust_anchors_payload` и другие. Значения, равные значениям по умолчанию, не
пишутся. Байтовые поля (`ech_config_list`, `key_share_data`) кодируются в base64,
`trust_anchors_payload` — в hex.

**Что не попадает:** прокси, `udp_proxy`, таймауты, cookies, `verify`, `local_address`,
`max_content_size`. Это окружение, секреты или лимиты, а не отпечаток. При восстановлении
передайте их как `overrides`.

**Заголовки с учётными данными** не экспортируются: `Authorization`, `Cookie` и заголовки,
в имени которых есть `token`, `secret`, `session`, `auth`, `key`, `cookie`, `passw`,
`signature`, `credential`. Их имена перечислены в `omitted_headers`. Задайте их заново после
`from_profile` или экспортируйте со значениями: `export_profile(include_secrets=True)`.

`include_fingerprint=False` не добавляет блок `fingerprint`.

В `fingerprint.header_order` не учитываются заголовки, которые зависят от конкретного
запроса: `Cookie`, `Content-Length`, `Content-Type`, `Authorization`, `Referer`, `Origin`,
`Range` и условные (`If-*`).

## `from_profile`

```python
session = Session.from_profile(profile, **overrides)
session = AsyncSession.from_profile(profile, **overrides)
```

Создаёт сессию из документа `export_profile`. Параметры транспорта и заголовки
восстанавливаются точно: порядок, написание имён, удалённые заголовки. `overrides` —
любые параметры конструктора (`proxy=`, `timeout=`, `verify=`, `cookies=`...); они
перекрывают значения из профиля.

Ошибки (`SessionConfigurationError`):

| Документ | Сообщение |
|---|---|
| другой `format` | `not a yumeclient.profile document` |
| `version` новее поддерживаемой | `profile version 2 is newer than this yumeclient supports (1); upgrade yumeclient` |
| `version` не целое | `invalid profile version: '1'` |
| неизвестный параметр в `transport` (например, `proxy`) | `unknown profile option(s): proxy` |
| `headers` не список пар | `profile 'headers' must be a list of [name, value] pairs` |
| противоречивые параметры | то же сообщение, что у конструктора |

## `fingerprint_diff`

```python
differences = fingerprint_diff(expected, actual)
```

`expected` и `actual` — `Response`, документ `export_profile` или словарь отпечатка
(`r.fingerprint`). Проверяются только поля, которые есть в `expected`. Пустой список —
отпечатки совпадают.

Каждое отличие — словарь `{"field", "kind", "expected", "actual"}` (для `set` ещё
`missing` и `unexpected`):

| `kind` | Значение |
|---|---|
| `value` | значения разные |
| `missing` | поле есть в `expected`, но не в `actual` |
| `order` | те же элементы в другом порядке |
| `set` | разный набор элементов; `missing` — чего нет в `actual`, `unexpected` — что лишнее |

Сравниваемые поля: `ja4`, `ja4_r`, `ja3` (по компонентам: `ja3.version`, `ja3.ciphers`,
`ja3.extensions`, `ja3.groups`, `ja3.point_formats`), `ja3_hash_md5` (только если `ja3` не
задан), `akamai_fingerprint`, `alpn_offered`, `alpn_negotiated`, `tls_version`, `tls_cipher`,
`http_protocol`, `tls_extensions`, `header_order`. GREASE-значения не учитываются.

**Порядок расширений у Chromium случайный.** Chrome перемешивает расширения в каждом
соединении, и профили Chromium делают так же (`random_tls_extension_order=True`). Поэтому
два запроса одного профиля дают отличия `kind="order"` в `ja3.extensions` и
`tls_extensions` — это норма. JA4 от порядка не зависит. Фильтруйте:

```python
real = [d for d in fingerprint_diff(profile, r) if d["kind"] != "order"]
```

Пример отличий `chrome_146` от `firefox_147`:

```python
[("ja4", "value"), ("ja4_r", "value"), ("ja3.ciphers", "set"), ("ja3.extensions", "set"),
 ("ja3.groups", "set"), ("akamai_fingerprint", "value"), ("tls_extensions", "set"),
 ("header_order", "set")]
```

## `Response.trace`

```python
trace = response.trace(redact=(), values=True, redact_query=True)
```

Возвращает JSON-совместимое описание запроса и ответа:

```python
{
    "format": "yumeclient.trace", "version": 1, "yumeclient": "0.8.1",
    "request_id": "16a39d51...", "elapsed": 0.058,
    "request": {
        "method": "GET",
        "url": "https://example.com/x?token=[redacted]&q=[redacted]",
        "header_order": [...], "header_source": "wire",
        "headers": [["Host", "example.com"], ["Connection", "keep-alive"], ...],
        "body": {"length": 0, "sha256": "..."},
    },
    "response": {"status": 200, "url": "...", "http_protocol": "HTTP/2.0",
                 "headers": [...], "body": {"length": 1256, "sha256": "..."}},
    "redirects": [{"status": 302, "url": "..."}],   # хопы history: статус и URL
    "connection": {"alpn_negotiated": "h2", "tls_version": "1.3", "tls_cipher": "...",
                   "tls_resumed": False, "connection_reused": False,
                   "remote_address": "...", "timings": {...}},
    "tls": {"ja3": "...", "ja4": "...", "ja4_r": "...", "akamai_fingerprint": "..."},
}
```

Что скрывается:

- **URL:** логин и пароль убираются, фрагмент тоже. Значения параметров query заменяются на
  `[redacted]`; часть query без `=` скрывается целиком. Путь не меняется. То же для
  URL-заголовков `Location`, `Content-Location`, `Referer`, `Origin`, `Link`, `Refresh`.
  `redact_query=False` оставляет query как есть.
- **Заголовки:** значения `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` и
  заголовков, в имени которых есть `token`, `secret`, `session`, `auth`, `key`, `cookie`,
  `passw`, `signature`, `credential`, заменяются на `"[redacted]"`. `redact=("X-Trace",)`
  добавляет свои имена. `values=False` убирает значения всех заголовков (остаются имена и
  порядок).
- **Тела:** только длина и SHA-256. Для тела запроса больше 8 MiB — только длина.

SHA-256 короткого тела с секретом (например, пароля в форме) можно подобрать перебором.
Учитывайте это, прежде чем публиковать трейс.

Заголовки запроса в трейсе идут в порядке отправки (`header_source: "wire"`), включая
добавленные транспортом (`Host`, `Accept-Encoding`, `Content-Length`).

## Эталонные отпечатки профилей

`tests/fixtures/profiles.json` хранит эталон для каждого профиля: JA3, JA4, JA4_r, ALPN,
порядок расширений, Akamai, порядок заголовков. Тест `tests/test_profile_fixtures.py`
сравнивает с ним текущую сборку.

```bash
python scripts/profile_fixtures.py            # показать отличия
python scripts/profile_fixtures.py --update   # перезаписать эталон
```

Отпечатки HTTP/3 хранятся отдельно, в `native/h3profiles.json`; их проверяет
`tests/test_h3_fingerprints.py`. Как снимать новые записи, см. [Разработка](development.md).
