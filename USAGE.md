# yumeclient

Синхронный и асинхронный Python-клиент в стиле `requests` поверх
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) v1.16.0.
Python-слой не подменяет TLS-реализацию: каждый запрос уходит через Go-cffi
адаптер (`native/main.go`), который держит uTLS-фингерпринты, HTTP/2/3,
прокси и cookie-jar на стороне Go. Cookie, выставленные на любом hop'е
редиректа или для любого хоста внутри jar, возвращаются в Python (`jarDump`)
и мержатся в `session.cookies`.

## Установка

Для полноценного `pip install` нужен wheel под ОС и архитектуру — релизный workflow собирает их для Windows, Linux и macOS. После настройки PyPI Trusted Publishing:

```sh
python -m pip install yumeclient
```

Локальная сборка: Go 1.24+, cgo, C-компилятор (Windows: MinGW-w64).

```powershell
# Windows
$env:CGO_ENABLED = "1"
$env:CC = "x86_64-w64-mingw32-gcc"
go -C native build -buildmode=c-shared -o ../yumeclient/yumeclient.dll .
python -m pip install -e .
```

Linux/macOS: `sh scripts/build-native.sh`, затем `python -m pip install -e .`.
Путь к библиотеке можно задать через `YUMECLIENT_LIBRARY`.

## Быстрый старт

```python
import yumeclient                      # one-shot API, как в requests
from yumeclient import Session, AsyncSession, Profiles

# one-shot, без сессии
r = yumeclient.get("https://httpbin.org/get", timeout=30)

# sync-сессия
with Session() as s:                   # клиент-профиль и OS по умолчанию: chrome_152 / windows
    s.headers.update({"Accept": "application/json"})
    r = s.get("https://httpbin.org/get", params={"page": 1})
    print(r.status_code, r.http_version, r.json())

# async-сессия — тот же синтаксис, каждый метод с await
async def main():
    async with AsyncSession() as s:
        r = await s.post("https://httpbin.org/post", json={"hello": "world"})
        print(r.json()["json"])
```

Методы: `get`, `post`, `put`, `patch`, `delete`, `head`, `options` (+ `request(method, url)`).
Общие параметры запроса: `params`, `data`, `json`, `files`, `headers`, `cookies`,
`timeout`, `proxy`, `allow_redirects`, `header_order`, `host_override`.

### Sync / Async — что выбрать

| | `Session` | `AsyncSession` |
|---|---|---|
| Вызов | `r = s.get(url)` | `r = await s.get(url)` |
| Контекст | `with Session() as s:` | `async with AsyncSession() as s:` |
| Параллелизм | потоки/процессы снаружи | `asyncio.gather(*[s.get(...) ...])` |
| Пул | системный | общий executor, `AsyncSession.configure_executor(n)` до старта |

Оба класса — обёртки над одним движком: cookies, дефолтные заголовки и
транспортное поведение идентичны. Внутри asyncio используйте только
`AsyncSession` (блокирующий `Session` заморозит loop).

## Заголовки

Сессия стартует **не с пустых** заголовков: для каждого профиля собирается
браузерный baseline (user-agent, sec-ch-ua, accept, sec-fetch-*, accept-encoding,
accept-language), зависящий от `client_identifier` и `client_os`.

```python
from yumeclient import Session, default_headers

with Session() as s:
    print(s.headers)                # dict с дефолтами; порядок дикта = порядок на проводе

s.headers.update({"X-Token": "1"})          # точечное обновление (как в requests)
s.headers = {"User-Agent": "my/1.0"}        # полная замена — уйдут только эти
r = s.get(url, headers={"Accept": "text/css"})  # разовый override поверх сессионных
```

- Заголовки регистронезависимы: `s.headers["accept"]` и `s.headers["Accept"]` — один ключ.
- `header_order` не задан → порядок на проводе равен порядку вставки в `session.headers`.
- `header_order=[...]` или `header_order=` в запросе задаёт порядок явно.
- `default_headers(identifier, os)` возвращает baseline без сессии.

## Профили и client_os

```python
from yumeclient import Session, Profiles, ALL_IDENTIFIERS, find

with Session(client_identifier=Profiles.CHROME_152, client_os="android") as s:
    ...
```

- `ALL_IDENTIFIERS` — все 83 профиля upstream v1.16.0; `Profiles.*` — константы; `find("safari_ios")` — поиск по подстроке.
- `client_os` принимает `"windows"`, `"android"`, `"ios"`, `"macos"` и меняет **только baseline заголовков** (UA, client hints), не сам TLS-фингерпринт.
- По умолчанию OS выводится из профиля: `*_ios_* → ios`, `*_android_* → android`, desktop-safari → `macos`, остальное → `windows`.
- Chrome-на-iOS — это CriOS без client hints (как в реальном браузере); okhttp/zalando/nike/mesh/confirmed/mobile-профили получают app-подобные наборы.
- Неизвестный профиль или OS → `SessionConfigurationError` с подсказкой похожих вариантов.

## Cookies

`session.cookies` — `CookieJar` с идентичностью `(name, domain, path)` и
браузерной семантикой:

```python
s.get("https://httpbin.org/cookies/set/k/v")   # Set-Cookie → jar автоматически (включая redirect-хопы)
s.cookies["k"] = "v2"                          # заменить по имени
s.cookies.set("k", "v3", domain="httpbin.org") # заменить точечно по домену
s.cookies.update({"a": "1"})
s.cookies.load("a=1; b=2", domain="example.org")   # распарсить Cookie-заголовок
s.cookies.get("k"); "k" in s.cookies
s.cookies.remove("k"); s.cookies.clear_domain("example.org")
s.cookies.export()      # list[dict] для бэкапа; CookieJar(export) — восстановить
s.get(url, cookies={"temp": "1"})   # разовые cookie: уйдут, но в jar не попадут
```

Cookie с любого redirect-хопа и любого хоста сохраняются (в отличие от
наивного `resp.cookies`): адаптер отдаёт полный дамп jar'а после каждого запроса.
Куки без expires живут до конца сессии; с `expires` — до истечения.

## Тело запроса

```python
s.post(url, json={"a": 1})                      # application/json
s.post(url, data={"form": "field"})             # x-www-form-urlencoded
s.post(url, data=b"raw bytes")                  # octet-stream (base64 через границу)
s.post(url, data="plain text")
s.post(url, data=[("k", "1"), ("k2", "2")],     # multipart; порядок частей сохраняется
       files=[("file", ("doc.pdf", pdf_bytes))])
```

Спецификация файла в `files` — как в `requests`:
- "content" / b"bytes" / открытый файл — имя берётся из файла, Content-Type угадывается по расширению (`mimetypes`);
- `("doc.pdf", content)` — имя + содержимое;
- `("doc.pdf", content, "application/pdf")` — + явный Content-Type;
- `("doc.pdf", content, None, {"X-Extra": "1"})` — + доп. заголовки части.

`str`-содержимое уходит UTF-8; имена/файлы с `"`, CR, LF процент-экранируются как у браузеров и urllib3. Boundary — Chrome-подобная `----WebKitFormBoundary` + 16 hex. `encode_multipart(data, files, boundary=None)` доступна отдельно.

## Ответ

`Response`: `status_code` / `status`, `headers` (dict[str, list[str]]),
`cookies`, `content`, `text`, `encoding`, `url`, `elapsed`, `history`,
`used_protocol`, `http_version` ("1.1"/"2"/"3"), `ok`, `json()`,
`raise_for_status()`, `r["Content-Type"]` — регистронезависимо.

## Транспортные параметры сессии

`client_identifier`, `client_os`, `random_tls_extension_order=True`,
`http_version` (`"auto"`/`"1.1"`/`"2"`/`"3"` или числа/`"h2"`/`"h3"`),
`proxy` (`http(s)://`, `socks5://`; для HTTP/3 — только socks5),
`timeout`, `verify`, `force_http1`, `disable_http3`, `disable_session_tickets`,
`server_name_overwrite`, `local_address`, `header_order`, `headers`, `cookies`,
полный набор custom-JA3 полей (`ja3_string`, `h2_settings`, `pseudo_header_order`, ... —
только вместе с `ja3_string`).

Транспортные атрибуты можно менять между запросами — сессия пересоздаст
Go-клиент. `await session.reset_connection()` (или `session.reset_connection()`
для sync) пересоздаёт соединение принудительно. Смена `proxy` между запросами
поддержана.

## Multipart

Mapping или последовательность пар принимаются для полей/файлов. Последовательности сохраняют порядок частей. Кодировщик создаёт CRLF-разделители и Chrome-подобную границу `----WebKitFormBoundary` плюс 16 hex-символов. Функция `encode_multipart` доступна для отдельного использования.

## Ограничения

`stream=True` не поддерживается: ответ целиком буферизуется в памяти. Upstream CFFI не отдаёт redirect history, поэтому `history` пока пуст. Автодополнение custom JA3 из Chrome defaults не реализовано — передавайте поддерживаемые поля через схему upstream. Для некоторых профилей нет браузерно-точных HTTP/3 настроек; при запросе HTTP/3 используются параметры upstream по умолчанию. Публикация выполняется только после успешных CI-сборок и настройки Trusted Publishing в PyPI.

## Примеры и тесты

Папка `examples/` — runnable-сценарии: `basic_requests.py` (синтаксис),
`profiles_and_os.py` (профили/OS), `cookies_flow.py` (куки). Тесты — `python -m pytest tests -q`; сетевые проверки добавляются флагом `--run-online`.
