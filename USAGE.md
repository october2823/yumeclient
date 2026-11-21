# Руководство yumeclient

Практическое руководство: как решать типичные задачи, с примерами. Полное описание каждой
темы — в [справочнике](docs/index.md), готовые скрипты — в [examples/](examples/).

- [Установка](#установка)
- [Первый запрос](#первый-запрос)
- [Сессии](#сессии)
- [Профили: под кого маскироваться](#профили-под-кого-маскироваться)
- [Заголовки](#заголовки)
- [Параметры и тело запроса](#параметры-и-тело-запроса)
- [Ответ](#ответ)
- [Cookies](#cookies)
- [Таймауты и ошибки](#таймауты-и-ошибки)
- [Большие ответы: стриминг](#большие-ответы-стриминг)
- [Прокси](#прокси)
- [HTTP/2 и HTTP/3](#http2-и-http3)
- [Проверка отпечатка](#проверка-отпечатка)
- [Свой TLS-отпечаток](#свой-tls-отпечаток)
- [Рецепты](#рецепты)

## Установка

```bash
pip install yumeclient
```

Готовые wheel есть для Windows x64, Linux x86-64/aarch64 (glibc 2.17+) и macOS 11+
(Intel и Apple Silicon), Python 3.11+. Других зависимостей нет. Сборка из исходников и прочие
платформы — в [Установке](docs/installation.md).

## Первый запрос

```python
import yumeclient

r = yumeclient.get("https://httpbin.org/get", params={"q": "test"})
print(r.status_code)       # 200
print(r.json()["args"])    # {'q': 'test'}
print(r.http_version)      # '2'
```

`yumeclient.get`, `post`, `put`, `patch`, `delete`, `head`, `options` и `request` создают
сессию на один запрос. Запрос уходит как из последнего Chrome (`chrome_152`): его
ClientHello, его HTTP/2 и его заголовки.

## Сессии

Для нескольких запросов используйте сессию: она держит соединения, cookie и заголовки.

```python
from yumeclient import Session

with Session(client_identifier="chrome_152", timeout=20) as s:
    s.get("https://example.com/login")
    r = s.post("https://example.com/login", data={"user": "me", "password": "secret"})
    r = s.get("https://example.com/account")   # cookie после логина уже в сессии
```

Асинхронный вариант — `AsyncSession` с теми же параметрами и методами:

```python
import asyncio
from yumeclient import AsyncSession

async def main():
    async with AsyncSession(timeout=20) as s:
        pages = await asyncio.gather(*(s.get(f"https://httpbin.org/get?page={i}") for i in range(10)))
        print([r.status_code for r in pages])

asyncio.run(main())
```

- Сессию закрывайте (`with` или `s.close()`): иначе соединения остаются открытыми.
- Одну `Session` можно использовать из нескольких потоков.
- Параметры транспорта (профиль, прокси по умолчанию, `verify`, `http_version`, ...)
  задаются при создании и потом не меняются. На один запрос можно передать `proxy`,
  `timeout`, `headers`, `cookies`, `allow_redirects` и другие — см. [Запросы](docs/requests.md).
- Отмена задачи asyncio отменяет и сетевой запрос; Ctrl+C прерывает синхронный запрос.

Подробно: [Сессии](docs/sessions.md).

## Профили: под кого маскироваться

`client_identifier` выбирает клиента, чей отпечаток воспроизводится: ClientHello, HTTP/2,
HTTP/3 и QUIC, базовые заголовки.

```python
from yumeclient import ALL_IDENTIFIERS, Profiles, Session, find

print(len(ALL_IDENTIFIERS))           # 93
print(find("firefox"))                # ['firefox_102', ..., 'firefox_148']

Session(client_identifier="firefox_148")
Session(client_identifier=Profiles.SAFARI_IOS_18_5)
Session(client_identifier="okhttp4_android_13")   # Android-приложение на okhttp
```

| Нужно | Профиль |
|---|---|
| Десктопный Chrome | `chrome_152` (по умолчанию), `chrome_146`, ... |
| Edge, Brave, Opera | `edge_131`, `brave_146`, `opera_91` |
| Firefox | `firefox_148`, `firefox_147`, ... |
| Safari на Mac / iPhone / iPad | `safari_macos_26_0`, `safari_ios_18_5`, `safari_ipad_15_6` |
| Android-приложение | `okhttp4_android_13`, `okhttp4_conscrypt` |
| Tor Browser | `tor_145` |

`client_os` меняет платформу в заголовках (`User-Agent`, `sec-ch-ua-platform`), не трогая
TLS:

```python
Session(client_identifier="chrome_152", client_os="macos")
Session(client_identifier="chrome_152", client_os="android")
```

Подробно: [Профили](docs/profiles.md) — полный список, что взято из записей браузеров, а что
нет.

## Заголовки

Сессия начинает с заголовков, которые браузер профиля шлёт при открытии страницы, в его
порядке. Их можно дополнять, менять и удалять:

```python
with Session(client_identifier="chrome_152") as s:
    print(s.headers["User-Agent"])                 # регистр имени не важен

    s.headers["Referer"] = "https://example.com/"  # для всех следующих запросов
    s.headers.update({"Accept-Language": "ru-RU,ru;q=0.9"})

    s.get(url, headers={"X-Request-Id": "42"})     # только для этого запроса
    s.get(url, headers={"Accept-Encoding": None})  # None — не отправлять заголовок
    s.get(url, header_order=["X-Request-Id", "User-Agent"])  # эти — первыми

    s.headers = {"User-Agent": "my-bot/1.0"}       # заменить весь набор
```

- Браузерные заголовки по HTTP/1.1 идут в написании браузера (`User-Agent`), по HTTP/2 и
  HTTP/3 — в нижнем регистре, как того требует протокол.
- `User-Agent` сам не добавляется: если вы удалили его из сессии, его не будет.
- Если `Accept-Encoding` не задан, транспорт добавит `gzip, deflate, br`; ответ
  распаковывается автоматически.

Посмотреть базовые заголовки без сессии: `yumeclient.default_headers("firefox_148")`.
Подробно: [Запросы → Заголовки](docs/requests.md#заголовки), [Профили](docs/profiles.md#базовые-заголовки).

## Параметры и тело запроса

```python
s.get(url, params={"q": "text", "tag": ["a", "b"]})       # ?q=text&tag=a&tag=b
s.post(url, json={"name": "yume"})                         # application/json
s.post(url, data={"login": "me", "password": "x"})          # form-urlencoded
s.post(url, data=b"\x00\x01")                               # bytes как есть (octet-stream)
s.post(url, data="raw text", headers={"Content-Type": "text/plain"})
s.post(url, files={"file": ("report.pdf", open("report.pdf", "rb"), "application/pdf")},
       data={"title": "Отчёт"})                             # multipart/form-data
```

`files` принимает те же формы, что `requests`: `bytes`, файловый объект, `(имя, содержимое)`,
`(имя, содержимое, тип)` и `(имя, содержимое, тип, заголовки)`.

Редиректы выполняются автоматически (до 20, как в браузере), с методом как в браузере (POST → GET на
301/302/303, 307/308 сохраняют метод и тело). `allow_redirects=False` возвращает сам 3xx.

Подробно: [Запросы](docs/requests.md).

## Ответ

```python
r = s.get("https://httpbin.org/json")

r.status_code, r.ok           # 200, True (ok — статус 200–399)
r.json()                      # разобранный JSON
r.text                        # строка (кодировка из Content-Type, иначе UTF-8)
r.content                     # bytes
r.headers["Content-Type"]     # ['application/json'] — список значений
r["content-type"]             # 'application/json' — значения через ", ", без учёта регистра
r.url                         # итоговый URL после редиректов
r.history                     # ответы редиректов
r.cookies                     # dict: cookie сессии, которые подходят к итоговому URL
r.elapsed                     # секунды на весь запрос
r.http_version                # '1.1', '2' или '3'
r.raise_for_status()          # HTTPStatusError на 4xx/5xx
```

`r.connection_info` — адреса, переиспользование соединения, версия TLS, шифр и тайминги
этапов. Подробно: [Ответы](docs/responses.md).

## Cookies

Cookie из ответов сохраняются в `s.cookies` и отправляются дальше по правилам браузера
(домен, путь, `Secure`, публичные суффиксы).

```python
import json
from yumeclient import CookieJar, Session

with Session() as s:
    s.get("https://httpbin.org/cookies/set?session=abc")
    print(s.cookies.to_dict())                      # {'session': 'abc'}

    s.cookies.set("consent", "yes", domain="httpbin.org")
    s.get(url, cookies={"preview": "1"})            # только для этого запроса, в jar не попадает

    saved = s.cookies.export()                      # список dict (формат Cookie-Editor)

# в другой сессии или после перезапуска
with Session(cookies=CookieJar(saved)) as s:
    ...
```

Импорт из браузера: экспортируйте cookie расширением Cookie-Editor (JSON) и передайте
список в `CookieJar(...)`. Подробно: [Cookies](docs/cookies.md).

## Таймауты и ошибки

По умолчанию на весь запрос даётся 30 секунд. Можно задать этапы отдельно:

```python
from yumeclient import Session, TimeoutConfig

Session(timeout=10)                                    # 10 с на весь запрос
Session(timeout=(5, 20))                               # 5 с на подключение, 20 с между данными
Session(timeout=TimeoutConfig(total=60, connect=5, read=15))
s.get(url, timeout=120)                                # для одного запроса
```

Ошибки — подклассы `yumeclient.RequestError`. У каждой есть `kind` (машинный код),
`stage`, `url`, `elapsed` и `retryable`:

```python
import yumeclient

try:
    r = s.get(url)
    r.raise_for_status()
except yumeclient.Timeout as e:           # ConnectTimeout, ReadTimeout, WriteTimeout
    print("медленно:", e.stage, e.elapsed)
except yumeclient.ProxyError as e:        # прокси недоступен или отказал
    ...
except yumeclient.ConnectError as e:      # DNS, отказ в соединении, TLS (TLSError)
    ...
except yumeclient.HTTPStatusError as e:   # от raise_for_status()
    print(e.response.status_code)
except yumeclient.RequestError as e:      # всё остальное сетевое
    print(e.kind, e)
```

Ошибки конфигурации (`SessionConfigurationError`) возникают при создании сессии, до
сети. Сама библиотека повторяет запрос, только если он точно не дошёл до сервера (например,
соединение из пула оказалось закрыто); остальные повторы — ваше решение. Пример повтора с
backoff — в [examples/errors_and_retries.py](examples/errors_and_retries.py).
Подробно: [Таймауты, ошибки, отмена](docs/timeouts-and-errors.md).

## Большие ответы: стриминг

```python
with s.get("https://example.com/big.iso", stream=True) as r:
    r.raise_for_status()
    with open("big.iso", "wb") as f:
        for chunk in r.iter_bytes(1 << 20):
            f.write(chunk)
```

В asyncio — `async for chunk in r.aiter_bytes()` и `await r.aread()`. Ограничить размер
ответа (после распаковки): `max_content_size=10_000_000` у сессии или запроса →
`ResponseTooLarge`. Подробно: [Ответы → Стриминг](docs/responses.md).

## Прокси

```python
Session(proxy="http://user:pass@proxy.example:8080")
Session(proxy="socks5://user:pass@127.0.0.1:1080")    # socks5 — и для HTTP/3 (UDP)

s.get(url, proxy="socks5://127.0.0.1:1081")            # другой прокси для одного запроса
s.get(url, proxy="")                                   # без прокси
```

Поддерживаются `http`, `https`, `socks5`, `socks5h`, `socks4`, `socks4a`. Через какой прокси
и за сколько прошло соединение — в `r.connection_info`. Подробно: [Прокси и сеть](docs/proxies.md).

## HTTP/2 и HTTP/3

По умолчанию (`http_version="auto"`) протокол выбирается как в браузере через ALPN:
HTTP/2, если сервер его поддерживает, иначе HTTP/1.1.

```python
Session(http_version="2")     # только HTTP/2; без него — ProtocolError, а не тихий откат
Session(http_version="1.1")   # только HTTP/1.1
Session(http_version="3")     # HTTP/3 (QUIC) в гонке с TCP, как Chrome
```

С `http_version="3"` у 53 профилей (Chrome, Edge, Brave, Opera, Firefox) QUIC-рукопожатие и
HTTP/3 записаны с настоящих браузеров. Через прокси HTTP/3 идёт только через `socks5://`.
Подробно: [Протоколы](docs/protocols.md).

## Проверка отпечатка

Каждый ответ несёт отпечаток того, что реально ушло в сеть:

```python
r = s.get("https://tls.peet.ws/api/all")
print(r.fingerprint["ja4"])                  # t13d1517h2_8daaf6152771_...
print(r.fingerprint["ja3"])
print(r.fingerprint["akamai_fingerprint"])   # HTTP/2
```

Сравнить два клиента — `yumeclient.fingerprint_diff(a, b)`; сохранить настройки клиента —
`s.export_profile()` и `Session.from_profile(...)`; безопасная трасса для баг-репорта —
`r.trace()`. Подробно: [Диагностика](docs/diagnostics.md).

## Свой TLS-отпечаток

Если нужного клиента нет среди профилей, ClientHello можно задать JA3-строкой. Остальное
(алгоритмы подписи, key share, ALPN, HTTP/2) берётся от Chrome или задаётся явно:

```python
JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"

with Session(ja3_string=JA3) as s:
    r = s.get("https://tls.peet.ws/api/all")
```

Все параметры (подписи, key share, ECH, HTTP/2 SETTINGS, порядок псевдозаголовков, ...)
— в [Своём TLS-отпечатке](docs/custom-tls.md); пример Firefox-подобной настройки —
[examples/custom_ja3.py](examples/custom_ja3.py).

## Рецепты

**Ограничить число одновременных запросов в asyncio**

```python
limit = asyncio.Semaphore(10)

async def fetch(s, url):
    async with limit:
        return await s.get(url)
```

По умолчанию у `AsyncSession` пул на 64 одновременных запроса на процесс; больше —
`AsyncSession.configure_executor(workers=256)` до первого запроса.

**Повторить запрос при сетевой ошибке**

```python
for attempt in range(3):
    try:
        r = s.get(url)
        break
    except yumeclient.RequestError as e:
        if not e.retryable or attempt == 2:
            raise
        time.sleep(2 ** attempt)
```

Повторяйте так только идемпотентные запросы (`GET`, `HEAD`, `PUT`, `DELETE`): POST мог
дойти до сервера до ошибки.

**Притвориться Android-приложением**

```python
with Session(client_identifier="okhttp4_android_13") as s:
    r = s.post("https://api.example.com/v1/login",
               json={"user": "me"},
               headers={"User-Agent": "MyApp/5.2.0 (Android 14; Pixel 8)", "X-App-Version": "5.2.0"})
```

Профили okhttp собирают запрос как okhttp 4: без браузерных заголовков, с `Host`,
`Connection: Keep-Alive`, `Accept-Encoding: gzip` и своим `User-Agent`, если вы его не задали.

**Сбросить соединения** (например, после смены сети): `s.reset_connection()`.

**Узнать, что не поддерживается**: [Ограничения](docs/limitations.md).
