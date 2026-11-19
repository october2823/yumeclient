# yumeclient

Синхронный и асинхронный Python-клиент в стиле `requests` поверх
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) v1.16.0.
Python-слой не подменяет TLS-реализацию: каждый запрос уходит через Go-cffi
адаптер (`native/`), который держит uTLS-фингерпринты, HTTP/2/3 и прокси.
Cookie хранятся в `session.cookies` (Python — единственный источник истины):
каждый запрос получает снимок jar'а, Go выбирает cookie по RFC 6265 на каждом
hop'е редиректа и возвращает только то, что сервер выставил или удалил.

## Установка

```sh
python -m pip install yumeclient
```

Готовые wheels (`py3-none`, любой Python ≥ 3.11): Windows x64, Linux x86_64 и
aarch64 (glibc ≥ 2.28), macOS universal2 (11+). Для других платформ — локальная сборка.

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
`timeout`, `proxy`, `allow_redirects`, `header_order`, `host_override`, `stream`,
`max_content_size`.

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
- Исключение — okhttp-профили (`okhttp4_*`, `conscrypt_android_latest`): у okhttp нет
  дефолтных заголовков уровня приложения, сессия стартует с пустого `session.headers`,
  а `Accept-Encoding: gzip` / `User-Agent: okhttp/4.12.0` дописывает сетевой слой на
  их собственных местах (см. «HTTP-слой okhttp»).

## HTTP-слой okhttp (`header_style`)

`header_style="okhttp"` — запросы собираются как у okhttp 4.x (BridgeInterceptor +
`Http1ExchangeCodec`). Для `okhttp4_android_7…13`, `okhttp4_conscrypt`,
`conscrypt_android_latest` включён по умолчанию; для остальных профилей —
`header_style="raw"` (заголовки ровно как переданы + то, что добавит Go-транспорт).

На проводе (HTTP/1.1):

```
POST /v1/api HTTP/1.1
x-app-version: 5.2.0               ← заголовки приложения: как переданы, в порядке добавления
user-agent: MyApp/5.2.0 (Android 14)
Content-Type: application/json     ← запросы с телом; значение — из ваших заголовков
Content-Length: 9                  ← считает транспорт
Host: api.example.com              ← порт только если не 443/80
Connection: Keep-Alive
Accept-Encoding: gzip              ← если вы не задали Accept-Encoding или Range
Cookie: a=1; b=2                   ← из cookie jar сессии
User-Agent: okhttp/4.12.0          ← только если вы не задали свой user-agent
```

- Сверено побайтово с настоящим okhttp 4.12.0 на одном и том же локальном сервере:
  GET/POST/HEAD/PUT, cookie, 302 POST→GET (без тела и без `Referer`), 307 с телом,
  `Range`, заданные приложением `Host`/`Accept-Encoding`/`Connection`.
- `Host`, `Connection`, `Accept-Encoding`, `User-Agent`, заданные вами, остаются на
  вашем месте и в вашем регистре — okhttp дописывает только отсутствующие.
- `Content-Type` для `json=` — `application/json`, для `data=dict` —
  `application/x-www-form-urlencoded` (как `FormBody`); для `data=bytes` неявного
  Content-Type нет (RequestBody без MediaType). Если приложение шлёт
  `application/json; charset=utf-8` (okhttp `String.toRequestBody`) — передайте его явно.
- Keep-alive как у okhttp `ConnectionPool`: соединения переиспользуются, до 5 простаивающих,
  5 минут; `r.fingerprint["connection_reused"]` показывает факт переиспользования.
- Запрос до 8 KiB (заголовки + тело) уходит одной записью: один TLS-record, как
  Conscrypt после flush Okio. Раньше Go-стек отправлял заголовки отдельно, а
  тело резал по ~1.2 KiB (dynamic record sizing).
- HTTP/2: тот же порядок; `Host` → `:authority`, `Connection` выкидывается.
  Профиль `conscrypt_android_latest`/`okhttp4_conscrypt` шлёт h2 как okhttp:
  SETTINGS `4:16777216`, WINDOW_UPDATE `16711681`, псевдо `m,p,a,s`, HEADERS без
  priority, первый stream id 3 (Akamai `4:16777216|16711681|0|m,p,a,s`).
  Известное отличие: Go-кодер h2 режет `cookie` на отдельные поля, okhttp шлёт одно.
- Вернуть прежнее поведение для okhttp-профиля: `header_style="raw"`.

## HTTP/1.1 и ALPN (`http_version`, `keep_alpn`)

Протокол после хендшейка выбирает **сервер** из списка ALPN в ClientHello
(RFC 7301); клиент обязан говорить на выбранном.

| Настройка | ALPN в hello (JA4) | Протокол |
|---|---|---|
| `http_version="auto"` (по умолчанию) | профиль: `h2,http/1.1` (`…h2_…`) | что выбрал сервер — ровно как okhttp |
| `http_version="1.1"` / `force_http1=True` | переписан на `http/1.1` (`…h1_…`) | HTTP/1.1, но hello уже не как у приложения |
| `http_version="1.1", keep_alpn=True` | профиль: `h2,http/1.1` (`…h2_…`) | HTTP/1.1, если сервер выбрал `http/1.1` (или не выбрал ничего); если выбрал `h2` — соединение закрывается сразу после хендшейка, ни одного байта HTTP не отправлено, `RequestError` |

Если с hello приложения сервер отдаёт приложению `http/1.1`, а вам `h2`, то
hello отличается тем, на что смотрит сервер, — клиентская настройка это не
исправит. Проверка: `r.fingerprint["alpn_offered"]` / `["alpn_negotiated"]`;
у эталона — `tshark -o tls.keylog_file:keys.log -Y "tls.handshake.type==8" -T
fields -e tls.handshake.extensions_alpn_str` (EncryptedExtensions TLS 1.3 видны
только с keylog).

## Профили и client_os

```python
from yumeclient import Session, Profiles, ALL_IDENTIFIERS, find

with Session(client_identifier=Profiles.CHROME_152, client_os="android") as s:
    ...
```

- `ALL_IDENTIFIERS` — 83 профиля upstream v1.16.0 + 10 extra-профилей адаптера (итого 93); `Profiles.*` — константы; `find("safari_ios")` — поиск по подстроке.
- Extra-профили (нет в upstream, TLS-стек собран адаптером и проверен по JA4):
  `edge_99` / `edge_101` / `edge_131` / `edge_latest` — Chromium TLS-стек (JA4 идентичен chrome_131) с Edge UA и sec-ch-ua брендом;
  `safari_macos_17_0` / `safari_macos_18_0` / `safari_macos_26_0` — Apple держит ClientHello стабильным с 16 версии (JA4 идентичен safari_16_0), macOS-baseline, client_os по умолчанию macos;
  `tor_145` — TLS-стек Firefox ESR 128 как в Tor Browser 14+ (15 extensions), Tor-стиль UA без te:trailers.
  `conscrypt_android_latest` / `okhttp4_conscrypt` — hello Android-приложения (okhttp поверх платформенного Conscrypt, TLS 1.3): 15 шифров без GREASE в порядке Conscrypt, 13 расширений с padding до 512 байт, groups 29-23-24, key share только X25519, JA3 `f79b6bad2ad0641e1921aef10262856b`, JA4 `t13d1513h2_8daaf6152771_eca864cca44a`; при повторном соединении с TLS 1.3 тикетом — resumption hello с `pre_shared_key` (41) вместо padding (выключается `disable_session_tickets=True`); h2 как okhttp: Akamai `4:16777216|16711681|0|m,p,a,s`, первый stream 3; HTTP-слой okhttp (`header_style`, см. выше). App-заголовки (UA приложения и т.п.) передавайте сами.
- Upstream `okhttp4_android_7` … `_9` — TLS 1.2-only hello старых Android (JA4 `t12d…`); `okhttp4_android_10` … `_13` — тот же Conscrypt TLS 1.3 hello, что и `conscrypt_android_latest` (идентичны с 0.4.6, когда порядок расширений перестал перемешиваться). Для современного Android-приложения — `conscrypt_android_latest` / `okhttp4_conscrypt`.
- `random_tls_extension_order` (по умолчанию `True`) действует только на Chromium-профили (`chrome_*`, `brave_*`, `opera_*`, `edge_*`) — только Chromium перемешивает расширения. Остальные стеки (Conscrypt/okhttp, Safari/CFNetwork, Firefox/Tor, мобильные приложения) всегда шлют свой фиксированный порядок.
- `client_os` принимает `"windows"`, `"android"`, `"ios"`, `"macos"` и меняет **только baseline заголовков** (UA, client hints), не сам TLS-фингерпринт.
- По умолчанию OS выводится из профиля: `*_ios_* → ios`, `*_android_* → android`, desktop-safari → `macos`, остальное → `windows`.
- Chrome-на-iOS — это CriOS без client hints (как в реальном браузере); okhttp/zalando/nike/mesh/confirmed/mobile-профили получают app-подобные наборы.
- Неизвестный профиль или OS → `SessionConfigurationError` с подсказкой похожих вариантов.

## Таймауты

```python
from yumeclient import Session, TimeoutConfig

Session(timeout=30)                                   # total: весь обмен (по умолчанию 30 с)
Session(timeout=(5, 30))                              # (connect, read), без total
Session(timeout=TimeoutConfig(connect=5, read=30, total=120, write=10))
s.get(url, timeout=3)                                 # переопределение для одного запроса
Session(timeout=None)                                 # без лимитов
```

- `connect` — DNS + прокси (CONNECT/SOCKS) + TCP + TLS каждого хопа, включая редиректы;
- `write` — отправка заголовков и тела запроса;
- `read` — ожидание заголовков ответа и максимальная пауза между кусками тела
  (медленный, но «живой» ответ не обрывается);
- `total` — весь обмен. При `stream=True` — до получения заголовков; тело дальше
  ограничено `read` (если `read` не задан — значением `total` как паузой).

Для HTTP/3 (racing, `http_version="3"`) стадии connect/write/read-заголовков не
отслеживаются (quic-go их не сообщает) — работают `total` и пауза чтения тела.

## Ошибки

Все ошибки запроса — подклассы `RequestError` с атрибутами `kind`, `stage`
(`connect`/`write`/`read`/`body`), `method`, `url` (без логина/пароля), `elapsed`,
`request_id`, `retryable`, `detail`; исходный текст Go — в `__cause__`.

| класс | `kind` | когда |
|---|---|---|
| `ConnectError` (`ConnectionError`) | `connect`, `dns` | соединение отклонено, хост не найден |
| `ProxyError` (`ConnectError`) | `proxy` | прокси недоступен, CONNECT/SOCKS/авторизация |
| `TLSError` (`ConnectError`) | `tls` | рукопожатие, сертификат |
| `ConnectionClosed` (`ConnectionError`) | `connection_closed` | соединение закрыто/сброшено после установки |
| `Timeout` (`TimeoutError`) | `timeout` | истёк `total` |
| `ConnectTimeout` (`Timeout`, `ConnectError`) | `connect_timeout` | истёк `connect` |
| `ReadTimeout` (`Timeout`) | `read_timeout` | истёк `read` (stage `read` или `body`) |
| `WriteTimeout` (`Timeout`) | `write_timeout` | истёк `write` |
| `RequestCancelled` | `cancelled` | запрос отменён (закрытие сессии) |
| `ResponseTooLarge` | `body_too_large` | тело больше `max_content_size` |
| `InvalidRequestError` (`ValueError`) | `invalid_request`, `configuration` | URL/метод/конфигурация отклонены до сети |
| `StreamClosed` | `stream_closed` | поток уже прочитан или закрыт |
| `HTTPStatusError` | `http_status` | `raise_for_status()`; ответ в `.response` |

```python
from yumeclient import ConnectTimeout, ProxyError, ReadTimeout, RequestError

try:
    r = s.get(url, timeout=TimeoutConfig(connect=5, read=20))
except (ConnectTimeout, ProxyError) as e:
    print("сменить прокси:", e.kind, e.url)
except ReadTimeout as e:
    print("сервер молчит на стадии", e.stage)
except RequestError as e:
    if e.retryable: ...
```

## Стриминг и отмена

```python
with s.get(url, stream=True) as r:           # тело не буферизуется
    for chunk in r.iter_bytes(256 * 1024):   # память ограничена размером куска
        f.write(chunk)

async with await a.get(url, stream=True) as r:
    async for chunk in r.aiter_bytes():
        ...

r = s.get(url, stream=True); body = r.read()          # дочитать в r.content
r = await a.get(url, stream=True); body = await r.aread()
```

- Выход из цикла, `close()`/`aclose()`, `with`, закрытие сессии и сборка мусора
  освобождают нативный поток. У sync-стрима `r.content` дочитывает тело; у async —
  нужен `await r.aread()`.
- Отмена задачи (`asyncio.wait_for`, `task.cancel()`, `TaskGroup`) обрывает запрос
  в Go сразу — и во время соединения, и при чтении тела.
- `session.close(grace=5.0)` даёт запросам в полёте `grace` секунд, затем отменяет
  их (`RequestCancelled`); `close(grace=None)` — ждать до конца.
- `max_content_size=...` (сессия или запрос) — лимит распакованного тела в байтах.

## Cookies

`session.cookies` — `CookieJar` с идентичностью `(name, domain, path)` и
семантикой RFC 6265: на каждом хопе (включая редиректы) уходят только cookie,
подходящие по домену (host-only — ровно этот хост, `Domain=` — и поддомены),
по пути (длинный путь первым) и по Secure (только https), не истёкшие:

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
наивного `resp.cookies`); удаление сервером (`Max-Age=0`, прошедший `Expires`)
убирает cookie из jar. Удалённая в Python cookie больше не отправляется.
Куки без expires живут до конца сессии; с `expires` — до истечения.

- `s.cookies.for_url(url)` / `s.cookies.to_dict(url=url)` — что уйдёт на этот URL.
- Cookie без домена (`s.cookies["k"] = "v"`) уходит на любой хост (как в requests),
  но не перекрывает одноимённую cookie, привязанную к хосту/домену.
- Сервер не может выставить cookie чужому домену; Secure-cookie, полученная по
  `http://`, сохраняется, но уходит только по https.

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

`str`-содержимое уходит UTF-8; имена/файлы с `"`, CR, LF процент-экранируются как у браузеров и urllib3. Boundary — Chrome-подобная `----WebKitFormBoundary` + 16 hex. Кодировщик живёт отдельным файлом `yumeclient/multipart.py` (`encode_multipart(data, files, boundary=None)`, `choose_boundary()`) — его можно править, не трогая ядро.

## Ответ

`Response`: `status_code` / `status`, `headers` (dict[str, list[str]]),
`cookies`, `content`, `text`, `encoding`, `url`, `elapsed`, `history`,
`used_protocol`, `http_version` ("1.1"/"2"/"3"), `ok`, `json()`,
`raise_for_status()` (→ `HTTPStatusError`), `r["Content-Type"]` — регистронезависимо,
`request_id`, `connection_info`, стрим-методы (см. «Стриминг и отмена»).

`r.connection_info`:

```python
{"connection_reused": False, "alpn_negotiated": "h2", "tls_version": "1.3",
 "tls_resumed": False, "http_protocol": "HTTP/2.0",
 "remote_address": "203.0.113.5:443", "local_address": "192.168.1.10:51123",
 "timings": {"redirects": 0.0, "connect": 0.081, "write": 0.0002, "wait": 0.064,
             "body": 0.003, "first_byte": 0.145, "total": 0.148}}
```

Тайминги относятся к последнему хопу; `redirects` — всё время до него; фазы в сумме
дают `total`. Через прокси `remote_address` — адрес прокси.

## Fingerprint

`r.fingerprint` / `session.last_fingerprint` (запрашивается автоматически):

- `ja3`, `ja3_hash_md5`, `ja4`, `ja4_r`, `tls_extensions`, `client_hello_len` —
  посчитаны из **фактического ClientHello на проводе** (байты, ушедшие в сокет,
  для host:port этого ответа), `source == "wire"`. Совпадают с tshark/Wireshark
  (`tls.handshake.ja3`, `tls.handshake.ja4`).
- `config_ja3_hash_md5`, `config_ja4` — что сконфигурировано у сессии. Если они
  отличаются от wire-значений — сессия шлёт не то, что вы ожидаете.
- `akamai_fingerprint` — из конфигурации HTTP/2 (SETTINGS / WINDOW_UPDATE / порядок псевдо-заголовков).
- `source == "config"` — провода нет (HTTP/3 racing через прокси, `udp_proxy`
  поверх http-прокси): значения посчитаны из конфигурации.
- `alpn_offered` — список ALPN из hello; `alpn_negotiated` — что выбрал сервер
  (`""` — сервер ALPN не прислал); `tls_version`, `tls_resumed`;
  `http_protocol` (`HTTP/1.1`/`HTTP/2.0`); `connection_reused` — запрос ушёл по
  keep-alive соединению.
- `request_headers` — `[[имя, значение], ...]` ровно в том порядке и регистре, в
  каком транспорт записал их в соединение (h2 — список полей HPACK с псевдо-заголовками).
  Для редиректов — последний хоп.

`force_http1=True` переписывает ALPN в ClientHello на `http/1.1` (JA4 `…h1_…`),
то есть меняет фингерпринт — для точной копии приложения, которое предлагает
`h2,http/1.1`, используйте `keep_alpn=True` (см. «HTTP/1.1 и ALPN»).

## Транспортные параметры сессии

`client_identifier`, `client_os`, `random_tls_extension_order=True`,
`http_version` (`"auto"`/`"1.1"`/`"2"`/`"3"` или числа/`"h2"`/`"h3"`),
`proxy` (`http(s)://`, `socks5://`; для HTTP/3 — только socks5),
`timeout`, `verify`, `force_http1`, `keep_alpn`, `header_style` (`"okhttp"`/`"raw"`),
`disable_http3`, `disable_session_tickets`,
`server_name_overwrite`, `local_address`, `header_order`, `headers`, `cookies`,
полный набор custom-JA3 полей (`ja3_string`, `h2_settings`, `pseudo_header_order`, ... —
только вместе с `ja3_string`).

Транспортные атрибуты можно менять между запросами — сессия пересоздаст
Go-клиент. `await session.reset_connection()` (или `session.reset_connection()`
для sync) пересоздаёт соединение принудительно. Смена `proxy` между запросами
поддержана; `proxy=` отдельного запроса идёт через отдельную нативную сессию
(свой пул соединений), а не через прокси сессии. `timeout` применяется к каждому
запросу и Go-клиент не пересоздаёт.

## Multipart

Mapping или последовательность пар принимаются для полей/файлов. Последовательности сохраняют порядок частей. Кодировщик создаёт CRLF-разделители и Chrome-подобную границу `----WebKitFormBoundary` плюс 16 hex-символов. Функция `encode_multipart` доступна для отдельного использования.

## Ограничения

Upstream CFFI не отдаёт redirect history, поэтому `history` пока пуст. Автодополнение custom JA3 из Chrome defaults не реализовано — передавайте поддерживаемые поля через схему upstream. Для некоторых профилей нет браузерно-точных HTTP/3 настроек; при запросе HTTP/3 используются параметры upstream по умолчанию. Публикация выполняется только после успешных CI-сборок и настройки Trusted Publishing в PyPI.

## Примеры и тесты

Папка `examples/` — runnable-сценарии: `basic_requests.py` (синтаксис),
`profiles_and_os.py` (профили/OS), `cookies_flow.py` (куки). Тесты — `python -m pytest tests -q`; сетевые проверки добавляются флагом `--run-online`.
