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
aarch64 (manylinux2014: glibc ≥ 2.17 — CI запускает wheel в образе manylinux2014),
macOS universal2 (11+). Для других платформ — локальная сборка.

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

- Заголовки регистронезависимы: `s.headers["accept"]` и `s.headers["Accept"]` — один ключ;
  так же работают `in`, `get`, `pop`, `del`.
- Удалённый заголовок не уходит вовсе: без `User-Agent` запрос идёт без него
  (сетевой слой Go не подставляет `Go-http-client/1.1` / `/2.0` — ни по HTTP/1.1, ни по
  HTTP/2, ни при гонке HTTP/3); okhttp-профили по-прежнему дописывают
  `User-Agent: okhttp/4.12.0`, как сам okhttp (убрать — `{"User-Agent": None}` в запросе).
- `None` удаляет заголовок, как в requests: `s.get(url, headers={"User-Agent": None})` —
  запрос без `User-Agent` (сессионный остаётся для других запросов). Работает и для
  полей, которые иначе добавил бы сетевой слой: `Accept-Encoding`, `priority` (ниже),
  умолчания `okhttp`-стиля (`User-Agent`, `Connection`, `Accept-Encoding`). Как и в
  requests, `Content-Type` от `json=`/`files=`/`data=`-словаря всё равно ставится
  (а `application/octet-stream` для `data=bytes` — умолчание yumeclient — убирается),
  `{"Cookie": None}` убирает только ваш заголовок (cookies из jar уходят), `Host` и
  `Content-Length` уходят всегда, недопустимое имя с `None` игнорируется.
- Имя заголовка должно быть токеном RFC 9110, значение — без управляющих символов
  (табуляция и не-ASCII допустимы); иначе `InvalidRequestError` до отправки. По HTTP/2
  нельзя передать `Connection` (кроме `close`/`keep-alive`), `Upgrade` и
  `Transfer-Encoding` (кроме `chunked`) — тоже `InvalidRequestError`, соединение остаётся.
- Chromium-профили (`chrome_144`+, `brave_146`, custom JA3 с Chrome-заполнением) по
  HTTP/2 и HTTP/3 отправляют последним `priority: u=0, i`, как Chrome; по HTTP/1.1 —
  нет. Свой `Priority` в сессии или запросе заменяет его, `{"priority": None}` убирает.
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
                                     (Connection / Accept-Encoding / User-Agent: None — не уходят)
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

## Протокол: `http_version`, ALPN, `keep_alpn`

`http_version` — пресет протокола: он согласованно задаёт ALPN в ClientHello,
принудительный HTTP/1.1 и HTTP/3. Протокол после хендшейка выбирает **сервер**
из списка ALPN (RFC 7301); явно заданную версию библиотека молча не понижает.

| Настройка | ALPN в hello (JA4) | Протокол |
|---|---|---|
| `http_version="auto"` (по умолчанию) | профиль: `h2,http/1.1` (`…h2_…`) | что выбрал сервер — ровно как okhttp |
| `http_version="2"` | профиль | только HTTP/2: если сервер выбрал `http/1.1` (или не прислал ALPN), соединение закрывается сразу после хендшейка, запрос не отправлен, `ProtocolError` |
| `http_version="1.1"` / `force_http1=True` | переписан на `http/1.1` (`…h1_…`) | HTTP/1.1, но hello уже не как у приложения |
| `http_version="1.1", keep_alpn=True` | профиль: `h2,http/1.1` (`…h2_…`) | HTTP/1.1, если сервер выбрал `http/1.1` (или не выбрал ничего); если выбрал `h2` — соединение закрывается сразу после хендшейка, ни одного байта HTTP не отправлено, `ProtocolError` |
| `http_version="3"` | профиль + QUIC | гонка соединений HTTP/3 и TCP (TCP — через 300 мс или сразу после неудачи QUIC); запрос уходит один раз — по протоколу, первым установившему соединение (или по уже открытому), выигравший запоминается для хоста. После ошибки запомненного протокола (у HTTP/3 — и после таймаута/отмены: молчащий UDP) следующие запросы снова устраивают гонку на новых соединениях; таймаут или отмена HTTP/1.1/HTTP/2 протокол и пул сохраняют. Сам запрос повторяется гонкой, если он идемпотентный (GET/HEAD/OPTIONS/TRACE или с `Idempotency-Key`) и время ещё есть, или если не был отправлен |

`http://` — всегда HTTP/1.1 при любом `http_version` (ALPN есть только у TLS, h2c
не поддерживается).

Противоречивые настройки отклоняются в конструкторе `SessionConfigurationError`,
до любого обращения к сети:

- `force_http1=True` вместе с `http_version="2"` или `"3"`; `disable_http3=True` с `"3"`;
- `keep_alpn=True` без `http_version="1.1"`, с `udp_proxy` или с `alpn_protocols` без `http/1.1`;
- `alpn_protocols` (custom JA3) вместе с принудительным HTTP/1.1, если список не
  `["http/1.1"]`: hello предложил бы `http/1.1` вместо вашего списка (сохранить список —
  `keep_alpn=True`); `http_version="2"` с `alpn_protocols` без `h2`;
- `http_version="3"` с прокси не `socks5://`.

`r.used_protocol` и `r.connection_info["http_protocol"]` всегда совпадают;
`connection_info["alpn_negotiated"]` — что выбрал сервер.

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
- HTTP/3-параметры (SETTINGS, порядок псевдозаголовков, приоритет): `chrome_144`–`chrome_152`
  (+`_PSK`), `brave_146`, `firefox_147`/`148`. У `chrome_146`–`152` и `brave_146` upstream их
  не задаёт — берутся параметры `chrome_144`: на проводе они совпадают с Chrome 157
  (`tests/fixtures/chrome_157_wire.json`). Для остальных профилей `http_version="3"`
  предупреждает и использует значения quic-go.
- `cloudscraper` (только CBC-шифры TLS 1.2 + encrypt_then_mac) работает и с серверами
  на OpenSSL: encrypt_then_mac (RFC 7366) реализован, а не только объявлен.

### Custom JA3 (`ja3_string`)

JA3 задаёт версию, шифры, порядок расширений, группы и форматы точек — но не
содержимое расширений и не HTTP/2 / HTTP/3. Остальное:

- явные параметры: `supported_signature_algorithms`, `supported_versions`,
  `key_share_curves`, `alpn_protocols`, `alps_protocols`, `cert_compression_algos`,
  `h2_settings`, `h2_settings_order`, `connection_flow`, `pseudo_header_order`,
  `priority_frames`, `header_priority` — всегда важнее заполнения;
- `fill_custom_with_chrome_defaults=True` (по умолчанию) — не заданное явно берётся из
  `Profiles.LATEST_CHROME` (`chrome_152`): signature algorithms, версии, key shares
  (Chrome-овские, но только для групп из JA3), ALPN/ALPS, сжатие сертификатов, ECH GREASE, HTTP/2 SETTINGS,
  WINDOW_UPDATE, приоритет HEADERS, порядок псевдозаголовков, HTTP/3-параметры,
  `priority`-заголовок;
- `fill_custom_with_chrome_defaults=False` — общие значения: TLS 1.3/1.2, sigalgs
  `0403,0804,0805,0806,0401,0501,0601`, ALPN `h2,http/1.1`, HTTP/2
  `1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`, HTTP/3 — quic-go;
- расширение 27 без `cert_compression_algos` → brotli, 28 (record_size_limit) → 16385;
- key shares без `key_share_curves` (и без подходящих Chrome-овских) — для первых двух групп
  JA3 плюс X25519, если она объявлена дальше; только для объявленных групп. Гибрид
  `X25519MLKEM768` получает share только вместе с X25519 (как у Chrome).

Списки принимают имена upstream (`"X25519MLKEM768"`, `"1.3"`, `"brotli"`) или числовые id
(int, десятичная или `0x`-строка); GREASE-значения → `GREASE`. Неизвестное значение —
`SessionConfigurationError` (upstream молча выбрасывал его из hello).

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
| `ProtocolError` (`ConnectError`) | `protocol` | сервер выбрал не тот протокол (`http_version="2"` → HTTP/1.1, `keep_alpn` → h2); запрос не отправлен |
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
- Ctrl+C прерывает sync-запрос и чтение sync-стрима сразу (`KeyboardInterrupt`),
  нативный запрос при этом отменяется и соединение закрывается. Раньше прерывание
  срабатывало только после прихода ответа.

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
- Сервер не может выставить cookie чужому домену или публичному суффиксу
  (`Domain=com`, `co.uk`, `github.io`; список Mozilla PSL, как в браузерах): такая
  cookie отбрасывается, а на самом суффикс-хосте становится host-only. `Domain=` на
  IP-адресе — тоже host-only.
- Secure-cookie, полученная по `http://`, сохраняется, но уходит только по https.

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
`cookies`, `content`, `text`, `encoding`, `url`, `elapsed`, `history`, `is_redirect`,
`used_protocol`, `http_version` ("1.1"/"2"/"3"), `ok`, `json()`,
`raise_for_status()` (→ `HTTPStatusError`), `r["Content-Type"]` — регистронезависимо,
`request_id`, `connection_info`, стрим-методы (см. «Стриминг и отмена»).

`r.history` — ответы пройденных редиректов, от первого к последнему (как в requests):
`status_code`, `headers`, `cookies` (Set-Cookie этого ответа), `url`, `used_protocol`,
`elapsed` (этот переход: от отправки до заголовков ответа, как в requests), `content`
(тело распаковано). Тело редиректа читается, только пока идёт: больше 64 KiB, пауза
дольше 0.5 с (или read-таймаута, если он меньше), чтение дольше 2 с или тело, которое не
распаковывается, дают `b""` — редирект при этом выполняется.
При `allow_redirects=False` или без редиректов — `[]`.

`r.connection_info`:

```python
{"connection_reused": False, "alpn_negotiated": "h2", "tls_version": "1.3",
 "tls_cipher": "TLS_AES_128_GCM_SHA256", "tls_resumed": False, "http_protocol": "HTTP/2.0",
 "remote_address": "203.0.113.5:443", "local_address": "192.168.1.10:51123",
 "timings": {"redirects": 0.0, "connect": 0.081, "proxy": None, "write": 0.0002,
             "wait": 0.064, "body": 0.003, "first_byte": 0.145, "total": 0.148}}
```

Тайминги относятся к последнему хопу; `redirects` — всё время до него; фазы
`redirects + connect + write + wait + body` в сумме дают `total`. `proxy` — часть
`connect`, ушедшая на путь через прокси (TCP до прокси + CONNECT/SOCKS); `None`, если
соединение переиспользовано или прокси нет. Через прокси `remote_address` — адрес прокси.

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
`h2,http/1.1`, используйте `keep_alpn=True` (см. «Протокол: `http_version`, ALPN, `keep_alpn`»).

## Транспортные параметры сессии

`client_identifier`, `client_os`, `random_tls_extension_order=True`,
`http_version` (`"auto"`/`"1.1"`/`"2"`/`"3"` или числа/`"h2"`/`"h3"`),
`proxy` (`http(s)://`, `socks5://`; для HTTP/3 — только socks5),
`timeout`, `verify`, `force_http1`, `keep_alpn`, `header_style` (`"okhttp"`/`"raw"`),
`disable_http3`, `disable_session_tickets`,
`server_name_overwrite`, `local_address`, `header_order`, `headers`, `cookies`,
полный набор custom-JA3 полей (`ja3_string`, `h2_settings`, `pseudo_header_order`, ... —
только вместе с `ja3_string`).

Транспортные параметры фиксированы на всё время жизни сессии: присваивание
(`s.proxy = ...`, `s.http_version = ...`) — `AttributeError` (раньше оно молча
игнорировалось). Для другой конфигурации создайте новую сессию
(`Session.from_profile(s.export_profile(), proxy=...)` переносит идентичность).
Можно менять `s.headers` (и содержимое `s.cookies`).

На отдельный запрос задаются `proxy=`, `timeout=`, `headers=`, `cookies=`,
`header_order=`, `allow_redirects=`, `stream=`, `max_content_size=`, `host_override=`.
`proxy=` запроса идёт через отдельную нативную сессию (свой пул соединений), а не
через прокси сессии. `await session.reset_connection()` (или
`session.reset_connection()` для sync) пересоздаёт соединения принудительно.

## Диагностика: профили, сравнение, трейсы

```python
import json
from yumeclient import Session, fingerprint_diff

s = Session(client_identifier="chrome_146", http_version="2")
r = s.get(url)
profile = s.export_profile()                 # JSON-safe, версионированный
json.dump(profile, open("profile.json", "w"))

s2 = Session.from_profile(json.load(open("profile.json")), proxy="socks5://...")
r2 = s2.get(url)
fingerprint_diff(profile, r2)    # [] - тот же отпечаток; иначе список отличий
print(json.dumps(r2.trace(), indent=1))      # редактированный трейс запроса
```

- `export_profile()` — `{"format": "yumeclient.profile", "version": 1, "transport": {...},
  "headers": [[имя, значение], ...], "fingerprint": {...}}`: профиль, OS, header style,
  `http_version` и все явно заданные параметры ClientHello/HTTP/2, дефолтные заголовки
  в порядке провода, последний наблюдённый отпечаток (`ja3`, `ja4`, `ja4_r`, Akamai,
  ALPN, расширения, порядок заголовков). Прокси, таймауты, cookies, `verify`, CA и
  локальный адрес **не** экспортируются. Байтовые поля — base64. Дефолтные заголовки
  с учётными данными (`Authorization`, `Cookie`, имена с `token`/`secret`/`auth`/`key`/...)
  тоже не попадают в профиль: их имена перечислены в `omitted_headers`, при
  восстановлении задайте их заново; `export_profile(include_secrets=True)` — экспорт
  со значениями. В `header_order` не учитываются заголовки, которые зависят от запроса
  (`Cookie`, `Content-Length`, `Content-Type`, `Authorization`, `Referer`, `Origin`,
  `Range`, условные).
- `Session.from_profile(profile, **overrides)` / `AsyncSession.from_profile(...)` —
  сессия из профиля; заголовки восстанавливаются точно (порядок, удалённые). Документ
  другого формата, более новой версии или с неизвестным параметром —
  `SessionConfigurationError`.
- `fingerprint_diff(expected, actual)` — принимает `Response`, профиль или dict
  отпечатка; проверяются поля, которые есть в `expected`. Каждое отличие —
  `{"field", "kind", "expected", "actual"}`, `kind`: `value`, `missing`, `order` (те же
  элементы в другом порядке, например случайный порядок расширений Chrome) или `set`
  (+ `missing` / `unexpected`). GREASE игнорируется, JA3 сравнивается по компонентам
  (`ja3.ciphers`, `ja3.extensions`, `ja3.groups`, ...).
- `r.trace(redact=(), values=True, redact_query=True)` — `{"format": "yumeclient.trace", ...}`:
  метод, URL без логина/пароля и фрагмента, со скрытыми значениями query (часть query
  без `=` скрывается целиком; то же в `Location`, `Content-Location`, `Referer`,
  `Origin`, `Link`, `Refresh`; путь URL не меняется), заголовки запроса в
  порядке провода, протокол, ALPN, TLS-версия/шифр, тайминги, JA3/JA4/Akamai, длина и
  SHA-256 тел (тело запроса больше 8 MiB — только длина). Значения `Authorization`,
  `Cookie`, `Set-Cookie` и заголовков с `token`/`secret`/`session`/`auth`/`key`/`password`
  в имени (и из `redact=`) заменены на `"[redacted]"`; `values=False` убирает все значения.
  SHA-256 короткого тела с секретом можно подобрать перебором — учитывайте при отправке.
- `tests/fixtures/profiles.json` — эталонный ClientHello каждого профиля (JA3/JA4/JA4_r,
  ALPN, порядок расширений, Akamai, порядок заголовков); тест
  `tests/test_profile_fixtures.py` сверяет с ним текущую сборку.
  `python scripts/profile_fixtures.py` показывает отличия, `--update` перезаписывает.

## Multipart

Mapping или последовательность пар принимаются для полей/файлов. Последовательности сохраняют порядок частей. Кодировщик создаёт CRLF-разделители и Chrome-подобную границу `----WebKitFormBoundary` плюс 16 hex-символов. Функция `encode_multipart` доступна для отдельного использования.

## Ограничения

- `http://` — всегда HTTP/1.1 (h2c не поддерживается).
- HTTP/3 (гонка): стадийные таймауты connect/write/read-заголовков не отслеживаются
  (quic-go их не сообщает) — работают `total` и пауза чтения тела.
- HTTP/3-параметры есть не у всех профилей (см. «Профили и client_os»).
- HTTP/1.1/HTTP/2-соединение, молча пропавшее (NAT, смена сети — без RST), замечает
  только ядро: до этого запросы по нему кончаются таймаутом, а таймаут соединение не
  сбрасывает (периодический PING по простою, как Go `ReadIdleTimeout`, не включён: он
  заметен серверу и не похож на браузер).
  Помогает `session.reset_connection()`.
- Custom JA3 с группой `X25519MLKEM768` без key share для неё (в том числе без X25519
  в JA3 — тогда share для гибрида не отправляется): если сервер выбирает её через
  HelloRetryRequest, рукопожатие падает (utls, как и Go, не поддерживает ML-KEM в HRR).
  Chrome всегда объявляет X25519 и отправляет key share для ML-KEM — так и задавайте.

Сетевой стек — upstream-модули `fhttp`, `tls-client`, `utls` с правками
(`native/third_party`, изменения — `native/third_party/patches/*.patch`; CI сверяет копии с
upstream и проверяет, что в них нет других файлов: `python scripts/third_party.py check`).

## Примеры и тесты

Папка `examples/` — runnable-сценарии: `basic_requests.py` (синтаксис),
`profiles_and_os.py` (профили/OS), `cookies_flow.py` (куки). Тесты — `python -m pytest tests -q`; сетевые проверки добавляются флагом `--run-online`.
