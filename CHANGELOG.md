# CHANGELOG

Все заметные изменения проекта документируются в этом файле.
Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [0.5.0] — 2026-11-20

### Added
- **Стриминг ответа.** `request(..., stream=True)` (и `await` в `AsyncSession`): тело
  остаётся в нативном слое и читается кусками прямо в буфер Python, без base64/JSON —
  `iter_bytes(chunk_size)`, `iter_content()`, `read()`, `close()`, `with`-блок;
  async: `aiter_bytes()`, `aread()`, `aclose()`, `async with`. Ответ 64 MiB читается
  с пиком памяти Python < 8 MiB. Ранний выход из цикла, `close()`, закрытие сессии и
  сборка мусора освобождают нативный поток. `is_stream_consumed`.
- **Нативная отмена.** У каждого запроса есть `request_id`; отмена asyncio-задачи
  (`wait_for`, `TaskGroup`, `task.cancel()`) обрывает запрос в Go на любой стадии
  (DNS/прокси/TCP/TLS, ожидание заголовков, чтение тела) и возвращает управление
  < 0.5 с вместо ожидания ответа. Поздний результат отменённого запроса не трогает jar.
- **Раздельные таймауты** — `TimeoutConfig(total, connect, read, write)`; `timeout=`
  принимает число (total), кортеж `(connect, read)`, `TimeoutConfig` или `None`.
  `connect` — DNS + прокси + TCP + TLS каждого хопа, `read` — ожидание заголовков и
  пауза между кусками тела, `write` — отправка запроса.
- **Структурированные ошибки** (все — подклассы `RequestError`, атрибуты `kind`, `stage`,
  `method`, `url`, `elapsed`, `request_id`, `retryable`, `detail`): `ConnectError`
  (+ `ProxyError`, `TLSError`), `ConnectionClosed`, `Timeout` (+ `ConnectTimeout`,
  `ReadTimeout`, `WriteTimeout`), `RequestCancelled`, `ResponseTooLarge`, `StreamClosed`,
  `InvalidRequestError`, `HTTPStatusError` (из `raise_for_status()`, ответ в `.response`).
  `Timeout` — ещё и `TimeoutError`, `ConnectError`/`ConnectionClosed` — `ConnectionError`.
  Логины/пароли из URL и Basic/Bearer-токены вырезаются из текста ошибок.
- **`response.connection_info`**: переиспользование соединения, ALPN, версия TLS,
  resumption, адреса сокета, тайминги фаз последнего хопа (`connect`, `write`, `wait`,
  `body`, `redirects`, `first_byte`, `total`; фазы в сумме дают `total`).
- **`max_content_size`** (сессия или запрос): лимит распакованного тела, иначе `ResponseTooLarge`.
- **`close(grace=5.0)`** у `Session`/`AsyncSession`: запросы в полёте получают `grace`
  секунд, затем отменяются; открытые потоки закрываются.
- **`CookieJar.for_url(url)`**, `to_dict(url=...)`, флаг `host_only` (`hostOnly` в
  `export()`/импорте).
- **Wheels:** `py3-none` — один wheel на платформу для любого Python ≥ 3.11
  (вместо cp311…cp314): Windows x64, Linux x86_64 и **aarch64** (manylinux_2_28),
  macOS **universal2** (arm64 + x86_64, macOS 11+). Релиз публикуется только после
  проверки содержимого каждого wheel и smoke-теста установленного wheel на
  Linux/Windows/macOS (arm64 и Intel) × Python 3.11–3.14.

### Fixed
- **Отмена `AsyncSession` ждала нативный запрос** (`wait_for(..., 0.1)` возвращался через
  1.5 с — вместе с медленным ответом).
- **`http://` игнорировал таймаут сессии** (жёсткие 30 с): `Session(timeout=1)` ждал ответа 3 с.
- **`timeout=` отдельного запроса игнорировался**, если Go-сессия уже существовала
  (таймаут фиксировался при создании клиента).
- **`proxy=` отдельного запроса игнорировался** после первого запроса сессии: запрос шёл
  через прокси сессии или **напрямую**. Теперь для другого прокси используется отдельная
  нативная сессия.
- **Cookie: области видимости.** Cookie выбираются по RFC 6265 на каждом хопе: domain /
  host-only, path (длинный путь первым), Secure — только по https, срок действия.
  Раньше jar tls-client отдавал все cookie «домена из двух меток» без учёта Path/Secure
  (Secure-cookie с https://a.example.com уходила на http://b.example.com, cookie с
  `Path=/admin` — на `/public`), сервер мог выставить cookie чужому домену, одноимённые
  cookie с разными path затирали друг друга.
- **Cookie, удалённая в Python** (`session.cookies.remove(...)`), продолжала отправляться и
  возвращалась в jar: Go-jar сессии жил отдельно. Теперь `session.cookies` — единственный
  источник истины: каждый запрос получает свой jar из снимка, обратно приходят только
  изменения (`Set-Cookie`, удаление через `Max-Age=0`/прошедший `Expires`). Параллельные
  запросы одной сессии больше не затирают cookie друг друга.
- **Wheels:** в Windows-wheel лежал второй PE-образ под именем `yumeclient.so`;
  macOS-wheel содержал только arm64 с `minos 26.0` (не ставился на macOS < 26 и Intel).

### Changed
- `timeout=0` / отрицательный → `SessionConfigurationError` (раньше 0 значил «30 с»).
- Текст ошибок дополнен `[METHOD url]`; исключения таймаутов/соединения наследуют
  `OSError` (через `TimeoutError`/`ConnectionError`).
- `close()` отменяет запросы в полёте через `grace` секунд (раньше ждал без ограничения;
  прежнее поведение — `close(grace=None)`).
- `Response` — обычный класс со `__slots__` (не dataclass); позиционный конструктор прежний.
- Смена `timeout` больше не пересоздаёт Go-сессию; ошибка невалидного запроса (URL/метод)
  больше не сбрасывает её соединения.
- Cookie без домена (`jar["k"] = "v"`) по-прежнему уходят на любой хост (как в requests),
  но не перекрывают одноимённую cookie, привязанную к хосту/домену.
- Secure-cookie, выставленная по `http://`, сохраняется, но отправляется только по https.

## [0.4.7] — 2026-11-17

### Added
- **HTTP-слой okhttp 4.x (`header_style="okhttp"`)** — по умолчанию для
  `okhttp4_android_7…13`, `okhttp4_conscrypt`, `conscrypt_android_latest`. Каждый
  запрос (включая redirect-хопы) собирается как у BridgeInterceptor +
  Http1ExchangeCodec: заголовки приложения как переданы → `Content-Type` →
  `Content-Length` → `Host` (без порта по умолчанию) → `Connection: Keep-Alive` →
  `Accept-Encoding: gzip` → `Cookie` (из jar) → `User-Agent: okhttp/4.12.0` (если
  приложение не задало свой). Заданные приложением Host/Connection/Accept-Encoding/
  User-Agent остаются на своём месте; при `Range` нет `Accept-Encoding`; 302/303 →
  GET без body-заголовков и без `Referer`. Сверено побайтово с настоящим okhttp
  4.12.0 (13 запросов, один и тот же сервер): идентично.
  Пул как у okhttp `ConnectionPool`: keep-alive, 5 простаивающих соединений, 5 минут.
  Запрос до 8 KiB уходит одной записью, одним TLS-record (как Conscrypt после flush
  Okio): без отдельного flush заголовков (fhttp не узнавал `io.NopCloser` Go ≥ 1.20)
  и без dynamic record sizing Go (первые record ~1.2 KiB).
  `header_style="raw"` — прежнее поведение.
- **`keep_alpn=True`** (вместе с `http_version="1.1"`): hello сохраняет ALPN профиля
  (`h2,http/1.1`, JA4 `…h2_…`), запросы идут по HTTP/1.1, если сервер выбрал
  `http/1.1`. Если сервер выбрал `h2`, соединение закрывается сразу после
  хендшейка (ни байта HTTP) и поднимается `RequestError`. Без `keep_alpn`
  `http_version="1.1"`/`force_http1` по-прежнему переписывает ALPN на `http/1.1` (JA4 `…h1_…`).
- **`Response.fingerprint`**: `alpn_offered`, `alpn_negotiated`, `tls_version`,
  `tls_resumed`, `http_protocol`, `connection_reused`, `request_headers` (поля
  заголовков ровно в том порядке и регистре, в каком транспорт записал их в соединение).

### Fixed
- **h2 conscrypt/okhttp-профиля = okhttp.** Было `1:4096;2:0;4:65535;6:262144|0|m,a,s,p`
  с Chrome-priority в HEADERS, стало как у okhttp `Http2Connection`: SETTINGS
  `4:16777216`, WINDOW_UPDATE `16711681`, псевдо `:method,:path,:authority,:scheme`,
  HEADERS без priority, первый stream 3 (Akamai `4:16777216|16711681|0|m,p,a,s`) —
  сверено с okhttp 4.12.0 через tls.peet.ws.
- **http:// держит keep-alive.** Plain-HTTP транспорт кэшируется на сессию (и прокси),
  а не создаётся заново на каждый запрос.

### Changed
- `session.headers` okhttp-профилей стартует пустым (у okhttp нет дефолтных заголовков
  приложения; `Accept-Encoding`/`User-Agent` дописывает сетевой слой). Прежний набор
  (`user-agent`, `accept: */*`, `accept-encoding`) — `header_style="raw"`.
- okhttp-стиль: `data=bytes` без неявного `Content-Type: application/octet-stream`.

## [0.4.6] — 2026-11-17

### Fixed
- **Порядок шифров conscrypt/okhttp-профиля = порядок Conscrypt на проводе.**
  Было `c02b,c02f,c02c,c030,cca9,cca8`, стало `c02b,c02c,cca9,c02f,c030,cca8`
  (сначала ECDHE-ECDSA AES128/AES256/CHACHA, потом ECDHE-RSA). JA4 сортирует
  шифры и совпадал и раньше; теперь совпадает и JA3: `f79b6bad2ad0641e1921aef10262856b`
  (= tshark на захвате реального приложения), JA3_full и JA4_r — побайтово.
- **`disable_session_tickets` применяется.** Флаг передавался из Python, но
  патченные билдеры (профили и ja3-путь) его не применяли — resumption нельзя
  было выключить.

- **Перемешивание расширений только у Chromium.** `random_tls_extension_order`
  (Python-дефолт `True`) перемешивал порядок у любых профилей, включая upstream
  Safari, Firefox, `okhttp4_android_*` и мобильные приложения, хотя реальные
  клиенты шлют фиксированный порядок. Теперь флаг действует только на
  `chrome_*`, `brave_*`, `opera_*`, `edge_*`. Побочный эффект: upstream
  `okhttp4_android_10` … `_13` теперь дают ровно Conscrypt-hello (JA3 `f79b6bad…`).

### Added
- **TLS 1.3 resumption для conscrypt/okhttp.** В spec добавлен `pre_shared_key`
  (41) последним расширением: в свежем hello он не отправляется (record 512,
  handshake 508, padding 21), при повторном соединении с сохранённым тикетом
  hello несёт PSK — `…,51,45,43,41` вместо padding, как вариант B на телефоне.

## [0.4.5] — 2026-11-16

### Fixed
- **Extra-профили уходили на провод как Chrome.** `createPatchedClient` отправлял
  все extra-идентификаторы (`okhttp4_conscrypt`, `conscrypt_android_latest`,
  `edge_*`, `tor_145`, `safari_macos_*`) в upstream `CreateClient`, который знает
  только `profiles.MappedTLSClients` и молча подставлял `DefaultClientProfile`
  (Chrome_150: GREASE, X25519MLKEM768, ext 27/ECH/ALPS, перемешанный порядок,
  hs_len ~1718). Теперь extra-профили идут через ручной билдер — на проводе их
  собственный hello. Conscrypt: 15 шифров без GREASE, exts
  `0,23,65281,10,11,35,16,5,13,51,45,43,21`, groups 29-23-24, key share X25519 32b,
  hs_len 508, JA4 `t13d1513h2_8daaf6152771_eca864cca44a` (= tshark эталон).
- **Фиксированный порядок расширений для не-Chromium extra-профилей.**
  `random_tls_extension_order` (по умолчанию `True`) больше не перемешивает
  conscrypt/okhttp, tor_145 и safari_macos_* — реальные Conscrypt, Firefox и Apple
  не шаффлят. Edge (Chromium) шаффлит как раньше.
- **Conscrypt spec строится заново на каждый handshake** (тот же класс бага,
  что fresh-spec фикс 0.4.3: общие объекты расширений между соединениями).
- **JA4 по спецификации FoxIO** (совпадает с Wireshark 4.x `tls.handshake.ja4`):
  хеш расширений = отсортированные hex-id без SNI/ALPN + `_` + signature
  algorithms в порядке провода; ALPN-тег = первый+последний символ первого
  значения (`http/1.1` → `h1`, раньше `t`); версия — максимум supported_versions.
  Старый `..._02bdef6adf81` считался по id в порядке провода без sigalgs.

### Changed
- **`Response.fingerprint` читает провод.** Каждое TLS-соединение сессии идёт
  через захватывающий dialer, который сохраняет первый TLS-record (ClientHello)
  ровно как он ушёл в сокет — после ApplyPreset, GREASE, padding, перемешивания
  и ALPN-переписывания `force_http1`. JA3/JA4 считаются из этих байт, по
  host:port ответа. Новые поля: `source` (`"wire"` / `"config"`),
  `client_hello_len`, `ja4_r`, `tls_extensions`, `handshakes`,
  `config_ja3_hash_md5` / `config_ja4` (сконфигурированные значения рядом —
  расхождение = сессия шлёт не то, что сконфигурировано). `akamai_fingerprint`
  по-прежнему из конфигурации h2.
- Прокси-лег не изменён: https:// — тот же insecure CONNECT dialer; http:// и
  socks5:// — dialer самого upstream (берётся из probe-клиента) в обёртке.
  `source: "config"` остаётся только для HTTP/3 racing через прокси и `udp_proxy`
  поверх не-socks5 прокси — там upstream должен сам владеть proxy URL (h3
  транспорт читает его из конфига), иначе QUIC ушёл бы мимо прокси.

## [0.4.2] — 2026-11-12

### Fixed
- **MLKEM key share генерация из заявленных групп (краш HRR).**
  ja3 с кривой 4588 (X25519MLKEM768) в `supported_groups`, но без
  соответствующего key share, заставлял Cloudflare слать HelloRetryRequest,
  а go-tls путь пересборки отвергал кривую: `tls: CurvePreferences includes
  unsupported curve`. peet.ws молча фолбэкал на X25519 (без HRR) и маскировал баг.
  `ensureKeyShare` теперь выводит shares из **заявленных** supported_groups
  (первые две non-GREASE группы + X25519 fallback, Chrome-стиль); utls 1.7.8
  сам генерирует ML-KEM share (mlkem 1184b + X25519 32b = 1216b) в ApplyPreset.
  Проверено на проводе: `group=4588 data=1216 bytes` рядом с `group=29 data=32`.

### Added
- **Mimic-путь key share**: параметр `key_share_data={group_int: raw_bytes}`
  перекрывает автогенерацию захваченными байтами share (прокидывается
  base64 через границу; закрывает хинт upstream «To mimic it, fill the
  Data(key) field manually»).

### Changed
- **Decimal-эвристика для signature algorithms**: строка `"1027"` (только
  цифры, без ведущего нуля) трактуется как decimal и конвертируется в
  hex `"403"`; `"0403"` (с ведущим нулём) остаётся hex как есть. Разрешает
  конфликт decimal-копий ja3 и hex-телефонных профилей.

### Verified
- Полный телефонный профиль (PHONE_JA3 + `psk_mode="psk"` + brotli/zlib +
  явный порядок расширений): cloudflare.com **200** на повторных запросах
  (раньше — краш CurvePreferences), httpbin.org 200, ja4 `t13d1313h2_*`.

## [0.4.1] — 2026-11-12

### Fixed
- **`invalid input` на числовых аргументах ja3**: upstream ja3-mapper
  ожидает именованные/hex-строки; int из curl_cffi-стиль вызовов
  превращались в JSON-числа и ломали Go-unmarshal. Фасад теперь
  нормализует: `key_share_curves` (29→X25519, 4588→X25519MLKEM768),
  `supported_versions` (772→"1.3", 771→"1.2"), signature algorithms
  (int → hex без префикса). Списки `None` остаются `None` (без ложного
  «custom options require ja3_string»).
- **JA4 приведён к спецификации**: `t13d<cc><ec><alpn>_<cipher_hash>_<ext_hash>`.
  Счётчики без GREASE; хеш шифров отсортирован и без GREASE; хеш
  расширений в wire-порядке, но исключает SNI(0), ALPN(16) и GREASE;
  лишний 4-й сегмент signature algorithms убран (это JA4S-территория).
  chrome_131: `t13d1516h2_8daaf6152771_...` — cipher hash совпадает с peet.ws.
- **akamai_fingerprint — канонический формат**
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` с буквами
  псевдо-заголовков; вычисляется из h2 settings, реально применённых к
  профилю: ja3-сессии без явных `h2_settings` получают Chrome-подобные
  дефолты + дефолтный pseudo order + connection flow 15663105, так что
  fingerprint = реальное состояние провода, а не заявка.
- **extensionID дополнен utls-типами**, нужными JA4 и порядку расширений:
  UtlsGREASE, UtlsPadding(21), FakeRecordSizeLimit(28),
  DelegatedCredentials(34), ApplicationSettingsNew/Old(17613/13172),
  GREASEEncryptedClientHello(17513). Раньше они мапились в 0xFFFF и
  портили счётчики/хеши.
- **MLKEM-кривые отключают h3 racing** в ja3-сессиях (quic-go отвергает
  их с «CurvePreferences includes unsupported curve»); h1/h2 не затронуты.

## [0.4.0] — 2026-11-12

### Added
- **Продвинутые контролы ClientHello** (требуют `ja3_string`):
  - `tls_extension_order` — явный wire-порядок TLS-расширений;
  - `grease` — True добавляет GREASE cipher/ext, False убирает всё;
  - `psk_mode` — `"psk"` добавляет pre-shared-key ext, `"no_psk"` срезает;
  - `ech_config_list` — сырые ECH config байты в custom payload;
  - `udp_proxy` — socks5:// для HTTP/3 racing.
- **`Response.fingerprint` / `session.last_fingerprint`**: JA3 (строка +
  md5), JA4, Akamai h2 fingerprint из финального ClientHello — ровно то,
  что сверяется с pcap (wire-значения GREASE рандомятся per-handshake как
  в браузере).
- **Дополнительные TLS-профили**: `edge_99`/`edge_101`/`edge_131`/
  `edge_latest` (Chromium TLS-стек, JA4 идентичен chrome_131),
  `safari_macos_17_0`/`18_0`/`26_0` (Apple ClientHello стабилен с 16),
  `tor_145` (Firefox ESR 128, 15 расширений). Итого 91 профиль.

### Fixed
- **ja3_string сессии теперь идут через `buildJa3Client`** в адаптере:
  upstream парсер ja3 переиспользуется через публичный
  `GetSpecFactoryFromJa3String`, spec правится контролами выше и
  пересобирается в ClientProfile. Автозаполнение пустых SupportedVersions,
  KeyShare, SignatureAlgorithms, Curves, ALPN — раньше пустые значения из
  ja3 давали «invalid Versions field» / «error decoding message».
- `fill_custom_with_chrome_defaults=False` — ja3 уходит как есть, без
  подмешивания Chrome (нужно для CFNetwork/телефонных профилей).
- Fallback `UTLSIdToSpec` для utls-нативных ID (Safari/Edge) с nil
  SpecFactory — fingerprint работает и для них.

### Target
- ClientHello iOS 26 CFNetwork/3860.700.2 воспроизводим (профиль
  `safari_ios_26_0` — это Safari, не CFNetwork, и давал CF 403).

## [0.3.1] — 2026-11-11

### Fixed
- **`close()` реально освобождает соединения** для всех типов сессий:
  раньше удалялся только sessionId из Go-мап, без `CloseIdleConnections` —
  keep-alive сокеты жили до таймаута. Нативный билдер теперь создаёт все
  identifier-клиенты, и `yumeclient_close` рвёт idle-коннекты у каждого.
- `AsyncSession.close()` синхронно помечает сессию закрытой — забытый
  `await` больше не оставляет сессию рабочей.
- Гонка close-vs-request: флаг перепроверяется после захвата lock.
- Двойной `close()` и `close()` после упавшего запроса — молча.

## [0.3.0] — 2026-11-11

### Added
- **`client_os`**: windows / android / ios / macos — базовый набор
  заголовков под профиль+OS (UA, client hints), OS выводится из
  идентификатора автоматически. Chrome+iOS → CriOS без client hints.
- **Браузерные дефолтные заголовки** для каждой сессии (user-agent,
  sec-ch-ua, accept, sec-fetch-*, accept-encoding, accept-language),
  согласованные по профилю — больше не `Go-http-client/2.0`.
- `Headers` — регистронезависимый упорядоченный dict: `update()`,
  замена, per-request override; порядок дикта = порядок на проводе.
- One-shot API: `yumeclient.get/post/...` и `await yumeclient.aget/...`.

### Changed
- Sync `Session` и async `AsyncSession` — обёртки над одним движком:
  cookies, заголовки и транспортное поведение идентичны.

## [0.2.5] — 2026-11-11

### Fixed
- **http://-цели уважают прокси сессии** (утечка исправлена): schemeGuard
  строил plain HTTP/1.1 клиент на голом DefaultTransport без Proxy —
  http:// запросы шли мимо прокси с реального IP. Именно это давало
  плавающие ошибки `EOF` на прокси-пулах: dead-ноды, полузакрытые
  keep-alive и ротация нод выплёскивались сырыми transport EOF.
  Guard теперь запоминает прокси сессии и ставит его в Transport.Proxy.

## [0.2.4] — 2026-11-11

### Fixed
- **Прокси-лег https:// прокси не верифицируется** (в духе curl/requests/
  браузеров): verify=False действовал только на сертификат цели, а серт
  прокси по IP без IP-SAN падал даже без verify=False. CONNECT-диалер
  теперь всегда пропускает проверку сертификата прокси; verify цели
  работает как раньше.

## [0.2.3] — 2026-11-11

### Fixed
- **`verify=False` для https://-прокси**: upstream connect.go строил
  прокси-TLS с жёстким tls.Config без InsecureSkipVerify. Для https://
  прокси клиент собирается адаптером со своим CONNECT-диалером, чей
  InsecureSkipVerify следует флагу сессии. socks5/http прокси и
  uTLS-фингерпринты цели не тронуты.

## [0.2.2] — 2026-11-11

### Added
- **`multipart.py` — отдельный модуль** (`encode_multipart`,
  `choose_boundary`): правится без ядра, `__init__` реэкспортирует.

### Fixed
- **Коллизия схем http/https в одной сессии**: upstream хранит кэш
  транспортов по host:443 без учёта схемы — h2/h3 транспорт, закэшированный
  с https-вызова, передавался http:// запросу на тот же хост
  («protocol negotiated» / «http2: unsupported scheme», симптом «форсит
  https»). schemeGuard: http:// всегда через выделенный HTTP/1.1 транспорт
  с тем же cookie jar и политикой редиректов.

## [0.2.1] — 2026-11-11

### Added
- **multipart — requests-совместимые file specs** (по мотивам
  FlorianREGAZ/Python-Tls-Client): tuple arities 2..4, голые file
  objects/bytes/str, имя из `.name`, Content-Type через mimetypes,
  процент-экранирование CR/LF/кавычек как у urllib3.

## [0.2.0] — 2026-11-11

### Added
- **Sync + async движок**: `Session` (with) / `AsyncSession` (async with) —
  одинаковый requests-стиль синтаксис; one-shot helpers.
- **`client_os`** (windows/android/ios) и дефолтные наборы заголовков на
  профиль.
- **examples/** — базовый синтаксис, профили/OS, cookie flow.

### Fixed
- **requestCookies реально сажаются в Go jar** — upstream cffi их
  игнорировал, cookies из Python вообще не улетали.
- **Cookies с redirect-хопов сохраняются**: адаптер отдаёт jarDump
  (все хосты) после каждого запроса, мержится в `session.cookies`.
- Разовые per-request cookies больше не прилипают к jar сессии.
- `CookieJar.set` без домена обновляет самую специфичную одноимённую
  cookie вместо дубля; домены нормализуются (порт/точка/регистр).

## [0.1.6] — 2026-10-12

### Added
- Первый публичный пакет на PyPI: async фасад над
  bogdanfinn/tls-client v1.16.0 через cgo c-shared адаптер,
  профили upstream, CookieJar, multipart encoder, CI (тесты на
  трёх ОС + релизные wheels для py3.11–3.14).
