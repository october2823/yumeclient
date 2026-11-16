# CHANGELOG

Все заметные изменения проекта документируются в этом файле.
Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

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
