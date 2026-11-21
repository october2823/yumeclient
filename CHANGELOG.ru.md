# CHANGELOG

[English](CHANGELOG.md) | **Русский**

Все заметные изменения проекта документируются в этом файле.
Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [0.8.3] — 2026-11-21

### Added
- `CODE_OF_CONDUCT.md`: Contributor Covenant 2.1 (русская версия — его официальный перевод).
  Жалобы отправляются закрыто, через форму закрытого сообщения репозитория.
- `ACCESSIBILITY.md`: что значит доступность для библиотеки без своего интерфейса и куда
  сообщать о препятствиях.

## [0.8.2] — 2026-11-21

### Added
- **Документация на английском.** Каждая страница теперь есть на английском и русском.
  Английские страницы лежат по обычным путям (`README.md`, `USAGE.md`, `CHANGELOG.md`,
  `docs/*.md`, `examples/README.md`), русские — рядом (`*.ru.md`, `docs/ru/*.md`). Под
  заголовком каждой страницы — ссылка на перевод. `tests/test_docs_i18n.py` проверяет, что
  у двух версий одинаковая структура (заголовки, блоки кода, таблицы, списки, ссылки), что
  в английских страницах нет русского текста и что каждый `#якорь` в ссылках существует.
- **Руководство для участников и политика безопасности**: `CONTRIBUTING.md` и `SECURITY.md` (с
  русскими версиями), формы issue (ошибка, несовпадение отпечатка, предложение) и
  шаблон pull request'а. Об уязвимостях сообщают закрыто через GitHub security advisories.

### Changed
- Русские страницы переехали: `docs/X.md` в `docs/ru/X.md`, `USAGE.md` в `USAGE.ru.md`,
  `CHANGELOG.md` в `CHANGELOG.ru.md`, `examples/README.md` в `examples/README.ru.md`. Старые
  ссылки (с PyPI и из `pyproject.toml`) теперь открывают английскую версию.
- В sdist попадают все `.md`-файлы из корня репозитория.

### Fixed
- **Открытие соединения обрывалось через 30 с**, хотя запрос разрешал больше. Диалеры
  сессии получали лимит от первого запроса (`max(30 с, connect)`), поэтому `timeout=None`, больший
  `connect` в позднем запросе или прокси, медленно отвечающий на CONNECT, заканчивались
  `ConnectTimeout` через 30 с. Теперь открытие одного соединения (DNS, TCP, туннель прокси) ограничено
  только таймаутами запроса и фиксированными 240 с.
- **`local_address` игнорировался** для `https://`-запросов через `https://`-прокси: соединение
  с прокси не привязывалось.
- **`http://`-прокси, не отвечавший на CONNECT,** держал соединение открытым ещё 30 с после
  того, как запрос уже завершился таймаутом или был отменён. Теперь обмен CONNECT
  заканчивается вместе с запросом. Отказ в CONNECT через `https://`-прокси теперь сообщается
  как `Proxy responded with non 200 code: ...`, как и для `http://`-прокси.
- В `LICENSE` не хватало последнего абзаца лицензии MIT ("IN NO EVENT SHALL ..."), из-за
  этого GitHub не распознавал лицензию.
- Ссылки документации на несуществующие заголовки: из `protocols.md` в `development.md`
  и из `responses.md` в `diagnostics.md`.
- `custom-tls.md`: кадры PRIORITY после SETTINGS отправляют профили `firefox_102`–`firefox_123`,
  а не «Firefox до 135».
- Этот список изменений: даты 0.1.6–0.5.1 теперь совпадают с загрузками на PyPI (у 0.2.0–0.2.4
  были на месяц позже), добавлены пропущенные 0.4.3 и 0.4.4, заголовки версий ведут
  на релизы.

## [0.8.1] — 2026-11-21

### Added
- **Документация.** Справочник `docs/` (14 страниц: сессии, запросы, ответы, профили,
  протоколы, свой TLS-отпечаток, таймауты и ошибки, cookies, прокси, диагностика,
  ограничения, установка, разработка), `USAGE.md` переписан в руководство с примерами,
  README на английском для GitHub и PyPI, `THIRD_PARTY_NOTICES.md` с лицензиями
  upstream-модулей.
- **Примеры** `examples/` (10 скриптов: быстрый старт, asyncio, профили и заголовки,
  cookies, стриминг, загрузка файлов, ошибки и повторы, прокси, отпечаток, custom JA3).
  Все запускаются в тестах против локальной замены httpbin (`tests/httpbin_local.py`);
  Python-фрагменты документации проверяются на синтаксис, ссылки — на существование.
- `TooManyRedirects` (`kind="too_many_redirects"`) — больше 20 редиректов. Раньше —
  `RequestError` без типа.
- `h2_settings` и `h2_settings_order` принимают любой идентификатор SETTINGS: имена RFC 9113,
  `ENABLE_CONNECT_PROTOCOL`, `NO_RFC7540_PRIORITIES` (у Firefox), `UNKNOWN_SETTING_<n>` и
  числа (`9`, `"0x9"`).

### Fixed
- **Custom JA3 с расширениями 22 (encrypt_then_mac) и 51764 (trust anchors)** — JA3
  `chrome_146`/`chrome_152` и `cloudscraper` из их же отпечатка — падал с непонятной
  `TLSError: unknown ClientHelloID: Custom-ja3`. Теперь работают. JA3 с расширением,
  которое нельзя собрать, — `InvalidRequestError` с номером расширения. Разбор JA3 больше не
  печатает `attention ...` в stdout.
- **`trust_anchors_payload` и `ech_config_list` игнорировались** с первой версии. Теперь
  первое попадает в расширение 51764, второе включает настоящий ECH (внутренний ClientHello
  зашифрован ключом сервера; без него ECH остаётся GREASE). Оба проверяются при создании
  сессии.
- **`CookieJar` терял cookie при параллельных запросах**: `AsyncSession` применяет ответы
  из потоков пула, и одновременные изменения затирали друг друга (8 потоков × 400 cookie —
  в jar оставалось 585 из 3200). Jar стал потокобезопасным; `copy.deepcopy` и `pickle`
  работают.
- **Редиректы как в браузере.** На каждый хоп Go сам добавлял `Referer` с адресом редиректа
  (браузер и `requests` его не меняют); теперь нет, ваш `Referer` переносится как есть. Когда
  метод меняется на GET, вместе с телом уходят `Content-Type`, `Content-Encoding`,
  `Content-Language`, `Content-Location`, `Content-Length` и `Origin` (как в Chromium).
  301 и 302 меняют на GET только `POST` (стандарт Fetch); раньше в GET без тела
  превращались и `PUT`, `PATCH`, `DELETE`.
- **Заголовки ответа — как прислал сервер.** По HTTP/1.1 (если в запросе был gzip в
  `Accept-Encoding`, то есть почти всегда) и по HTTP/3 из ответа пропадали `Content-Length`
  и `Content-Encoding`; по HTTP/2 оставались. Тело по-прежнему распаковывается.
- **`supported_signature_algorithms`** с `"0x0403"` падал при первом запросе; теперь
  принимаются имена, числа и hex с `0x` и без, неизвестное имя — `SessionConfigurationError`.
- **`pseudo_header_order`** с опечаткой или неполный отправлял запросы без `:authority` и
  `:scheme`. Теперь нужны все четыре псевдозаголовка (`":method"`, `"method"` или `"m"`).
- **`tls_extension_order`** ставил в конец ECH, ALPS (старый и новый), NPN, PSK и ещё ряд
  расширений: их номера сопоставлялись неверно.
- **`h2_settings` без `h2_settings_order`** уходили в случайном порядке; теперь — в порядке
  словаря.
- **`connection_flow` без `ja3_string`** молча игнорировался; теперь
  `SessionConfigurationError`, как у остальных параметров custom TLS.
- **`udp_proxy`** у custom JA3 заменял и TCP-прокси, у профилей игнорировался, а
  `http_version="3"` с HTTP-прокси отклонялся даже вместе с `udp_proxy`. Теперь QUIC идёт через
  `udp_proxy` (SOCKS5), TCP — через `proxy`.
- **QUIC через SOCKS5 выдавал себя**: 4-байтный Source Connection ID (у Chrome — 0), без
  `google_initial_rtt` и без стадийных таймаутов. Теперь рукопожатие через прокси такое же, как
  напрямую.
- **Неверный URL запроса** (не `http(s)://`, без хоста, с неверным портом) давал
  `ConnectError` с `retryable=True` — код повтора по `retryable` повторял его без конца.
  Теперь — `InvalidRequestError` (`stage="request"`) до обращения к сети.
- **Свой JA3 с `X25519MLKEM768` (4588)** — то есть JA3 любого современного Chrome — с
  `http_version="3"` молча оставался на TCP. Теперь HTTP/3 работает: QUIC ClientHello
  берётся из записи Chrome (или quic-go при `fill_custom_with_chrome_defaults=False`), а не
  из JA3.
- **Незакрытая сессия** держала свои соединения до конца процесса. Теперь их освобождает
  сборщик мусора (закрывать сессию явно по-прежнему правильно).
- `default_headers()` для Safari, приложений и okhttp возвращал обычный `dict` (поиск с учётом
  регистра); теперь всегда `Headers`.
- **Неверный URL прокси** (без схемы, `ftp://`, без порта у SOCKS, кривой порт) давал
  `InvalidRequestError: client creation failed` при первом запросе; теперь —
  `SessionConfigurationError` с понятным текстом при создании сессии (и для `proxy=` запроса).
- `http://` через `https://`-прокси проверял сертификат прокси, а `https://` — нет. Теперь
  оба не проверяют (сертификат прокси никогда не проверялся для HTTPS-целей; цель
  проверяется по `verify`).

### Changed
- **Предел редиректов — 20, как в браузерах** (стандарт Fetch, Chromium). Раньше действовал
  предел Go: на 10-м редиректе ошибка, то есть выполнялось 9.
- `udp_proxy` принимает только `socks5://` и `socks5h://` (`udp://` принимался, но не работал).
- Метаданные пакета: описание, классификаторы, ключевые слова, ссылки на документацию,
  лицензия в формате SPDX (`MIT`), файлы лицензий upstream в wheel.
- Старые примеры (`basic_requests.py`, `cookies_flow.py`, `profiles_and_os.py`) заменены
  новыми.

## [0.8.0] — 2026-11-20

### Added
- **HTTP/3 и QUIC как у браузера — для 53 профилей.** Раньше QUIC-рукопожатие у всех
  профилей было quic-go: его ClientHello (JA4 `q…` одинаковый для всех), его transport
  parameters, его Initial-пакеты; HTTP/3-параметры были только у 13 профилей. Теперь
  для Chrome 103–152, Edge 99/101/131/latest, Brave 146, Opera 89–91 и Firefox 102–148
  (включая `_PSK`) всё берётся из записей самих браузеров (`native/h3profiles.json`):
  - ClientHello внутри QUIC (свой у QUIC: только TLS 1.3, без GREASE у Chromium),
    перемешивание расширений как у Chromium (Firefox — с 135), ECH GREASE;
  - transport parameters: набор, значения, порядок (перемешанный у Chromium и Firefox
    104–135), GREASE-параметр, `version_information`, `google_connection_options`,
    `google_initial_rtt` на повторных соединениях;
  - Initial-пакеты: длины Connection ID (у Firefox — случайная), номер первого пакета
    (у Firefox 146+ — случайный, как в neqo), размер датаграммы (1250 у Chromium,
    1357/1252 у Firefox), заполнение (PADDING-фреймы у Chromium, нули после пакета у
    Firefox), раскладка ClientHello по пакетам: chaos protection Chromium (≤122, 124–131,
    133+ — три разных схемы) и SNI slicing Firefox 146+;
  - HTTP/3: SETTINGS и их порядок, GREASE-фрейм, порядок открытия QPACK-потоков,
    PRIORITY_UPDATE у Chromium, заголовок `priority`, порядок псевдозаголовков.
  Тест `tests/test_h3_fingerprints.py` сверяет каждый профиль с записью браузера на
  aioquic-сервере. Записи собираются `scripts/h3_browsers.py` (скачивает нужную версию
  браузера), `scripts/h3_capture.py` (сервер-регистратор), `scripts/h3_profiles.py`
  (собирает `h3profiles.json`).
- **HTTP/2 без TLS (h2c, prior knowledge) для `http_version="2"` на `http://`**, как
  `Protocol.H2_PRIOR_KNOWLEDGE` у OkHttp и gRPC: SETTINGS, WINDOW_UPDATE, приоритеты и
  порядок псевдозаголовков — профиля. Сервер без h2c — `ProtocolError`.
- **HTTP/3, сломанный у сервера, как в Chrome.** Если HTTP/3-соединение установилось,
  а затем закрылось с кодом ошибки HTTP/3, QPACK или QUIC (сервером или клиентом из-за
  нарушения протокола), HTTP/3 для этого адреса помечается сломанным на 5 минут
  (при повторах — вдвое дольше, до 2 суток), запрос — если его можно повторить —
  сразу уходит по TCP, следующие тоже идут по TCP, без UDP-попытки и задержки гонки.
  Раньше каждый запрос снова выигрывал HTTP/3 и падал. Закрытие без ошибки (QUIC
  NO_ERROR, H3_NO_ERROR, код 0, неизвестные и зарезервированные коды — RFC 9114 §8.1 —
  и транспортный APPLICATION_ERROR, которым приходит закрытие во время рукопожатия),
  сброс сервером одного запроса, отказ от слишком большого ответа, таймауты и
  соединение, которое сервер забыл (idle timeout, stateless reset), HTTP/3 не ломают:
  следующий запрос — по новому QUIC-соединению.
- `yumeclient.profiles.HTTP3_FINGERPRINTS` (профили с записью браузера) и
  `yumeclient.profiles.NO_HTTP3` (клиенты без HTTP/3 с причиной).

### Fixed
- **HTTP/3 с серверами, использующими динамическую таблицу QPACK** (google.com и др.):
  каждый запрос падал с `qpack: expected Required Insert Count to be zero` — профили
  объявляли таблицу 64 KiB, а декодер её не поддерживал. Реализован декодер динамической
  таблицы (RFC 9204) с потоками энкодера/декодера.
- **Редирект с `http://` на `https://` уходил не с профилем**: `http://`-запросы шли
  через отдельный клиент, и `https://`-хоп после редиректа открывал TLS со стека Go
  (его ClientHello вместо профиля, системная проверка сертификата вопреки
  `verify=False`). Теперь все хопы идут через сессию: `https://` — профилем, `http://` —
  простым транспортом сессии.
- `http://`-запросы игнорировали `local_address` и брали прокси из переменных окружения
  `HTTP_PROXY`/`HTTPS_PROXY` (запросы `https://` — нет). Теперь у обоих — только `proxy=`
  сессии и её адрес.
- **Лимит размера заголовков ответа HTTP/3 не действовал** у профилей, не отправляющих
  `SETTINGS_MAX_FIELD_SECTION_SIZE` сами (у `firefox_147`/`148` уже в 0.7.0, в 0.8.0 — у всех
  профилей с записью браузера): HEADERS-фрейм, объявивший 2^40 байт, заставлял выделить
  эту память (процесс падал с `out of memory`), а одна запись динамической таблицы,
  повторённая 2000 раз, давала 120 МБ заголовков. Теперь действует объявленный профилем
  лимит (Chrome — 256 KiB), иначе 10 МБ, — и для трейлеров.
- Трейлеры, ждущие запись динамической таблицы QPACK, ждали её дольше любых таймаутов.
  QPACK: отменённые и отвергнутые секции и брошенные до конца ответы отменяются у
  энкодера (Stream Cancellation, один раз на поток), обрыв потока энкодера закрывает
  соединение (H3_CLOSED_CRITICAL_STREAM), ошибочная инструкция в нём —
  QPACK_ENCODER_STREAM_ERROR.
- Сервер, не дающий кредита flow control нашим однонаправленным потокам, держал запросы
  дольше любых таймаутов: подтверждения QPACK (Section Acknowledgment) и PRIORITY_UPDATE
  Chrome писались на пути запроса. Теперь они уходят из очереди в фоне; переполненная
  очередь (64 KiB) закрывает соединение (H3_EXCESSIVE_LOAD). Порядок между потоками
  прежний: PRIORITY_UPDATE уходит до HEADERS своего запроса (как у Chrome), типы
  QPACK-потоков Firefox — до SETTINGS; поток без кредита задерживает запрос не больше
  чем на 50 мс.
- `max_idle_timeout` сервера меньше 5 секунд поднимался до 5 секунд (а 0 — «без таймаута» —
  превращался в 5 секунд): после того как сервер закрыл простаивающее соединение,
  следующий запрос до 5 секунд ждал на мёртвом соединении. Теперь, как в Chrome и Firefox,
  действует объявленное значение и запрос сразу идёт по новому соединению; keep-alive
  профилей без QUIC-отпечатка — не чаще раза в секунду.
- Полностью прочитанный по HTTP/3 ответ с `Content-Encoding: deflate`, у которого конец
  потока (FIN) пришёл после последнего DATA, закрывался как брошенный: STOP_SENDING и
  отмена секции QPACK, чего браузеры не делают. Тело deflate теперь дочитывается до конца
  потока, как gzip.
- `http://` через `socks5h://` и `socks4://` уходил на прокси как запрос к HTTP-прокси
  (`GET http://...` открытым текстом); теперь через SOCKS, как `https://`.
- **Стадийные таймауты HTTP/3** (`connect`, `write`, `read`) не работали: `read=0.5` ждал
  ответа 2 с, `connect=0.5` при молчащем UDP кончался `ConnectError` через 5 с.
- Заголовок `priority: u=0, i` по HTTP/2 отправляется с Chrome 124 (записи Chrome 99–152):
  у `chrome_124`, `chrome_130_PSK`, `chrome_131`, `chrome_133` (+`_PSK`), `edge_131`,
  `edge_latest` его не было.
- Edge-профили отправляли SETTINGS HTTP/2 Chrome 107–116 при любой версии: у `edge_131`/
  `edge_latest` лишний `MAX_CONCURRENT_STREAMS`, у `edge_99`/`edge_101` лишний
  `ENABLE_PUSH`. Теперь — как у Chromium той же версии.
- `chrome_116_PSK_PQ` по QUIC объявляет X25519Kyber768, как Chrome 116 с PostQuantumKyber.
- **Заголовки браузеров сверены с записями самих браузеров** (Chromium 99–152, Opera 89–91,
  Firefox 102–148; `tests/fixtures/browser_headers.json`):
  - HTTP/1.1: `Host` уходил последним (теперь первым, как у любого клиента), имена — в
    нижнем регистре (теперь как у браузера: `User-Agent`, `Sec-Fetch-Mode`, у Chromium —
    `sec-ch-ua`), не было `Connection: keep-alive` у Chrome и Firefox;
  - `Sec-CH-UA` у всех версий был `"Not(A:Brand";v="24"` в одном порядке — теперь по
    алгоритму Chromium: GREASE-бренд, его версия и порядок брендов свои у каждой версии
    (Chrome, Edge, Brave; Opera — значения релизных сборок);
  - Chrome: `Accept` с `signed-exchange;v=b3;q=0.9` до 109, `zstd` в `Accept-Encoding` только
    с 123 (раньше у всех версий);
  - Opera: в User-Agent стояла версия Opera вместо версии Chromium (`Chrome/91.0.0.0`
    вместо `Chrome/105.0.0.0`) и не та `OPR/`;
  - Firefox: место `Accept-Encoding`, значения `Accept`/`Accept-Language`/`Accept-Encoding`
    по версиям, `Priority: u=0, i` с 128, `te: trailers` только по HTTP/2 и на всех ОС
    (раньше — по всем протоколам и только на Windows), `rv:109.0` у Firefox 110–119;
  - HTTP/2 HEADERS у `firefox_132`/`133`/`135` несли приоритет Chrome (exclusive, вес 256)
    вместо Firefox (вес 42); `tor_145` — SETTINGS, приоритет и заголовки Firefox 128 ESR
    (база Tor Browser 14), а не Firefox 133+.
- Akamai-отпечаток печатал SETTINGS `NO_RFC7540_PRIORITIES` (9) как `0:1`.

### Changed
- `http_version="3"` с клиентом, у которого HTTP/3 нет (`okhttp4_*`, `okhttp4_conscrypt`,
  `conscrypt_android_latest`, `cloudscraper`, `tor_145`), — `SessionConfigurationError`
  (раньше предупреждение и QUIC-рукопожатие quic-go). Для профилей без записи браузера
  (Safari, iOS- и Android-приложения) предупреждение остаётся.
- `http_version="2"` на `http://` — h2c вместо HTTP/1.1 (при `"auto"`, `"1.1"`, `"3"` по
  `http://` по-прежнему HTTP/1.1).
- HTTP/3 с записью браузера не использует 0-RTT (браузерное рукопожатие без early data).
- `default_headers()` и стартовые `session.headers` браузерных профилей пишут имена как
  браузер по HTTP/1.1 (`User-Agent` вместо `user-agent`). `default_headers()` возвращает
  `Headers`: чтение, запись, `del`, `pop`, `setdefault` — без учёта регистра, с сохранением
  написания (`h["user-agent"] = ...` заменяет `User-Agent`).
- По HTTP/1.1 `Host` идёт первым и тогда, когда его задали вы (`headers={"Host": ...}`)
  без `header_order`; порядок с `Host` в `header_order` соблюдается как есть.
- `edge_latest`: заголовки Edge 131 (`Edg/131`, `Sec-CH-UA` Edge 131, `zstd`), как его
  TLS- и HTTP/2-профиль Chromium 131; раньше — Edge 120.
- Удалена недокументированная отладочная переменная `YUMECLIENT_UPSTREAM_JA3` (https с ней
  не работал с 0.7.0).

## [0.7.0] — 2026-11-20

### Added
- **`response.history`** — ответы пройденных редиректов (статус, заголовки, Set-Cookie,
  URL, протокол, время перехода, тело до 64 KiB), `response.is_redirect`. Раньше список был
  всегда пуст. Тело редиректа читается, только пока идёт (пауза > 0.5 с, чтение > 2 с →
  `b""`), и не задерживает переход. В истории все выполненные редиректы, включая цепочки
  307/308 с телом.
- **Chrome-заполнение custom JA3 работает.** `fill_custom_with_chrome_defaults=True`
  (по умолчанию) раньше не доходило до сетевого слоя. Теперь не заданное явно
  (sigalgs, версии, key shares, ALPN/ALPS, сжатие сертификатов, ECH, HTTP/2, HTTP/3)
  берётся из `chrome_152`; `False` — общие значения.
- **HTTP/3-параметры Chrome для `chrome_146`–`chrome_152` (+`_PSK`) и `brave_146`**:
  upstream их не задаёт, уходил только `SETTINGS_H3_DATAGRAM`. Теперь SETTINGS,
  порядок псевдозаголовков и приоритет совпадают с Chrome 157 на проводе
  (`tests/fixtures/chrome_157_wire.json`, тест на aioquic-сервере).
- Chromium-профили по HTTP/2 отправляют `priority: u=0, i`, как Chrome.
- `headers={"X": None}` удаляет заголовок (как в requests), в том числе добавляемый
  сетевым слоем: `Accept-Encoding`, `priority` по HTTP/2 и HTTP/3, умолчания
  `okhttp`-стиля, а также `application/octet-stream` для `data=bytes`.
- Wheels Linux проверяются в CI на manylinux2014 (glibc 2.17).

### Fixed
- **Гонка протоколов (`http_version="3"`) отправляла запрос дважды**: по HTTP/3 и через
  300 мс ещё и по HTTP/2 — если HTTP/3 отвечал дольше 300 мс, POST доходил до сервера
  два раза (обе попытки читали одно тело). Теперь гонка идёт за соединение: запрос
  отправляет только протокол, первым установивший соединение (HTTP/3 — после полного
  рукопожатия), или уже открытое соединение. Каждый запрос гонки открывал новое
  QUIC-соединение — теперь выигравшее переиспользуется. После ошибки запомненного
  протокола, а у HTTP/3 и после таймаута или отмены (молчащий UDP не отличить от
  медленного сервера), следующая гонка идёт на новых соединениях; после таймаута или
  отмены HTTP/1.1/HTTP/2 протокол и пул остаются (HTTP/2-соединение продолжает работать).
  Заголовок, который HTTP/2 не передаёт (`Connection: Upgrade`, `Upgrade`,
  `Transfer-Encoding` кроме `chunked`), — `InvalidRequestError` без потери соединения
  (и вне гонки сессия больше не сбрасывается). Сам запрос повторяется гонкой, если он идемпотентный
  (GET/HEAD/OPTIONS/TRACE или с `Idempotency-Key`) и время ещё есть, либо если
  соединение закрылось, не отправив его. Ответ медленнее 10 с в гонке больше не
  превращается в ошибку; если не подключился ни один протокол, ошибка — от TCP.
- **Закрытая сессия не закрывала соединения**: HTTP/2 оставались открытыми до разрыва
  сервером, у HTTP/3 — UDP-сокет, QUIC-соединение и горутины (выигравший в гонке
  транспорт вообще не сохранялся и не закрывался). Одновременные первые запросы одной
  сессии создавали по своему нативному клиенту, и все, кроме последнего, не закрывались
  никогда. Теперь клиент у сессии один, а закрывается он (и после ошибки запроса, и при
  `close()`), когда завершатся запросы, ещё идущие через него, включая их редиректы.
- **Ответ с `Content-Encoding: deflate` по HTTP/1.1 зависал** до таймаута (fhttp читал
  всё тело ещё в цикле чтения соединения — взаимная блокировка). Тело deflate вообще
  читалось целиком в память до выдачи ответа, в обход стриминга и `max_content_size`.
  Теперь распаковка ленивая; raw deflate (RFC 1951), начинающийся не с `0x78`, раньше
  возвращался сжатым.
- Закрытие недочитанного zstd-тела могло зависнуть: декодер ждал своё чтение тела,
  которое закрывалось после него.
- **`cloudscraper` против OpenSSL с CBC**: рукопожатие падало с `bad record MAC` — utls
  объявлял encrypt_then_mac, но не реализовывал. Реализован RFC 7366.
- **`Go-http-client/2.0` при гонке HTTP/3** (`http_version="3"`) в сессии без `User-Agent`.
  Пустой ключ `User-Agent` теперь означает «не отправлять» и для HTTP/2.
- **Дополнительные HTTP/2-соединения** (когда первое занято или закрыто) открывались
  без контекста запроса: без отмены, connect-таймаута и `timings["proxy"]`.
- Custom JA3: `priority_frames` и `header_priority` не доходили до провода; JA3 с
  расширением 27 без `cert_compression_algos` падал (`unknown ClientHelloID`, а upstream
  печатал в stdout); record_size_limit уходил со значением 0.
- Числовые `key_share_curves`: GREASE-значения (`10794` и др.) и `25497`
  (X25519Kyber768) превращались в X25519MLKEM768 (второй ML-KEM key share — обрыв
  рукопожатия), `31` — в P521 (P521 — это `25`). Неизвестные значения
  `key_share_curves`, `supported_versions`, `cert_compression_algos` молча выпадали из
  hello — теперь `SessionConfigurationError`.
- Akamai-отпечаток `firefox_102`–`firefox_123` не включал их PRIORITY-фреймы.
- **Заголовок со значением `None` уходил пустым** (`User-Agent: `, `X-Token: `) вместо
  удаления.
- Custom JA3 без X25519 в группах (например `23-24`) получал key share X25519 —
  незаявленной группы, и OpenSSL обрывал рукопожатие (`illegal_parameter`). Key shares
  теперь только для групп из JA3; гибрид ML-KEM — только вместе с X25519. При key
  shares вида `X25519MLKEM768, P-384, X25519` ответ сервера с ML-KEM обрывал рукопожатие
  (`invalid server key share`: utls брал ключ первой классической группы).
- Запрос, ждущий дополнительное HTTP/2-соединение, которое открывает другой запрос, не
  реагировал на свою отмену и таймаут до конца той установки.
- Linux wheel x86_64 помечался `manylinux1` (glibc 2.5), хотя Go-рантайму нужен Linux 3.2+;
  теперь `manylinux2014`.

### Changed
- `fhttp`, `tls-client`, `utls` собираются из `native/third_party` с правками
  (`native/third_party/patches/*.patch`; `python scripts/third_party.py check` сверяет копии
  с upstream + патч и отклоняет любые лишние файлы).
- Предупреждение «нет браузерных HTTP/3-параметров» — для всех профилей без них, а не
  только для `chrome_150`/`152`.
- Заголовок с недопустимым именем или управляющим символом в значении (кроме табуляции)
  отклоняется до отправки — `InvalidRequestError` (`ValueError`). Раньше запрос падал в
  сетевом слое с `ConnectError` (kind `connect`), а сессия при этом теряла соединения;
  `except ConnectError` такие ошибки больше не ловит.

## [0.6.0] — 2026-11-20

### Added
- **Диагностика TLS-конфигурации** (`yumeclient.diagnostics`):
  - `session.export_profile()` — версионированный JSON-снимок идентичности сессии
    (профиль, OS, header style, `http_version`, все явные параметры ClientHello/HTTP/2,
    дефолтные заголовки в порядке провода, последний наблюдённый отпечаток). Прокси,
    таймауты, cookies, `verify`, CA, локальный адрес и заголовки с учётными данными
    не экспортируются (последние — с `include_secrets=True`).
  - `Session.from_profile(profile, **overrides)` / `AsyncSession.from_profile(...)` —
    восстановление, заголовки точно (порядок и удалённые); чужой формат, более новая
    версия или неизвестный параметр — `SessionConfigurationError`.
  - `fingerprint_diff(expected, actual)` — сравнение отпечатков (`Response`, профиль или
    dict) по полям: `value` / `missing` / `order` / `set`, GREASE игнорируется, JA3 —
    по компонентам.
  - `response.trace()` — редактированный трейс запроса: порядок заголовков на проводе,
    протокол, ALPN, TLS-версия и шифр, тайминги, JA3/JA4/Akamai, длина и SHA-256 тел;
    значения `Authorization`/`Cookie`/`Set-Cookie`/`*token*`/`*secret*`/`*key*`/... и
    query (в том числе в `Location`, `Referer`, `Link`, `Refresh`) скрыты.
  - `tests/fixtures/profiles.json` + `tests/test_profile_fixtures.py`: эталонный
    ClientHello каждого из 93 профилей (JA3/JA4/JA4_r, ALPN, порядок расширений, Akamai,
    порядок заголовков); `python scripts/profile_fixtures.py [--update]`.
- `connection_info["tls_cipher"]` и `timings["proxy"]` (часть `connect` на путь через прокси).
- `ProtocolError` (`ConnectError`, `kind="protocol"`).
- `yumeclient.__version__`.

### Fixed
- **`http_version="2"` молча откатывался на HTTP/1.1**, если сервер выбирал `http/1.1`.
  Теперь соединение закрывается сразу после хендшейка, запрос не отправляется,
  `ProtocolError`. `keep_alpn` при выборе сервером `h2` тоже даёт `ProtocolError`
  (раньше — общий `ConnectError`).
- **Противоречивые настройки протокола** принимались и молча разрешались в пользу одной
  из них: `force_http1=True` + `http_version="2"` (уходил HTTP/1.1), `alpn_protocols=["h2"]`
  + `http_version="1.1"` (ALPN переписывался на `http/1.1`) и т. п. Теперь —
  `SessionConfigurationError` в конструкторе, до сети (список — [Протоколы](docs/ru/protocols.md#противоречивые-настройки)).
- **Присваивание транспортных параметров сессии игнорировалось** (`s.proxy = ...`,
  `s.http_version = ...` записывались в объект-обёртку и ни на что не влияли, хотя
  USAGE обещал пересоздание клиента) — теперь `AttributeError` с подсказкой.
- **`session.headers` был регистронезависим только при записи**: `s.headers["user-agent"]`
  и `del` давали `KeyError`, `"user-agent" in s.headers` — `False`, а
  `s.headers.pop("user-agent", None)` ничего не удалял — заголовок продолжал уходить.
  Теперь `[]`, `in`, `get`, `pop`, `del` не зависят от регистра.
- **Без `User-Agent` уходил `User-Agent: Go-http-client/1.1`** (`…/2.0` на h2) — отпечаток
  Go вместо профиля, а `USER-AGENT` в другом регистре уходил вторым заголовком рядом
  с `Go-http-client`. Теперь заголовка нет вовсе (HTTP/1.1, HTTP/2, HTTP/3; исключение —
  гонка `http_version="3"`, исправлено в 0.7.0);
  okhttp-профили по-прежнему добавляют `okhttp/4.12.0`.
- `Headers |= {...}` и `Headers | {...}` не учитывали регистр и давали два заголовка.
- Предупреждения запроса (`HTTP/2-only selection ...`) указывали на внутренности
  `concurrent.futures`, а не на вызывающий код.
- **Ctrl+C не прерывал sync-запрос**: блокирующий ctypes-вызов держал главный поток до
  прихода ответа. Теперь `KeyboardInterrupt` — сразу (< 0.1 с), нативный запрос
  отменяется, соединение закрывается; то же для чтения sync-стрима.
- **Cookie на публичный суффикс** (`Domain=com`, `co.uk`, `github.io`) сохранялась и уходила
  на все сайты под суффиксом. Теперь отбрасывается (Mozilla PSL, как в браузерах); на
  самом суффикс-хосте — host-only. `Domain=` на IP-адресе — host-only.
- **Профиль `nike_android_mobile` не подключался к серверам на OpenSSL** (nginx, Apache,
  HAProxy) с TLS 1.3: `illegal_parameter` — upstream-спека шлёт GREASE key share без
  GREASE в supported_groups (RFC 8446 4.2.8). Лишний key share убирается; JA3/JA4 не
  меняются.

### Changed
- `http_version="2"` строгий (см. Fixed); `http://` остаётся HTTP/1.1 при любом
  `http_version` (h2c не поддерживается).
- Транспортные параметры сессии неизменяемы (см. Fixed); на запрос — `proxy=`,
  `timeout=`, `headers=`, `cookies=`, `header_order=`, `allow_redirects=`, `stream=`,
  `max_content_size=`.
- `session.headers` больше не содержит дубликатов имени в разном регистре:
  `Headers({"A": 1, "a": 2})` → `{"A": 2}`.

## [0.5.1] — 2026-11-19

### Fixed
- **Python 3.14: шум в логе при отмене.** Каждая отменённая async-задача (и прерванное
  чтение `aiter_bytes()`) попадала в обработчик ошибок event loop как
  `RequestCancelled exception in shielded future` с трейсбеком: в 3.14 `asyncio.shield`
  сообщает об ошибке внутреннего future после отмены внешнего. Executor-future теперь
  ожидается через `asyncio.wrap_future`; поведение отмены прежнее.

## [0.5.0] — 2026-11-19

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

## [0.4.6] — 2026-11-16

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

## [0.4.4] — 2026-11-16

### Added
- **Профиль `conscrypt_android_latest`** (псевдоним `okhttp4_conscrypt`): ClientHello
  Android-приложения, которое соединяется через системный Conscrypt с TLS 1.3: 15 шифров,
  13 расширений (с padding), без GREASE, настройки HTTP/2 как у okhttp
  (`1:4096;2:0;4:65535;6:262144`). Upstream-профили `okhttp4_android_7`–`13` предлагают
  только TLS 1.2. В этой версии профиль ещё уходил с hello Chrome (исправлено в 0.4.5).

## [0.4.3] — 2026-11-16

### Changed
- **`grease=True` расставляет GREASE как iOS CFNetwork**: пустое GREASE-расширение перед SNI
  и расширение с одним байтом `0x00` в конце, GREASE-значение первым в шифрах,
  `supported_groups`, `key_share` (с однобайтовым ключом `0x00`) и `supported_versions`.
  `grease=False` убирает GREASE отовсюду.
- Явный `tls_extension_order` выключает случайный порядок расширений, а GREASE расставляется
  после применения порядка, поэтому позиции GREASE не сдвигаются.

### Fixed
- **Сессия падала на втором хосте** с `local error: tls: internal error`: спецификация
  ClientHello была общей для рукопожатий, и второе брало key share первого. Теперь
  спецификация строится заново для каждого рукопожатия.
- JA3 в `Response.fingerprint` без GREASE, а его пятое поле — форматы точек, а не алгоритмы
  подписи.

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

## [0.3.1] — 2026-11-12

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

## [0.2.4] — 2026-10-18

### Fixed
- **Прокси-лег https:// прокси не верифицируется** (в духе curl/requests/
  браузеров): verify=False действовал только на сертификат цели, а серт
  прокси по IP без IP-SAN падал даже с verify=False. CONNECT-диалер
  теперь всегда пропускает проверку сертификата прокси; verify цели
  работает как раньше.

## [0.2.3] — 2026-10-18

### Fixed
- **`verify=False` для https://-прокси**: upstream connect.go строил
  прокси-TLS с жёстким tls.Config без InsecureSkipVerify. Для https://
  прокси клиент собирается адаптером со своим CONNECT-диалером, чей
  InsecureSkipVerify следует флагу сессии. socks5/http прокси и
  uTLS-фингерпринты цели не тронуты.

## [0.2.2] — 2026-10-18

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

## [0.2.1] — 2026-10-18

### Added
- **multipart — requests-совместимые file specs** (по мотивам
  FlorianREGAZ/Python-Tls-Client): tuple arities 2..4, голые file
  objects/bytes/str, имя из `.name`, Content-Type через mimetypes,
  процент-экранирование CR/LF/кавычек как у urllib3.

## [0.2.0] — 2026-10-18

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

## [0.1.6] — 2026-10-15

### Added
- Первый публичный пакет на PyPI: async фасад над
  bogdanfinn/tls-client v1.16.0 через cgo c-shared адаптер,
  профили upstream, CookieJar, multipart encoder, CI (тесты на
  трёх ОС + релизные wheels для py3.11–3.14).

[0.8.3]: https://github.com/october2823/yumeclient/releases/tag/v0.8.3
[0.8.2]: https://github.com/october2823/yumeclient/releases/tag/v0.8.2
[0.8.1]: https://github.com/october2823/yumeclient/releases/tag/v0.8.1
[0.8.0]: https://github.com/october2823/yumeclient/releases/tag/v0.8.0
[0.7.0]: https://github.com/october2823/yumeclient/releases/tag/v0.7.0
[0.6.0]: https://github.com/october2823/yumeclient/releases/tag/v0.6.0
[0.5.1]: https://github.com/october2823/yumeclient/releases/tag/v0.5.1
[0.5.0]: https://github.com/october2823/yumeclient/releases/tag/v0.5.0
[0.4.7]: https://github.com/october2823/yumeclient/releases/tag/v0.4.7
[0.4.6]: https://github.com/october2823/yumeclient/releases/tag/v0.4.6
[0.4.5]: https://github.com/october2823/yumeclient/releases/tag/v0.4.5
[0.4.4]: https://github.com/october2823/yumeclient/releases/tag/v0.4.4
[0.4.3]: https://github.com/october2823/yumeclient/releases/tag/v0.4.3
[0.4.2]: https://github.com/october2823/yumeclient/releases/tag/v0.4.2
[0.4.1]: https://github.com/october2823/yumeclient/releases/tag/v0.4.1
[0.4.0]: https://github.com/october2823/yumeclient/releases/tag/v0.4.0
[0.3.1]: https://github.com/october2823/yumeclient/releases/tag/v0.3.1
[0.3.0]: https://github.com/october2823/yumeclient/releases/tag/v0.3.0
[0.2.5]: https://github.com/october2823/yumeclient/releases/tag/v0.2.5
[0.2.4]: https://github.com/october2823/yumeclient/releases/tag/v0.2.4
[0.2.3]: https://pypi.org/project/yumeclient/0.2.3/
[0.2.2]: https://pypi.org/project/yumeclient/0.2.2/
[0.2.1]: https://pypi.org/project/yumeclient/0.2.1/
[0.2.0]: https://pypi.org/project/yumeclient/0.2.0/
[0.1.6]: https://pypi.org/project/yumeclient/0.1.6/
