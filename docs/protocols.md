# Протоколы

`http_version` задаёт, какие версии HTTP сессия может использовать. Протокол после
рукопожатия выбирает сервер из списка ALPN, который клиент предложил в ClientHello
(RFC 7301). Если сервер выбрал версию, которую сессия не разрешает, библиотека не понижает
её молча, а закрывает соединение до отправки запроса и бросает `ProtocolError`.

| Значение | ALPN в ClientHello | Что происходит |
|---|---|---|
| `"auto"` (по умолчанию) | как у профиля, обычно `h2, http/1.1` | HTTP/2 или HTTP/1.1 — что выбрал сервер, как браузер |
| `"2"` | как у профиля | только HTTP/2. Сервер выбрал `http/1.1` или не прислал ALPN — `ProtocolError`, запрос не отправлен. По `http://` — h2c ([ниже](#http-без-tls)) |
| `"1.1"` или `force_http1=True` | переписан на `http/1.1` | HTTP/1.1; ClientHello уже не как у браузера (другой JA4) |
| `"1.1"` и `keep_alpn=True` | как у профиля | HTTP/1.1 с ClientHello браузера. Сервер выбрал `h2` — `ProtocolError`, ни одного байта HTTP не отправлено |
| `"3"` | как у профиля + QUIC | гонка HTTP/3 и TCP, как в Chrome ([ниже](#http3-и-quic)) |

Также принимаются `1`, `2`, `3`, `"h1"`, `"h2"`, `"h3"`, `"quic"`, `None` (= `"auto"`).

```python
from yumeclient import Session, ProtocolError

with Session(http_version="2") as s:
    r = s.get("https://httpbin.org/get")
    print(r.http_version)                                  # '2'
    print(r.connection_info["alpn_negotiated"])            # 'h2'

with Session(http_version="1.1", keep_alpn=True) as s:   # HTTP/1.1, но JA4 браузера
    try:
        s.get("https://www.google.com/")
    except ProtocolError:
        pass                                               # сервер выбрал h2
```

`r.used_protocol` и `r.connection_info["http_protocol"]` всегда совпадают;
`connection_info["alpn_negotiated"]` — что выбрал сервер.

## Противоречивые настройки

Отклоняются в конструкторе `SessionConfigurationError`, до сети:

- `force_http1=True` вместе с `http_version="2"` или `"3"`; `disable_http3=True` с `"3"`;
- `keep_alpn=True` без `http_version="1.1"`, вместе с `udp_proxy` или с `alpn_protocols` без
  `http/1.1`;
- `alpn_protocols` (свой JA3) с принудительным HTTP/1.1, если список не `["http/1.1"]`
  (ClientHello предложил бы другое; сохранить список — `keep_alpn=True`);
- `http_version="2"` с `alpn_protocols` без `h2`; пустой `alpn_protocols`;
- `http_version="3"` с прокси, который не `socks5://`;
- `http_version="3"` с клиентом без HTTP/3 (`profiles.NO_HTTP3`).

## HTTP без TLS

По `http://` ALPN нет. При `"auto"`, `"1.1"` и `"3"` запросы идут по HTTP/1.1 — браузеры по
открытому HTTP используют только его. При `http_version="2"` — HTTP/2 с prior knowledge (h2c,
RFC 9113 §3.3, как `Protocol.H2_PRIOR_KNOWLEDGE` в OkHttp или gRPC): клиент сразу шлёт
preface HTTP/2. Сервер, который не говорит h2c, — `ProtocolError`.

Запросы по `http://` идут через тот же транспорт сессии, что и `https://`: тот же прокси,
`local_address`, cookie. Редиректы между `http://` и `https://` остаются в сессии, и каждый
`https://`-хоп — с TLS профиля.

## HTTP/2

HTTP/2-параметры берутся из профиля: SETTINGS и их порядок, WINDOW_UPDATE соединения,
PRIORITY-фреймы, приоритет в HEADERS, порядок псевдозаголовков. Вместе они дают Akamai-отпечаток
(`r.fingerprint["akamai_fingerprint"]`). Для Chrome:

```
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

Переопределить их можно только для своего TLS-отпечатка (`ja3_string` + `h2_settings` и
т. д., [Свой TLS-отпечаток](custom-tls.md)).

## HTTP/3 и QUIC

```python
with Session(client_identifier="chrome_152", http_version="3") as s:
    r = s.get("https://cloudflare-quic.com/")
    print(r.http_version)          # '3', если сервер поддерживает HTTP/3
```

### Гонка соединений

С `http_version="3"` сессия делает то же, что Chrome при известном Alt-Svc:

1. Запускает QUIC-рукопожатие; через 300 мс (или сразу, если QUIC упал) — параллельно TCP.
2. Запрос уходит **один раз** — по протоколу, который первым установил соединение (или по
   уже открытому соединению). Выигравший протокол запоминается для хоста.
3. После ошибки запомненного протокола следующие запросы снова устраивают гонку на новых
   соединениях. У HTTP/3 это относится и к таймауту или отмене (молчащий UDP), у HTTP/1.1 и
   HTTP/2 таймаут или отмена протокол и пул не сбрасывают.
4. Упавший запрос повторяется гонкой, если он идемпотентный (GET, HEAD, OPTIONS, TRACE или с
   заголовком `Idempotency-Key`) и время ещё есть, или если он точно не был отправлен.

### Сломанный HTTP/3

Если HTTP/3-соединение закрылось с кодом ошибки HTTP/3, QPACK или QUIC (сервером или из-за
нарушения протокола), HTTP/3 для этого адреса помечается сломанным, как в Chrome: на 5 минут,
при повторах вдвое дольше, до 48 часов. Запрос повторяется по TCP, следующие идут по TCP
сразу.

Не считаются поломкой: закрытие без ошибки (`NO_ERROR`, `H3_NO_ERROR`, неизвестные коды),
сброс сервером одного запроса, слишком большой ответ, таймауты, соединение, которое сервер
забыл (idle timeout, stateless reset). Следующий запрос просто идёт по новому
QUIC-соединению.

### Отпечаток QUIC и HTTP/3

У 53 профилей (`profiles.HTTP3_FINGERPRINTS`) QUIC и HTTP/3 воспроизводят записи самих
браузеров — Chrome 103–152, Opera 89–91, Firefox 102–148; Edge и Brave — Chromium той же
версии:

- **ClientHello внутри QUIC.** Он отличается от TCP-шного: только TLS 1.3, у Chromium без
  GREASE. Перемешивание расширений и ECH GREASE — как у браузера.
- **Transport parameters**: набор, значения, порядок, GREASE-параметр, `version_information`,
  `google_connection_options`, `google_initial_rtt` на повторных соединениях.
- **Initial-пакеты**: длины Connection ID, номер первого пакета, размер датаграммы, способ
  заполнения (PADDING-фреймы или нули после пакета у Firefox), раскладка ClientHello по
  пакетам (chaos protection Chromium, SNI slicing Firefox 146+).
- **HTTP/3**: SETTINGS и их порядок, GREASE-фрейм, порядок и типы QPACK-потоков,
  PRIORITY_UPDATE, заголовок `priority`, порядок псевдозаголовков.
- **QPACK**: динамическая таблица декодера, как у браузеров (без неё запросы к серверам,
  которые сжимают заголовки через таблицу, падали — например, google.com).

У профилей без записи (Safari, iOS- и Android-приложения) `http_version="3"` работает, но с
предупреждением: QUIC и HTTP/3 у них — значения библиотеки, а не устройства. Свой JA3 с
Chrome-заполнением берёт QUIC и HTTP/3 того Chrome.

Как записать браузер и добавить запись — [Разработка](development.md#отпечатки-http3).

### Прокси и HTTP/3

QUIC идёт поверх UDP, поэтому HTTP/3 возможен только через SOCKS5 (UDP ASSOCIATE):
`proxy="socks5://..."` или отдельный `udp_proxy=` (`socks5://` или `socks5h://`). С
HTTP-прокси без `udp_proxy` `http_version="3"` — `SessionConfigurationError`. У ответов по
HTTP/3 (с прокси и без) `r.fingerprint["source"]` равен `"config"`: QUIC ClientHello не
записывается, значения посчитаны из конфигурации.

## Таймауты по протоколам

Стадии таймаутов одинаковы для HTTP/1.1, HTTP/2 и HTTP/3; у HTTP/3 `connect` — это
QUIC-рукопожатие. В гонке TCP стартует через 300 мс, поэтому `connect` меньше 300 мс
кончается раньше, чем TCP успеет начать. Подробнее — [Таймауты](timeouts-and-errors.md).

## Если сервер выбирает не тот протокол

Если приложению сервер отдаёт `http/1.1`, а вам — `h2` с тем же ClientHello, значит, сервер
смотрит на что-то ещё: клиентская настройка этого не исправит. Сравните
`r.fingerprint["alpn_offered"]` и `connection_info["alpn_negotiated"]` с эталоном. ALPN
ответа сервера в TLS 1.3 зашифрован; в записи tshark он виден только с keylog:

```sh
tshark -o tls.keylog_file:keys.log -Y "tls.handshake.type==8" -T fields -e tls.handshake.extensions_alpn_str
```
