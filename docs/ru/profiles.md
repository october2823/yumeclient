# Профили

[English](../profiles.md) | **Русский**

Профиль (`client_identifier`) задаёт всё, что сервер видит в клиенте до первого байта
ответа:

- TLS ClientHello: шифры, расширения и их порядок, группы и key shares, ALPN, GREASE, ECH;
- HTTP/2: SETTINGS, WINDOW_UPDATE, приоритеты, порядок псевдозаголовков;
- HTTP/3 и QUIC (у 53 профилей): ClientHello внутри QUIC, transport parameters, раскладку
  Initial-пакетов, SETTINGS и QPACK ([Протоколы](protocols.md#http3-и-quic));
- базовые заголовки и HTTP-слой (браузерный или okhttp).

```python
from yumeclient import Session, Profiles, ALL_IDENTIFIERS, find

Session(client_identifier="firefox_148")
Session(client_identifier=Profiles.SAFARI_IOS_18_5)
find("safari_ios")         # ['safari_ios_15_5', 'safari_ios_15_6', ..., 'safari_ios_26_0']
len(ALL_IDENTIFIERS)       # 93
```

По умолчанию — `Profiles.LATEST_CHROME` (`"chrome_152"`). `Profiles.<ИМЯ>` — константы для
всех профилей (имя в верхнем регистре). Неизвестный профиль — `SessionConfigurationError` с
похожими вариантами.

## Список

| Семейство | Профили | HTTP/3 |
|---|---|---|
| Chrome | `chrome_103` … `chrome_112`, `chrome_116_PSK`, `chrome_116_PSK_PQ`, `chrome_117`, `chrome_120`, `chrome_124`, `chrome_130_PSK`, `chrome_131`, `chrome_131_PSK`, `chrome_133`, `chrome_133_PSK`, `chrome_144`, `chrome_144_PSK`, `chrome_146`, `chrome_146_PSK`, `chrome_150`, `chrome_150_PSK`, `chrome_152`, `chrome_152_PSK` | запись браузера |
| Edge | `edge_99`, `edge_101`, `edge_131`, `edge_latest` (= 131) | Chromium той же версии |
| Brave | `brave_146`, `brave_146_PSK` | Chromium 146 |
| Opera | `opera_89`, `opera_90`, `opera_91` | запись браузера |
| Firefox | `firefox_102` … `firefox_135` (102, 104, 105, 106, 108, 110, 117, 120, 123, 132, 133, 135), `firefox_146_PSK`, `firefox_147`, `firefox_147_PSK`, `firefox_148` | запись браузера |
| Tor Browser | `tor_145` (TLS Firefox ESR 128) | нет, Tor не использует HTTP/3 |
| Safari macOS | `safari_15_6_1`, `safari_16_0`, `safari_macos_17_0`, `safari_macos_18_0`, `safari_macos_26_0` | значения библиотеки |
| Safari iOS / iPadOS | `safari_ios_15_5`, `safari_ios_15_6`, `safari_ios_16_0`, `safari_ios_17_0`, `safari_ios_18_0`, `safari_ios_18_5`, `safari_ios_26_0`, `safari_ipad_15_6` | значения библиотеки |
| Android, okhttp | `okhttp4_android_7` … `okhttp4_android_13`, `okhttp4_conscrypt`, `conscrypt_android_latest` | нет |
| Приложения | `zalando_android_mobile`, `zalando_ios_mobile`, `nike_android_mobile`, `nike_ios_mobile`, `mms_ios`, `mms_ios_1` … `_3`, `mesh_ios`, `mesh_ios_1`, `mesh_ios_2`, `mesh_android`, `mesh_android_1`, `mesh_android_2`, `confirmed_ios`, `confirmed_android` | значения библиотеки |
| Прочее | `cloudscraper` (TLS 1.2, только CBC-шифры) | нет |

Суффиксы:

- `_PSK` — ClientHello с расширением `pre_shared_key`: повторные соединения к серверу, который
  выдал тикет, возобновляют сессию TLS 1.3, как браузер при повторном визите. Без `_PSK`
  каждое соединение — полное рукопожатие.
- `_PQ` — с постквантовым обменом ключами (`chrome_116_PSK_PQ`: X25519Kyber768, как Chrome 116
  с включённым PostQuantumKyber).

83 профиля — из [tls-client](https://github.com/bogdanfinn/tls-client) v1.16.0, 10 добавлены
yumeclient: `edge_*`, `tor_145`, `safari_macos_*`, `conscrypt_android_latest`,
`okhttp4_conscrypt`. Эталонный ClientHello каждого профиля (JA3, JA4, ALPN, порядок
расширений, Akamai) лежит в `tests/fixtures/profiles.json`; тест сверяет с ним каждую сборку.

### Заметки по семействам

- **Chromium** (Chrome, Edge, Brave, Opera) перемешивает расширения ClientHello на каждом
  соединении; `random_tls_extension_order=True` (по умолчанию) делает так же. Остальные
  стеки шлют свой фиксированный порядок, и параметр на них не действует.
- **Edge** — TLS-стек Chromium (`edge_99` = hello Chrome 100, `edge_101` = Chrome 110,
  `edge_131`/`edge_latest` = Chrome 131) с заголовками Edge (`Edg/`, бренд в `Sec-CH-UA`);
  HTTP/2 SETTINGS, `priority` и HTTP/3 — Chromium той же версии.
- **Safari 17+ на macOS**: Apple не меняет ClientHello с Safari 16, поэтому JA4 у
  `safari_macos_*` такой же, как у `safari_16_0`; отличаются заголовки.
- **Android-приложения на okhttp**: `okhttp4_android_7` … `_9` — TLS 1.2 старых Android;
  `okhttp4_android_10` … `_13`, `conscrypt_android_latest` и `okhttp4_conscrypt` — один и тот же
  ClientHello современного Android (okhttp поверх системного Conscrypt, TLS 1.3): 15 шифров
  без GREASE, 13 расширений с padding до 512 байт, key share только X25519. Повторное
  соединение с тикетом шлёт resumption hello с `pre_shared_key` (выключается
  `disable_session_tickets=True`). HTTP/2 как у okhttp: Akamai `4:16777216|16711681|0|m,p,a,s`.
  Для приложения на актуальном Android берите `conscrypt_android_latest` или
  `okhttp4_conscrypt`.
- **cloudscraper** — TLS 1.2, только CBC-шифры и `encrypt_then_mac` (RFC 7366, реализован
  полностью, работает и с серверами на OpenSSL).
- Клиенты без HTTP/3 (`profiles.NO_HTTP3`: `okhttp4_*`, `okhttp4_conscrypt`,
  `conscrypt_android_latest`, `cloudscraper`, `tor_145`) с `http_version="3"` дают
  `SessionConfigurationError`: сами они QUIC не используют.

## client_os

`client_os` — `"windows"`, `"macos"`, `"android"` или `"ios"`. Он меняет только базовые
заголовки, но не TLS: ClientHello у Chrome на Windows и на Android одинаковый. Что именно
меняется у Chromium: на всех ОС — User-Agent и `sec-ch-ua-platform`; на `android` ещё
`sec-ch-ua-mobile: ?1` и нет `Upgrade-Insecure-Requests` и `Sec-Fetch-User`; на `ios` — весь
набор (Chrome на iOS работает на WebKit: User-Agent `CriOS`, без client hints и
`Sec-Fetch-*`). С записями браузеров сверены только десктопные варианты (Windows).

По умолчанию ОС выводится из профиля: `*_ios*`, `safari_ipad_*` → `ios`; `*_android*`,
`okhttp4_*`, `conscrypt_*` → `android`; `safari_15_6_1`, `safari_16_0`, `safari_macos_*` →
`macos`; остальные → `windows`.

```python
Session(client_identifier="chrome_152", client_os="android")   # Chrome на Android
Session(client_identifier="chrome_152", client_os="ios")       # CriOS: без client hints, как настоящий Chrome на iOS
```

## Базовые заголовки

Сессия начинает не с пустых заголовков, а с тех, что браузер шлёт при переходе на страницу,
в его порядке и написании. Для Chrome, Edge, Brave, Opera, Firefox и Tor они сверены с
записями самих браузеров (`tests/fixtures/browser_headers.json`) по HTTP/1.1 и HTTP/2:

- набор, порядок и значения зависят от версии: `Sec-CH-UA` по алгоритму Chromium (GREASE-бренд,
  его версия и порядок брендов меняются от версии к версии), `Accept` с
  `signed-exchange;v=b3;q=0.9` до Chrome 109 и `q=0.7` с Chrome 110, `zstd` в
  `Accept-Encoding` с Chrome 123 и Firefox 128, и т. д.;
- по HTTP/1.1 — `Host` первым, `Connection: keep-alive`, написание имён как у браузера
  (`User-Agent`, но `sec-ch-ua` у Chromium);
- по HTTP/2 и HTTP/3 имена в нижнем регистре, `Connection` не передаётся;
- Chromium с версии 124 по HTTP/2 и HTTP/3 добавляет последним `priority: u=0, i`; Firefox
  с 128 шлёт `Priority: u=0, i` по всем протоколам, а по HTTP/2 ещё `te: trailers`.

```python
from yumeclient import default_headers, profiles

default_headers("chrome_152")                 # Headers: базовые заголовки профиля
default_headers("firefox_148", "macos")
profiles.sec_ch_ua(131, "Microsoft Edge")     # Sec-CH-UA Chromium 131 с брендом Edge
```

**Safari и приложения — без записей.** Для `safari_*` и `mms_*` базовый набор — четыре
заголовка (`user-agent`, `accept`, `accept-language`, `accept-encoding`), для остальных
приложений — правдоподобный набор приложения. Они не сверены с устройствами: в них нет
`Sec-Fetch-*` и `Priority`, которые шлёт современный Safari, а имена — в нижнем регистре и
по HTTP/1.1 (Safari пишет их с заглавных букв). По HTTP/2 и HTTP/3 регистр не важен. Для
точной эмуляции задайте заголовки сами (`s.headers = {...}`, порядок — `header_order`);
User-Agent и заголовки конкретного приложения тоже передавайте сами.

## HTTP-слой okhttp

`header_style="okhttp"` собирает запрос так, как его собирает okhttp 4.x
(`BridgeInterceptor`). Это стиль по умолчанию для `okhttp4_*`, `okhttp4_conscrypt` и
`conscrypt_android_latest` (`profiles.OKHTTP_IDENTIFIERS`); у остальных — `"raw"`.

```
POST /v1/api HTTP/1.1
x-app-version: 5.2.0               ← заголовки приложения: как переданы, по порядку
user-agent: MyApp/5.2.0 (Android 14)
Content-Type: application/json     ← у запросов с телом
Content-Length: 9
Host: api.example.com
Connection: Keep-Alive
Accept-Encoding: gzip              ← если вы не задали Accept-Encoding или Range
Cookie: a=1; b=2                   ← из cookie jar
User-Agent: okhttp/4.12.0          ← если вы не задали свой user-agent
```

- Сессия начинает с пустых заголовков: у okhttp нет заголовков уровня приложения.
- `Host`, `Connection`, `Accept-Encoding`, `User-Agent`, которые вы задали, остаются на вашем
  месте и в вашем регистре; okhttp дописывает только отсутствующие. `None` убирает и их.
- `json=` — `application/json`, `data=dict` — `application/x-www-form-urlencoded`, у
  `data=bytes` неявного `Content-Type` нет (как у `RequestBody` без `MediaType`). Если
  приложение шлёт `application/json; charset=utf-8`, передайте его явно.
- Соединения переиспользуются как в `ConnectionPool` okhttp: до 5 свободных на 5 минут.
- Запрос до 8 KiB (заголовки и тело) уходит одной записью — одним TLS-record, как у Conscrypt.
- HTTP/2: тот же порядок, `Host` становится `:authority`; SETTINGS `4:16777216`,
  WINDOW_UPDATE `16711681`, псевдозаголовки `m,p,a,s`, первый stream id 3. Отличие от okhttp:
  кодер HTTP/2 разбивает `cookie` на отдельные поля, okhttp шлёт одно.
- Редиректы: 302 после POST — GET без тела и без `Referer`, 307 — с телом.
- Проверено побайтово с настоящим okhttp 4.12.0 на одном локальном сервере.

`header_style="raw"` для okhttp-профиля возвращает обычное поведение: заголовки ровно как
переданы.
