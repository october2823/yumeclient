# Свой TLS-отпечаток

Готовые [профили](profiles.md) покрывают большинство задач: у каждого — ClientHello, HTTP/2,
HTTP/3 и заголовки, снятые с настоящего клиента. Свой отпечаток нужен, когда клиента нет в
списке. Например, есть запись трафика приложения или JA3 из логов сервера. Задаётся он
параметром `ja3_string` и набором низкоуровневых параметров на этой странице.

```python
from yumeclient import Session

JA3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
       "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037,4588-29-23-24,0")

with Session(ja3_string=JA3, random_tls_extension_order=False) as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.fingerprint["ja3"] == JA3)          # True: порядок расширений как в JA3
    print(r.fingerprint["ja4"])
```

`ja3_string` нельзя совмещать с `client_identifier`: у сессии либо профиль, либо свой
отпечаток. У сессии со своим отпечатком `client_identifier == ""`. Базовые заголовки — от
`chrome_152`, если `header_style` не задан.

## Что задаёт JA3, а что нет

JA3 — это пять полей через запятую: `версия,шифры,расширения,группы,форматы точек`. Каждое
поле — список десятичных чисел через `-`. JA3 задаёт:

- версию из `ClientHello.legacy_version` (`771` = TLS 1.2, как у всех современных клиентов);
- шифры и их порядок;
- **какие** расширения есть и в каком порядке;
- группы (`supported_groups`) и форматы точек EC.

JA3 **не** задаёт содержимое большинства расширений (подписи, версии, key shares, ALPN, ALPS,
сжатие сертификатов, ECH), GREASE, параметры HTTP/2 и HTTP/3. Эти части берутся из явных
параметров, а что не задано — заполняется:

| `fill_custom_with_chrome_defaults` | Чем заполняется не заданное |
|---|---|
| `True` (по умолчанию) | значениями `Profiles.LATEST_CHROME` (`chrome_152`): signature algorithms, версии, key shares (только для групп из JA3), ALPN и ALPS, сжатие сертификатов, ECH GREASE, `trust_anchors`, HTTP/2 SETTINGS, WINDOW_UPDATE, приоритет HEADERS, порядок псевдозаголовков, отпечаток HTTP/3 и заголовок `priority` |
| `False` | общими значениями: версии TLS 1.3 и 1.2, подписи `0403,0804,0805,0806,0401,0501,0601`, ALPN `h2,http/1.1`, HTTP/2 `1:65536;2:0;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p`, HTTP/3 — значения quic-go |

Явно заданный параметр всегда важнее заполнения. Ещё два правила действуют в обоих режимах:

- расширение 27 (`compress_certificate`) без `cert_compression_algos` получает brotli,
  расширение 28 (`record_size_limit`) — значение 16385;
- если `key_share_curves` не задан и Chrome-овские key shares к JA3 не подходят, key share
  получают первые две группы из JA3. Если X25519 объявлена дальше, она тоже получает key share.
  Гибрид `X25519MLKEM768` получает key share только вместе с X25519, как у Chrome.

### Поддерживаемые расширения

В JA3 можно использовать расширения с этими id:
`0 5 10 11 13 16 18 21 22 23 27 28 34 35 41 42 43 44 45 51 13172 17513 17613 51764 65037 65281`
и GREASE (`2570`, `6682`, ..., `64250`). JA3 с другим id не построить. Ошибку бросит первый
запрос: `InvalidRequestError`, kind `configuration`, текст
`client creation failed: ja3_string: unknown extension with id N provided`.

## Параметры ClientHello

Все параметры этого раздела, кроме `server_name_overwrite`, `disable_session_tickets` и
`random_tls_extension_order`, требуют `ja3_string`. Без него — `SessionConfigurationError` («... requires ja3_string»).

| Параметр | Тип | Что делает |
|---|---|---|
| `supported_signature_algorithms` | список | расширение 13 (`signature_algorithms`) и 34 (`delegated_credentials`) |
| `supported_versions` | список | расширение 43 |
| `key_share_curves` | список | для каких групп отправить key share (расширение 51) |
| `key_share_data` | `{group: bytes}` | готовые байты key share для группы — воспроизвести запись байт в байт |
| `alpn_protocols` | список строк | расширение 16 (ALPN), например `["h2", "http/1.1"]` |
| `alps_protocols` | список строк | расширение ALPS (17513 или 17613), например `["h2"]` |
| `cert_compression_algos` | список | расширение 27 |
| `trust_anchors_payload` | `bytes` или hex | данные расширения 51764 (`trust_anchors`, Chrome 146+) с 2-байтовой длиной в начале |
| `ech_config_list` | `bytes` | настоящий ECH ([ниже](#encrypted-client-hello)) |
| `tls_extension_order` | список int | точный порядок расширений на проводе |
| `random_tls_extension_order` | `bool` | перемешивать расширения в каждом соединении, как Chrome (по умолчанию `True`; у профилей действует только для Chromium) |
| `grease` | `bool` | добавить (`True`) или убрать (`False`) GREASE |
| `psk_mode` | `"psk"` / `"no_psk"` | оставить или убрать расширение 45 (`psk_key_exchange_modes`) |
| `server_name_overwrite` | `str` | SNI вместо хоста из URL; работает и с профилями |
| `disable_session_tickets` | `bool` | не возобновлять TLS-сессии; работает и с профилями |

### Значения списков

Списки принимают имена upstream или числовые id: `int`, десятичную строку или строку с `0x`.
Неизвестное значение — `SessionConfigurationError` до сети. Upstream в этом случае молча
выбрасывал значение из hello.

| Параметр | Имена | Пример |
|---|---|---|
| `key_share_curves` | `X25519`, `X25519MLKEM768` (4588), `P256` (23), `P384` (24), `P521` (25), `X25519Kyber768` (0x6399), `X25519Kyber512D`, `X25519Kyber768Old`, `P256Kyber768`, `GREASE` | `["GREASE", "X25519MLKEM768", "X25519"]` |
| `supported_versions` | `"1.3"` (772), `"1.2"` (771), `"1.1"`, `"1.0"`, `GREASE` | `["GREASE", "1.3", "1.2"]` |
| `cert_compression_algos` | `zlib` (1), `brotli` (2), `zstd` (3) | `["brotli"]` |
| `supported_signature_algorithms` | `ECDSAWithP256AndSHA256`, `PSSWithSHA256`, `PKCS1WithSHA256`, `ECDSAWithP384AndSHA384`, `PSSWithSHA384`, `PKCS1WithSHA384`, `PSSWithSHA512`, `PKCS1WithSHA512`, `ECDSAWithP521AndSHA512`, `PKCS1WithSHA1`, `ECDSAWithSHA1`, `Ed25519`, `SHA224_RSA`, `SHA224_ECDSA` | `["ECDSAWithP256AndSHA256", 0x0804, "0401"]` |

У подписей строка из цифр без ведущего нуля читается как десятичное число (`"1027"` = 0x0403).
Строка с ведущим нулём или буквами читается как hex (`"0403"`, `"0x0804"`).

```python
with Session(ja3_string=JA3,
             supported_signature_algorithms=["ECDSAWithP256AndSHA256", "PSSWithSHA256", "PKCS1WithSHA256"],
             supported_versions=["GREASE", "1.3", "1.2"],
             key_share_curves=["GREASE", "X25519MLKEM768", "X25519"],
             alpn_protocols=["h2", "http/1.1"], alps_protocols=["h2"],
             cert_compression_algos=["brotli"]) as s:
    print(s.get("https://tls.peet.ws/api/all").fingerprint["ja4"])
```

### Порядок расширений и GREASE

- `random_tls_extension_order=True` (по умолчанию) перемешивает расширения в каждом соединении
  так, как это делает Chrome с версии 110. Для своего JA3 это тоже действует, поэтому
  `r.fingerprint["ja3"]` от соединения к соединению меняется, а JA4 нет: JA4 сортирует
  расширения. Для отпечатка не-Chromium клиента ставьте `False`.
- `tls_extension_order=[...]` ставит расширения ровно в этом порядке и отключает
  перемешивание. Расширения, которых нет в списке, идут после перечисленных.
- `grease=True` добавляет GREASE так, как его ставит Apple CFNetwork: шифр в начало, пустое
  расширение первым и расширение с байтом `0x00` последним, значение в начало групп, key share
  и версий. `grease=False` убирает все GREASE. Без параметра GREASE есть там, где он явно
  указан в JA3 или в списках, и в том, что взято у Chrome: при
  `fill_custom_with_chrome_defaults=True` список `supported_versions` копируется у Chrome
  вместе с GREASE. Сам JA3 по определению GREASE не содержит.

```python
APPLE_JA3 = ("771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-"
             "49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0")

with Session(ja3_string=APPLE_JA3, grease=True, random_tls_extension_order=False,
             fill_custom_with_chrome_defaults=False) as s:
    r = s.get("https://tls.peet.ws/api/all")
```

### Encrypted Client Hello

Без `ech_config_list` расширение 65037 из JA3 — GREASE ECH, как у Chrome без ECH-конфига:
внешний hello несёт настоящий SNI. С `ech_config_list` hello шифруется по-настоящему
(draft-ietf-tls-esni). Внешний SNI — `public_name` из конфига, настоящий хост уходит
внутри зашифрованной части.

```python
import base64

# ECHConfigList из HTTPS DNS-записи сервера (параметр ech=, base64; здесь обрезан)
ech = base64.b64decode("AEX+DQBB...")

with Session(ja3_string=JA3, ech_config_list=ech) as s:
    s.get("https://crypto.cloudflare.com/cdn-cgi/trace")
```

Требования (иначе `SessionConfigurationError`):

- значение — сериализованный `ECHConfigList` с 2-байтовой длиной в начале, ровно как в DNS;
- в JA3 есть расширение 65037;
- `http_version` не `"3"`: ECH работает только поверх TCP.

Если сервер не принял конфиг (например, ключ сменился), рукопожатие завершается ошибкой
`TLSError`. Сертификат при этом проверяется для `public_name` даже с `verify=False`.
Повторного рукопожатия с присланными сервером `retry_configs` библиотека не делает:
возьмите свежий конфиг из DNS и создайте новую сессию.

## Параметры HTTP/2

Эти параметры требуют `ja3_string`. Без них берутся значения
`chrome_152` (при `fill_custom_with_chrome_defaults=True`) или общие (при `False`).

| Параметр | Пример | На проводе |
|---|---|---|
| `h2_settings` | `{"HEADER_TABLE_SIZE": 65536, "INITIAL_WINDOW_SIZE": 6291456}` | кадр SETTINGS |
| `h2_settings_order` | `["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE"]` | порядок записей в SETTINGS |
| `connection_flow` | `15663105` | WINDOW_UPDATE для соединения после SETTINGS |
| `pseudo_header_order` | `[":method", ":authority", ":scheme", ":path"]` | порядок псевдозаголовков |
| `header_priority` | `{"streamDep": 0, "exclusive": True, "weight": 255}` | приоритет в кадре HEADERS |
| `priority_frames` | `[{"streamID": 3, "priorityParam": {"streamDep": 0, "exclusive": False, "weight": 200}}]` | кадры PRIORITY после SETTINGS (Firefox до 135) |

- Ключи `h2_settings` и элементы `h2_settings_order` принимают имена RFC 9113
  (`HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`,
  `MAX_FRAME_SIZE`, `MAX_HEADER_LIST_SIZE`), `ENABLE_CONNECT_PROTOCOL` (8),
  `NO_RFC7540_PRIORITIES` (9), имена upstream `UNKNOWN_SETTING_<id>` или сам id (`9`, `"0x4a4a"`).
  Значения — целые 0..2³²−1.
- Если `h2_settings_order` не задан, записи идут в порядке ключей словаря `h2_settings`.
- `pseudo_header_order` должен перечислить все четыре псевдозаголовка по одному разу. Формы
  `":method"`, `"method"` и `"m"` равнозначны.
- `weight` — значение с провода (0–255). В Akamai-отпечатке оно на единицу больше.

```python
FIREFOX_LIKE = dict(
    h2_settings={"HEADER_TABLE_SIZE": 65536, "INITIAL_WINDOW_SIZE": 131072, "MAX_FRAME_SIZE": 16384,
                 "NO_RFC7540_PRIORITIES": 1},
    h2_settings_order=["HEADER_TABLE_SIZE", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "NO_RFC7540_PRIORITIES"],
    connection_flow=12517377,
    pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
)

with Session(ja3_string=JA3, http_version="2", **FIREFOX_LIKE) as s:
    print(s.get("https://tls.peet.ws/api/all").fingerprint["akamai_fingerprint"])
    # 1:65536;4:131072;5:16384;9:1|12517377|0|m,p,a,s
```

## HTTP/3

Свой JA3 описывает TCP ClientHello. QUIC-рукопожатие у браузеров другое: только TLS 1.3,
транспортные параметры, без части TCP-расширений. Поэтому JA3 его не задаёт.

- `fill_custom_with_chrome_defaults=True`: с `http_version="3"` сессия использует весь
  HTTP/3-отпечаток `chrome_152`. Это его QUIC ClientHello, транспортные параметры, SETTINGS и
  приоритеты.
- `False`: значения quic-go по умолчанию. Этот отпечаток не похож ни на один браузер.
- JA3 с `X25519MLKEM768` (4588), как у современных Chrome, HTTP/3 не мешает: QUIC ClientHello
  берётся не из JA3. До 0.8.1 такая сессия молча оставалась на TCP.

Если нужен HTTP/3 конкретного браузера, используйте его профиль. Список профилей с записанным
HTTP/3 — `yumeclient.profiles.HTTP3_FINGERPRINTS`, подробнее в разделе [Протоколы](protocols.md#http3-и-quic).

## Как воспроизвести запись

1. Возьмите JA3, JA4 и Akamai-отпечаток клиента: из логов сервера, из `tls.peet.ws` или из
   своей записи (Wireshark 4.2+ показывает JA3 и JA4 у ClientHello).
2. Создайте сессию с `ja3_string`. Подберите `fill_custom_with_chrome_defaults`: `True` для
   Chromium-клиентов, `False` для остальных.
3. Задайте содержимое расширений: подписи, версии, key shares, ALPN, ALPS. Для не-Chromium
   клиента выключите `random_tls_extension_order`.
4. Сравните результат с целью через `yumeclient.fingerprint_diff(r.fingerprint, target)`
   ([Диагностика](diagnostics.md)). Отпечаток в `r.fingerprint` посчитан по байтам, которые
   ушли в сеть.
5. Сохраните настройку через `s.export_profile()` и создавайте сессии через `Session.from_profile(...)`.

## Ошибки конфигурации

| Ситуация | Исключение |
|---|---|
| `ja3_string` вместе с `client_identifier` | `SessionConfigurationError` до сети |
| параметр из этой страницы без `ja3_string` | `SessionConfigurationError` до сети |
| неизвестное имя группы, версии, подписи, алгоритма сжатия, настройки HTTP/2 | `SessionConfigurationError` до сети |
| неверный `pseudo_header_order`, `ech_config_list`, `trust_anchors_payload` | `SessionConfigurationError` до сети |
| JA3 с неподдерживаемым расширением или с ошибкой формата | `InvalidRequestError` (kind `configuration`) на первом запросе |
| сервер отверг hello (например, key share для группы, которую не поддерживает uTLS) | `TLSError` |

Известное ограничение: если `X25519MLKEM768` (4588) есть в группах, а key share для неё нет,
сервер с ML-KEM ответит HelloRetryRequest. uTLS на такой ответ выдаёт ошибку
`tls: CurvePreferences includes unsupported curve`. Отправляйте key share для 4588 вместе с
X25519, как Chrome; так делает и заполнение по умолчанию.
