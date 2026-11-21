# Прокси

Прокси задаётся URL'ом: для всей сессии (`Session(proxy=...)`) или для одного запроса
(`s.get(..., proxy=...)`).

```python
from yumeclient import Session

with Session(proxy="http://user:pass@203.0.113.10:3128") as s:
    print(s.get("https://httpbin.org/ip").json())
```

## Схемы

| URL | Протокол | DNS-имя цели | Аутентификация |
|---|---|---|---|
| `http://host:port` | HTTP-прокси: `CONNECT` для `https://`, absolute-form для `http://` | у прокси | Basic (`Proxy-Authorization`) |
| `https://host:port` | то же поверх TLS до прокси | у прокси | Basic |
| `socks5://host:port` | SOCKS5 (RFC 1928) | у прокси (имя уходит прокси) | логин/пароль (RFC 1929) |
| `socks5h://host:port` | то же, что `socks5://` | у прокси | логин/пароль |
| `socks4://host:port` | SOCKS4 | **локально**, прокси получает IPv4 | нет |
| `socks4a://host:port` | SOCKS4a | у прокси | нет |

- Логин и пароль — в URL: `scheme://user:pass@host:port`. Спецсимволы кодируйте
  percent-encoding'ом: пароль `p@ss` пишется `p%40ss` (`urllib.parse.quote(password, safe="")`).
- `socks5://` и `socks5h://` ведут себя одинаково: имя хоста всегда отправляется прокси, и
  запроса к локальному DNS нет. Исключение — HTTP/3 через SOCKS5 (см. ниже).
- Порт обязателен для SOCKS. Для `http://` и `https://` без порта берутся 80 и 443.
- Переменные окружения `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` не читаются.
  Прокси используется только тогда, когда передан явно.

URL проверяется при создании сессии и в каждом запросе с `proxy=`. Ошибка —
`SessionConfigurationError` (подкласс `ValueError`), запрос в сеть не уходит. Учётные данные
в тексте ошибки скрыты.

```text
proxy '127.0.0.1:8080' has no scheme; write it as http://host:port (or https://, socks5://, ...)
proxy 'ftp://127.0.0.1:21': unsupported scheme 'ftp'; use one of http://, https://, socks5://, ...
proxy 'socks5://127.0.0.1': a SOCKS proxy needs a port (usually 1080)
```

До 0.8.1 такие ошибки появлялись только при первом запросе, как `InvalidRequestError` с
текстом `client creation failed: ...`.

## HTTP- и HTTPS-прокси

- **`https://` цели.** Клиент открывает туннель `CONNECT example.com:443 HTTP/1.1`. В нём
  указано имя хоста, а не IP. TLS-рукопожатие с сервером идёт внутри туннеля с отпечатком
  профиля: прокси видит ClientHello так же, как его увидел бы сервер.
- **`http://` цели.** Запрос уходит прокси целиком: `GET http://example.com/path HTTP/1.1`.
  Заголовки и их порядок — профиля.
- **Авторизация.** Если в URL есть логин и пароль, заголовок `Proxy-Authorization: Basic ...`
  отправляется сразу, без ожидания ответа 407. Digest, NTLM и Negotiate не поддерживаются.
- **Ответ 407.** При `https://` цели туннель не открывается, и запрос падает с `ProxyError`:
  `Proxy responded with non 200 code: 407 Proxy Authentication Required`. При `http://` цели
  407 приходит обычным ответом: `r.status_code == 407`, как в requests.
- **Сертификат HTTPS-прокси не проверяется** — ни при `verify=True`, ни при `verify=False`.
  Так поступает большинство клиентов: прокси выбирает оператор, а их сертификаты часто
  выписаны на имя, а не на IP. Сертификат целевого сервера проверяется по `verify` как обычно.
  До 0.8.1 запросы к `http://` через HTTPS-прокси, наоборот, проверяли его сертификат и
  падали на самоподписанном.

## SOCKS

- **SOCKS5** поддерживает анонимный вход и логин/пароль. При неверном пароле —
  `ProxyError`: `username/password authentication failed`.
- **SOCKS4** передаёт прокси только IPv4-адрес: имя разрешается локальным DNS. Если имя не
  должен видеть локальный резолвер, используйте `socks4a://` или `socks5://`. Логин в URL
  SOCKS4 игнорируется: поле user id отправляется пустым.
- **Через SOCKS ходит и `http://`.** До 0.8.0 `http://` через `socks5h://` и `socks4://`
  уходил на прокси открытым HTTP-запросом и не работал.

## HTTP/3 через прокси

QUIC работает поверх UDP, а UDP туннелирует только SOCKS5 (команда UDP ASSOCIATE).

| Настройки | TCP (HTTP/1.1, HTTP/2) | QUIC (HTTP/3) |
|---|---|---|
| `proxy="socks5://..."` | через прокси | через UDP-relay того же прокси |
| `proxy="http://..."` | через прокси | ошибка конфигурации при `http_version="3"` |
| `proxy="http://...", udp_proxy="socks5://..."` | через `proxy` | через `udp_proxy` |
| `udp_proxy="socks5://..."` без `proxy` | напрямую | через `udp_proxy` |

```python
from yumeclient import Session

with Session(client_identifier="chrome_144", http_version="3",
             proxy="http://user:pass@203.0.113.10:3128",       # TCP-гонка и запасной HTTP/2
             udp_proxy="socks5://user:pass@203.0.113.20:1080",  # QUIC
             ) as s:
    r = s.get("https://cloudflare-quic.com/")
    print(r.http_version)
```

- `udp_proxy` принимает только `socks5://` и `socks5h://`. Он несовместим с `keep_alpn`.
- **DNS при QUIC через SOCKS5 — локальный.** UDP-relay принимает адрес назначения, поэтому
  имя хоста разрешается на вашей машине, а прокси получает IP. TCP-соединения той же сессии
  по-прежнему отдают имя прокси.
- **Отпечаток QUIC через прокси такой же, как без прокси.** Это касается длины connection ID,
  транспортных параметров и первого пакета. До 0.8.1 через SOCKS5 QUIC шёл стандартным
  дайлером: 4-байтовый source connection ID (у Chrome — 0), без `google_initial_rtt`, без
  событий для стадийных таймаутов.
- Профили без HTTP/3 (`NO_HTTP3`: OkHttp, conscrypt, cloudscraper, tor) не используют QUIC и
  с прокси тоже.

## Прокси на один запрос

`proxy=` в запросе выбирает прокси только для этого запроса:

| `proxy=` | Что происходит |
|---|---|
| не передан или `None` | прокси сессии (или напрямую, если у сессии его нет) |
| `"socks5://..."`, `"http://..."` | указанный прокси |
| `""` | **напрямую**, даже если у сессии есть прокси |

```python
with Session(proxy="socks5://127.0.0.1:1080") as s:
    s.get("https://example.com/")                          # через 127.0.0.1:1080
    s.get("https://example.com/", proxy="http://10.0.0.2:3128")  # через другой прокси
    s.get("https://example.com/", proxy="")                # без прокси
```

Для каждого прокси у сессии свой нативный клиент со своими соединениями. TLS-сессии,
кэш протокола HTTP/3 и пул соединений не смешиваются между прокси. Cookie общие: jar один
на сессию. Списка исключений (`NO_PROXY`) нет — используйте `proxy=""` в нужных запросах.

## Локальный адрес

`local_address="IP:порт"` привязывает исходящие TCP-соединения к локальному адресу. Порт `0`
означает любой свободный. С прокси привязывается соединение до прокси. Работает со всеми
схемами прокси.

```python
with Session(local_address="192.0.2.15:0") as s:
    s.get("https://example.com/")
```

## Диагностика

- `r.connection_info["remote_address"]` — адрес, с которым установлено соединение. С прокси
  это адрес прокси.
- `r.connection_info["timings"]["proxy"]` — время установки туннеля (`CONNECT` или SOCKS-рукопожатие)
  в секундах; без прокси — `None`.
- Ошибки прокси — `ProxyError` (`kind="proxy"`, `stage="connect"`, `retryable=True`): прокси не
  отвечает, отказал в соединении, не прошла аутентификация, туннель не открылся. Текст
  исходной ошибки — в `str(exc)` (учётные данные скрыты) и `exc.__cause__`.

```python
from yumeclient import ProxyError, Session

try:
    with Session(proxy="http://127.0.0.1:1") as s:
        s.get("https://example.com/")
except ProxyError as exc:
    print(exc.kind, exc.stage, exc.retryable)   # proxy connect True
```
