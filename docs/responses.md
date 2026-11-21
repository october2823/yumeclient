# Ответы и стриминг

```python
r = s.get("https://httpbin.org/json")
r.status_code        # 200
r.ok                 # True для 200–399
r["Content-Type"]    # 'application/json'
r.json()             # dict
r.http_version       # '2'
r.elapsed            # 0.148 (секунды)
```

## Атрибуты `Response`

| Атрибут | Тип | Описание |
|---|---|---|
| `status_code`, `status` | `int` | код ответа |
| `ok` | `bool` | `200 <= status_code < 400` |
| `headers` | `dict[str, list[str]]` | заголовки ответа: имя → список значений. Значения — как прислал сервер, имена приведены к каноничному виду (`x-lower-case` → `X-Lower-Case`) |
| `r["Имя"]` | `str` | значения заголовка через `", "`, без учёта регистра; `KeyError`, если его нет |
| `cookies` | `dict[str, str]` | cookie для конечного URL после обмена: подходящие cookie сессии и запроса плюс выставленные ответами (`Set-Cookie` всех хопов), без удалённых. Весь jar — в `s.cookies` |
| `content` | `bytes` | тело, уже распакованное (gzip, deflate, br, zstd) |
| `text` | `str` | тело как текст: кодировка из `charset` в `Content-Type`, иначе `encoding`; ошибки заменяются |
| `encoding` | `str` | кодировка для `text`, если сервер её не указал; по умолчанию `"utf-8"`, можно присвоить |
| `json()` | | `json.loads(r.text)`; невалидный JSON — `json.JSONDecodeError` (`ValueError`) |
| `url` | `str` | итоговый URL после редиректов |
| `history` | `list[Response]` | пройденные редиректы, от первого к последнему |
| `is_redirect` | `bool` | ответ 3xx с `Location` (когда редирект не выполнялся) |
| `elapsed` | `float` | длительность запроса в секундах, включая редиректы; без `stream=True` — вместе с чтением тела, со `stream=True` — до заголовков |
| `http_version` | `str` | `"1.1"`, `"2"` или `"3"` |
| `used_protocol` | `str` | строка протокола транспорта: `"HTTP/1.1"`, `"HTTP/2.0"`, `"HTTP/3.0"` |
| `connection_info` | `dict` | соединение, TLS, адреса, тайминги ([ниже](#connection_info)) |
| `fingerprint` | `dict` | отпечаток того, что ушло в сеть ([ниже](#fingerprint)) |
| `request_id` | `str` | идентификатор запроса в нативном слое (есть и у исключений) |
| `raise_for_status()` | | `HTTPStatusError` для кодов вне 200–399; ответ — в `e.response` |
| `trace()` | | описание запроса без секретов ([Диагностика](diagnostics.md#трейс-запроса)) |

`repr(r)` — `<Response [200] 148ms>`.

`r.headers` содержит заголовки в том виде, в каком их прислал сервер, включая
`Content-Encoding` и `Content-Length` сжатого тела, а `r.content` уже распакован — так же, как
в `requests`. Повторно распаковывать тело не нужно.

## История редиректов

```python
r = s.get("https://httpbin.org/redirect/2")
[h.status_code for h in r.history]   # [302, 302]
r.history[0].headers["Location"]
r.url                                # https://httpbin.org/get
```

У каждого элемента `history`: `status_code`, `headers`, `cookies` (его `Set-Cookie`), `url`,
`used_protocol`, `elapsed` (от отправки этого хопа до его заголовков) и `content` — тело
редиректа, распакованное.

Тело редиректа читается, только пока оно идёт быстро: если оно больше 64 KiB, сервер молчит
дольше 0.5 с (или дольше `read`-таймаута, если он меньше), чтение занимает больше 2 с или
тело не распаковывается — `content` будет `b""`, а редирект всё равно выполнится.

При `allow_redirects=False` или без редиректов `history == []`.

## connection_info

```python
{
    "connection_reused": False,
    "alpn_negotiated": "h2",
    "tls_version": "1.3",
    "tls_cipher": "TLS_AES_128_GCM_SHA256",
    "tls_resumed": False,
    "http_protocol": "HTTP/2.0",
    "remote_address": "203.0.113.5:443",
    "local_address": "192.168.1.10:51123",
    "timings": {"redirects": 0.0, "connect": 0.081, "proxy": None, "write": 0.0002,
                "wait": 0.064, "body": 0.003, "first_byte": 0.145, "total": 0.148},
}
```

- Всё относится к последнему хопу (после редиректов).
- `connection_reused` — запрос ушёл по уже открытому соединению (keep-alive, HTTP/2 или
  HTTP/3 мультиплексирование).
- `alpn_negotiated` — что выбрал сервер (`""` — ALPN не прислан). У `http://` и у HTTP/3
  TLS-полей и `alpn_negotiated` нет: QUIC-рукопожатие не записывается.
- `remote_address` через прокси — адрес прокси.

Тайминги, секунды:

| Поле | Что измеряет |
|---|---|
| `redirects` | время до начала последнего хопа: предыдущие хопы и подготовка запроса |
| `connect` | DNS, прокси, TCP (или QUIC) и TLS последнего хопа; `None`, если соединение переиспользовано |
| `proxy` | часть `connect`, ушедшая на путь через прокси (TCP до прокси, CONNECT или SOCKS); `None` без прокси или при переиспользовании |
| `write` | отправка заголовков и тела |
| `wait` | ожидание заголовков ответа после отправки |
| `body` | чтение тела |
| `first_byte` | от начала запроса до заголовков ответа |
| `total` | весь запрос; `redirects + connect + write + wait + body` |

## fingerprint

`r.fingerprint` — отпечаток соединения, по которому ушёл запрос. Он посчитан по байтам
ClientHello, которые реально ушли в сокет, и совпадает с тем, что покажут Wireshark или
tshark (`tls.handshake.ja3`, `tls.handshake.ja4`).

| Поле | Описание |
|---|---|
| `ja3`, `ja3_hash_md5` | JA3 и его MD5 |
| `ja4`, `ja4_r` | JA4 (FoxIO) и его raw-форма |
| `tls_extensions` | расширения ClientHello по порядку (GREASE включены) |
| `alpn_offered` | ALPN, предложенный в ClientHello |
| `akamai_fingerprint`, `akamai_hash_sha256_96` | отпечаток HTTP/2 (SETTINGS, WINDOW_UPDATE, PRIORITY, псевдозаголовки) |
| `http_protocol` | протокол ответа |
| `connection_reused` | запрос ушёл по открытому соединению |
| `request_headers` | `[[имя, значение], ...]` — заголовки в том порядке и регистре, в каком транспорт записал их в соединение; у HTTP/2 и HTTP/3 с псевдозаголовками |
| `source` | `"wire"` — посчитано по записанному TCP ClientHello; `"config"` — его не было (запрос по `http://`, любой ответ по HTTP/3), значения посчитаны из конфигурации |

У переиспользованного соединения ClientHello не было — поля TLS относятся к рукопожатию, с
которого началось это соединение. `s._core.last_fingerprint` хранит отпечаток последнего
запроса сессии.

Сравнить отпечаток с эталоном — `fingerprint_diff()` ([Диагностика](diagnostics.md)).

## Потоковое чтение

С `stream=True` запрос возвращает ответ, как только пришли заголовки, а тело остаётся в
нативном слое, пока вы его не прочитаете. Память ограничена размером куска.

```python
with s.get(url, stream=True) as r:
    r.raise_for_status()
    with open("file.bin", "wb") as f:
        for chunk in r.iter_bytes(256 * 1024):
            f.write(chunk)
```

```python
async with AsyncSession() as s:
    async with await s.get(url, stream=True) as r:
        async for chunk in r.aiter_bytes():
            ...
```

| Sync | Async | |
|---|---|---|
| `r.iter_bytes(chunk_size=65536)` | `r.aiter_bytes(chunk_size=65536)` | куски до `chunk_size` байт |
| `r.iter_content(chunk_size, decode_unicode=False)` | | как в `requests`; `decode_unicode=True` — строки |
| `r.read()` | `await r.aread()` | дочитать всё в `r.content` |
| `r.close()` | `await r.aclose()` | закрыть, не дочитывая |
| `with r:` | `async with r:` | закрыть на выходе |
| `r.is_stream_consumed` | | тело прочитано до конца или закрыто |

- Выход из цикла `iter_bytes`/`aiter_bytes` (в том числе `break` и исключение) закрывает
  поток. Повторное чтение закрытого потока — `StreamClosed`.
- У sync-ответа обращение к `r.content` дочитывает тело. У async-ответа сначала нужен
  `await r.aread()`, иначе `r.content` бросает `StreamClosed` (`kind="stream_not_read"`).
- `total`-таймаут при `stream=True` кончается на заголовках; тело дальше ограничено
  `read`-таймаутом как паузой между кусками ([Таймауты](timeouts-and-errors.md)).
- `max_content_size` действует и на поток: превышение — `ResponseTooLarge` во время чтения.
- Закрытие сессии закрывает её открытые потоки. Брошенный поток освобождается сборщиком
  мусора, но соединение до этого занято — закрывайте явно.
