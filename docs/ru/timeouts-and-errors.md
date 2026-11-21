# Таймауты, ошибки, отмена

[English](../timeouts-and-errors.md) | **Русский**

## Таймауты

Таймаут задаётся для сессии (`Session(timeout=...)`) и переопределяется для одного запроса
(`s.get(url, timeout=...)`). Он не входит в транспортные настройки сессии, поэтому смена таймаута
в запросе не создаёт новых соединений.

| Значение | Что значит |
|---|---|
| `30` (по умолчанию) | `total` = 30 с на весь обмен |
| число `x` | `total` = `x` |
| `(connect, read)` | лимиты стадий без общего лимита; `None` в кортеже — без лимита для этой стадии |
| `TimeoutConfig(total=..., connect=..., read=..., write=...)` | любые сочетания |
| `None` | без лимитов |

Значения — положительные числа в секундах. `0`, отрицательные числа, строки и кортеж
другой длины дают `SessionConfigurationError`, например
`timeout total must be a positive number or None, got 0`.

```python
from yumeclient import Session, TimeoutConfig

with Session(timeout=TimeoutConfig(connect=5, read=30, total=120)) as s:
    s.get("https://httpbin.org/get")
    s.get("https://httpbin.org/delay/2", timeout=3)               # только для этого запроса
    s.get("https://httpbin.org/drip?duration=20", timeout=(5, 2))  # пауза в теле > 2 с — ошибка
```

### Стадии

| Стадия | Что ограничивает |
|---|---|
| `connect` | DNS, соединение с прокси и CONNECT или SOCKS-рукопожатие, TCP, TLS. Отдельно для каждого нового соединения, в том числе на хопах редиректа |
| `write` | отправку заголовков и тела запроса |
| `read` | ожидание заголовков ответа и **паузу** между кусками тела. Медленный, но живой ответ не обрывается |
| `total` | весь обмен, включая редиректы и чтение тела |

- `stream=True`: `total` действует до получения заголовков. Дальше тело ограничено паузой
  `read`, а если `read` не задан — паузой длиной `total`. Общая длительность скачивания не
  ограничена.
- Стадии одинаковы для HTTP/1.1, HTTP/2 и HTTP/3. У HTTP/3 `connect` — это QUIC-рукопожатие.
  В гонке HTTP/3 с TCP (`http_version="3"`) TCP-соединение стартует через 300 мс, поэтому
  `connect` меньше 300 мс истекает раньше, чем TCP успеет начаться.
- Переиспользованное соединение не проходит `connect`: таймаут стадии считается только
  при открытии нового соединения.
- Даже без таймаутов открытие TCP-соединения (вместе с DNS) и обмен CONNECT с HTTP(S)-прокси
  занимают не больше 240 с каждый; `connect` больше 240 с эти шаги не удлиняет.

Какая стадия истекла, видно по исключению: `ConnectTimeout`, `WriteTimeout`, `ReadTimeout`
(атрибут `stage`: `read` — ждали заголовки, `body` — ждали следующий кусок тела) или `Timeout`
для `total`.

## Иерархия исключений

```
RuntimeError
└── TLSClientError                         ошибки библиотеки, базовый класс
    ├── SessionConfigurationError (+ ValueError)   неверные параметры сессии, до сети
    └── RequestError                       ошибка конкретного запроса
        ├── InvalidRequestError (+ ValueError)     запрос отклонён до сети
        ├── ConnectError (+ ConnectionError)       соединение не установлено
        │   ├── ProxyError
        │   ├── TLSError
        │   ├── ProtocolError
        │   └── ConnectTimeout (+ Timeout)
        ├── ConnectionClosed (+ ConnectionError)   соединение оборвалось после установки
        ├── Timeout (+ TimeoutError)
        │   ├── ConnectTimeout
        │   ├── ReadTimeout
        │   └── WriteTimeout
        ├── RequestCancelled                       запрос отменён
        ├── ResponseTooLarge                       тело больше max_content_size
        ├── TooManyRedirects                       больше 20 редиректов
        ├── StreamClosed                           поток уже прочитан или закрыт
        └── HTTPStatusError                        Response.raise_for_status()
```

Благодаря встроенным базовым классам код, написанный под стандартные исключения, тоже
работает: `except TimeoutError`, `except ConnectionError`, `except ValueError`.

### `kind` и когда возникает

| Класс | `kind` | Когда |
|---|---|---|
| `ConnectError` | `connect`, `dns` | соединение отклонено, хост не найден, сеть недоступна |
| `ProxyError` | `proxy` | прокси недоступен, отказал в CONNECT/SOCKS, неверная авторизация прокси |
| `TLSError` | `tls` | рукопожатие не удалось, сертификат не прошёл проверку, сервер отверг ClientHello |
| `ProtocolError` | `protocol` | сервер выбрал не тот протокол: `http_version="2"` → HTTP/1.1, `keep_alpn` → h2, h2c не поддерживается. Запрос не отправлен |
| `ConnectionClosed` | `connection_closed` | соединение закрыто или сброшено после установки, сервер оборвал ответ |
| `Timeout` | `timeout` | истёк `total` |
| `ConnectTimeout` | `connect_timeout` | истёк `connect` |
| `ReadTimeout` | `read_timeout` | истёк `read` |
| `WriteTimeout` | `write_timeout` | истёк `write` |
| `RequestCancelled` | `cancelled` | `close(grace=...)` закрыл сессию, пока запрос был в полёте. Отменённая задача asyncio получает `asyncio.CancelledError`, а не это исключение |
| `ResponseTooLarge` | `body_too_large` | распакованное тело больше `max_content_size` |
| `TooManyRedirects` | `too_many_redirects` | больше 20 редиректов подряд |
| `InvalidRequestError` | `invalid_request`, `configuration` | неверный URL, метод, заголовок; сессию нельзя собрать (например, JA3 с неподдерживаемым расширением) |
| `StreamClosed` | `stream_closed`, `stream_not_read` | чтение уже закрытого потока; `r.content` у async-стрима до `await r.aread()` |
| `HTTPStatusError` | `http_status` | `r.raise_for_status()` при статусе 400–599 |

### Атрибуты `RequestError`

| Атрибут | Что содержит |
|---|---|
| `kind` | машинный вид ошибки (таблица выше) |
| `stage` | `connect`, `write`, `read`, `body`, `request` (ошибка в самом запросе: неверный URL или метод, слишком много редиректов) или `None` |
| `method`, `url` | запрос. Логин и пароль из URL удалены |
| `elapsed` | секунды от начала запроса до ошибки |
| `request_id` | id нативного запроса, совпадает с `Response.request_id` |
| `retryable` | `True` для таймаутов, `connect`, `dns`, `proxy`, `connection_closed` |
| `detail` | текст ошибки без контекста запроса |
| `response` | ответ (только у `HTTPStatusError`) |
| `__cause__` | исходный текст ошибки Go |

Логины, пароли, токены `Basic` и `Bearer` из текста ошибки вырезаются: сообщение можно писать
в лог.

## Повторы

`retryable=True` значит, что ошибка временная и тот же запрос может пройти. Это не значит,
что повтор безопасен: при `connection_closed`, `read_timeout` и `timeout` сервер мог уже
выполнить запрос. Повторяйте автоматически только идемпотентные запросы (GET, HEAD, PUT,
DELETE, OPTIONS) или запросы с `Idempotency-Key`.

```python
import time
from yumeclient import RequestError, Session

def get_with_retries(s: Session, url: str, attempts: int = 3):
    for attempt in range(attempts):
        try:
            return s.get(url, timeout=10)
        except RequestError as e:
            if not e.retryable or attempt == attempts - 1:
                raise
            time.sleep(0.5 * 2 ** attempt)
```

Сама библиотека повторяет запрос только там, где так делает браузер:

- соединение из пула оказалось закрыто сервером: запрос повторяется по новому соединению,
  если в старое из него ничего не записано (тогда — любой метод, тело отправляется заново)
  или если он идемпотентный;
- при `http_version="3"` HTTP/3-соединение не открылось или закрылось до отправки: запрос
  заново проходит гонку протоколов (подробно — в разделе
  [Протоколы](protocols.md#http3-и-quic)).

Запрос, который мог дойти до сервера, библиотека повторяет только если он идемпотентный: GET,
HEAD, OPTIONS, TRACE или запрос с заголовком `Idempotency-Key` (как `net/http` в Go; PUT и DELETE
библиотека сама не повторяет).

## HTTP-статусы

Ответы 4xx и 5xx — не исключения: `s.get(...)` возвращает `Response`. Проверить статус:

```python
r = s.get("https://httpbin.org/status/404")
print(r.ok)              # False (ok = 200–399)
r.raise_for_status()     # HTTPStatusError: 404 ...; ответ в e.response
```

## Отмена

- **asyncio.** Отмена задачи (`task.cancel()`, `asyncio.wait_for`, `asyncio.timeout`,
  `TaskGroup`) сразу обрывает запрос в Go: и во время соединения, и при чтении тела.
  Соединение закрывается, задача получает `CancelledError`.
- **Закрытие сессии.** `close(grace=5.0)` ждёт запросы в полёте `grace` секунд, затем
  отменяет их (`RequestCancelled`). С `grace=None` закрытие ждёт, пока все запросы закончатся.
  Новые запросы в закрытую сессию — `SessionConfigurationError("session is closed")`.
- **Ctrl+C.** В синхронном коде главного потока `KeyboardInterrupt` прерывает запрос и чтение
  потока сразу, а не после прихода ответа. Нативный запрос при этом отменяется.

```python
import asyncio
from yumeclient import AsyncSession

async def main():
    async with AsyncSession() as s:
        try:
            await asyncio.wait_for(s.get("https://httpbin.org/delay/10"), 1)
        except asyncio.TimeoutError:
            print("отменено через 1 с, соединение закрыто")

asyncio.run(main())
```

## Лимит тела

`max_content_size` (в сессии или в запросе) ограничивает **распакованное** тело в байтах.
Защищает от сжатых «бомб»: гигабайт нулей в gzip занимает около мегабайта.

```python
with Session(max_content_size=10 * 1024 * 1024) as s:
    s.get("https://example.com/huge")                          # ResponseTooLarge, если больше 10 MiB
    s.get("https://example.com/huge", max_content_size=2**30)  # свой лимит для этого запроса
```

При `stream=True` лимит проверяется по мере чтения. `max_content_size=None` в запросе
означает «как у сессии»; по умолчанию лимита нет.

## Ошибки конфигурации

`SessionConfigurationError` наследует `ValueError` и бросается в конструкторе: неизвестный
профиль или ОС, противоречивые настройки протокола, неверные значения TLS-параметров. Сообщение
называет параметр и подсказывает исправление:

```
unknown client_identifier 'chrome_999'; did you mean: chrome_109, chrome_152, chrome_150
force_http1=True conflicts with http_version='2'
grease requires ja3_string
```

Если нативная библиотека не найдена, первый запрос бросит `TLSClientError` с путём, по
которому её искали ([Установка](installation.md#своя-нативная-библиотека)).
