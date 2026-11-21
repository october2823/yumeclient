# Сессии

[English](../sessions.md) | **Русский**

Сессия — это профиль клиента (TLS, HTTP/2, HTTP/3, заголовки), пул соединений, cookie jar и
набор параметров по умолчанию. Запросы одной сессии переиспользуют соединения и cookie, как
вкладки одного браузера.

```python
from yumeclient import Session, AsyncSession

with Session(client_identifier="chrome_152") as s:
    r = s.get("https://httpbin.org/get")


async def main():
    async with AsyncSession(client_identifier="firefox_148") as s:
        r = await s.get("https://httpbin.org/get")
```

## Session и AsyncSession

| | `Session` | `AsyncSession` |
|---|---|---|
| Вызов | `r = s.get(url)` | `r = await s.get(url)` |
| Контекст | `with Session() as s:` | `async with AsyncSession() as s:` |
| Параллельность | потоки (`concurrent.futures`) | `asyncio.gather`, `TaskGroup` |
| Где выполняется | в вызывающем потоке | общий пул потоков, `AsyncSession.configure_executor(n)` |
| Закрытие | `s.close(grace=5.0)` | `await s.close(grace=5.0)` |
| Сброс соединений | `s.reset_connection()` | `await s.reset_connection()` |

Оба класса — фасады одного движка: параметры, заголовки, cookie и поведение транспорта
одинаковы. В asyncio-коде используйте только `AsyncSession`: синхронный `Session`
заблокирует event loop на время запроса.

Методы обоих классов: `request(method, url, **kwargs)`, `get`, `head`, `post`, `put`, `patch`,
`delete`, `options`. Параметры запроса — в [Запросы](requests.md).

`Session` потокобезопасна: одну сессию можно использовать из нескольких потоков, запросы
идут параллельно по общему пулу соединений.

## Параметры конструктора

Все параметры именованные. Значения по умолчанию подобраны так, чтобы сессия выглядела как
актуальный Chrome на Windows.

### Профиль и заголовки

| Параметр | По умолчанию | Описание |
|---|---|---|
| `client_identifier` | `"chrome_152"` | профиль клиента: TLS ClientHello, HTTP/2, HTTP/3, базовые заголовки. Список — [Профили](profiles.md) |
| `client_os` | из профиля | `"windows"`, `"macos"`, `"android"`, `"ios"`. Меняет только базовые заголовки (User-Agent, client hints), не TLS |
| `header_style` | из профиля | `"okhttp"` — HTTP-слой okhttp 4.x (по умолчанию у `okhttp4_*` и Conscrypt-профилей), `"raw"` — заголовки ровно как переданы |
| `headers` | `None` | заголовки сессии: добавляются к базовым заголовкам профиля (`update`); заменить набор целиком — `s.headers = {...}` после создания |
| `header_order` | `None` | порядок заголовков на проводе; по умолчанию — порядок вставки в `session.headers` |
| `cookies` | `None` | начальные cookie: `dict`, список словарей (экспорт браузера) или `CookieJar` |
| `random_tls_extension_order` | `True` | перемешивать расширения ClientHello для каждого соединения, как Chromium. На профили не-Chromium не действует; на `ja3_string` действует — см. [Свой TLS-отпечаток](custom-tls.md) |

### Протокол

| Параметр | По умолчанию | Описание |
|---|---|---|
| `http_version` | `"auto"` | `"auto"`, `"1.1"`, `"2"`, `"3"` (также `1`, `2`, `3`, `"h2"`, `"h3"`, `"quic"`). См. [Протоколы](protocols.md) |
| `force_http1` | `False` | то же, что `http_version="1.1"` |
| `keep_alpn` | `False` | с `http_version="1.1"`: оставить ALPN профиля (`h2,http/1.1`) в ClientHello |
| `disable_http3` | `False` | запретить HTTP/3 |
| `disable_session_tickets` | `False` | не возобновлять TLS-сессии (каждое соединение — полное рукопожатие) |

### Сеть

| Параметр | По умолчанию | Описание |
|---|---|---|
| `proxy` | `None` | `http://`, `https://`, `socks5://`, `socks5h://`, `socks4://`, `socks4a://`, с `user:pass@`. См. [Прокси и сеть](proxies.md) |
| `udp_proxy` | `None` | отдельный прокси для QUIC: `socks5://` или `socks5h://` |
| `timeout` | `30` | число (лимит на весь обмен), `(connect, read)`, `TimeoutConfig` или `None`. См. [Таймауты](timeouts-and-errors.md) |
| `verify` | `True` | проверять сертификат сервера |
| `server_name_overwrite` | `None` | имя в SNI вместо хоста из URL; сертификат проверяется для этого имени |
| `local_address` | `None` | локальный адрес исходящих соединений, `"IP:порт"` (порт `0` — любой) |
| `max_content_size` | `None` | максимальный размер распакованного тела ответа в байтах (`ResponseTooLarge`) |
| `retries` | `0` | автоматические повторы неудавшихся запросов: число или `Retry`. См. [Повторы](timeouts-and-errors.md#автоматические-повторы) |

### Свой TLS-отпечаток

Только вместе с `ja3_string` (и без `client_identifier`): `ja3_string`,
`supported_signature_algorithms`, `supported_versions`,
`key_share_curves`, `key_share_data`, `alpn_protocols`, `alps_protocols`,
`cert_compression_algos`, `trust_anchors_payload`, `tls_extension_order`, `ech_config_list`,
`grease`, `psk_mode`, `h2_settings`, `h2_settings_order`, `connection_flow`,
`pseudo_header_order`, `priority_frames`, `header_priority`. Без `ja3_string` они дают
`SessionConfigurationError`. `fill_custom_with_chrome_defaults` (по умолчанию `True`) без
`ja3_string` просто не используется. Описание — в [Свой TLS-отпечаток](custom-tls.md).

### Проверка параметров

Параметры проверяются в конструкторе, до сети. Неизвестный профиль или ОС, противоречивые
настройки протокола (`force_http1=True` с `http_version="2"`, `http_version="3"` с HTTP-прокси
и т. п.), параметры custom JA3 без `ja3_string`, неверные значения — `SessionConfigurationError`
(подкласс `ValueError`) с объяснением:

```python
from yumeclient import Session, SessionConfigurationError

try:
    Session(client_identifier="chrome_999")
except SessionConfigurationError as e:
    print(e)    # unknown client_identifier 'chrome_999'; did you mean: chrome_109, chrome_152, chrome_150
```

## Что можно менять у живой сессии

Транспорт сессии фиксирован: профиль, протокол, прокси, TLS-параметры, таймаут по умолчанию.
Присваивание такого атрибута — `AttributeError`, а не тихое игнорирование:

```python
s = Session()
s.proxy = "socks5://127.0.0.1:1080"   # AttributeError: proxy is fixed for the lifetime of a session
```

Меняются свободно:

- `s.headers` — словарь заголовков (`s.headers.update(...)`, `s.headers["X"] = ...`,
  `del s.headers["X"]`, `s.headers = {...}`);
- содержимое `s.cookies` (`CookieJar`).

Для другой конфигурации создайте новую сессию. Перенести идентичность (профиль, заголовки,
TLS-параметры) в сессию с другим прокси —
`Session.from_profile(s.export_profile(), proxy=...)`, см. [Диагностика](diagnostics.md).

Отдельному запросу можно задать `proxy=`, `timeout=`, `headers=`, `cookies=`, `header_order=`,
`allow_redirects=`, `stream=`, `max_content_size=`, `host_override=`, `retries=`. Запрос с `proxy=` идёт
через отдельный нативный клиент со своим пулом соединений; профиль, заголовки и cookie —
от сессии.

## Свойства

| Свойство | Тип | |
|---|---|---|
| `s.client_identifier` | `str` | профиль (`""` для `ja3_string`) |
| `s.client_os` | `str` | ОС базовых заголовков |
| `s.header_style` | `str` | `"okhttp"` или `"raw"` |
| `s.headers` | `Headers` | заголовки сессии, регистронезависимый словарь |
| `s.cookies` | `CookieJar` | cookie jar сессии |

## Жизненный цикл

### Закрытие

`with`/`async with` закрывают сессию сами. Явно:

```python
s.close()               # sync
await a.close()         # async
```

`close(grace=5.0)` даёт запросам, которые ещё выполняются в других потоках или задачах,
`grace` секунд на завершение, затем отменяет их (`RequestCancelled`); `grace=None` — ждать до
конца. Открытые потоковые ответы закрываются, соединения освобождаются. После закрытия любой
запрос — `SessionConfigurationError("session is closed")`. Повторный `close()` ничего не делает.

Сессия, которую не закрыли, освобождает свои соединения, когда её соберёт сборщик мусора
(с 0.8.1; раньше они оставались открытыми до конца процесса). Когда это произойдёт, заранее
неизвестно, поэтому закрывайте сессию явно.

### Новые соединения

`s.reset_connection()` (`await a.reset_connection()` у async) закрывает соединения сессии:
следующий запрос откроет новое соединение с новым рукопожатием. Cookie и заголовки остаются.
Полезно после смены сети или когда соединение «зависло» без RST
(см. [Ограничения](limitations.md)).

### Пул потоков AsyncSession

`AsyncSession` выполняет нативные вызовы в общем пуле на 64 потока: одновременно в полёте
может быть до 64 запросов всех `AsyncSession` процесса, остальные ждут в очереди. Изменить
размер — до первого запроса:

```python
from yumeclient import AsyncSession

AsyncSession.configure_executor(256)
```

После старта запросов вызов бросает `SessionConfigurationError`. `await yumeclient.close_runtime()`
останавливает пул при завершении программы (необязательно).

### Отмена и Ctrl+C

- Отмена asyncio-задачи (`task.cancel()`, `asyncio.wait_for`, `asyncio.timeout`, `TaskGroup`)
  обрывает нативный запрос сразу — на любой стадии: DNS, соединение, TLS, ожидание ответа,
  чтение тела.
- Ctrl+C в главном потоке прерывает синхронный запрос и чтение потока сразу
  (`KeyboardInterrupt`); нативный запрос отменяется, соединение закрывается.

## One-shot функции

Для единичных запросов без сессии:

```python
import yumeclient

r = yumeclient.get("https://httpbin.org/get", client_identifier="firefox_148", timeout=10)
r = yumeclient.post("https://httpbin.org/post", json={"a": 1})


async def main():
    r = await yumeclient.aget("https://httpbin.org/get")
```

Функции: `request`, `get`, `head`, `post`, `put`, `patch`, `delete`, `options` и async-варианты
`arequest`, `aget`, `ahead`, `apost`, `aput`, `apatch`, `adelete`, `aoptions`. Они принимают
и параметры сессии, и параметры запроса; каждая создаёт сессию и закрывает её после ответа.
С `stream=True` сессия закрывается вместе с ответом.

Для серии запросов к одному сайту one-shot функции медленнее и заметнее: каждый вызов —
новое соединение и полное TLS-рукопожатие, cookie не сохраняются.
