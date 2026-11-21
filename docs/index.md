# Документация yumeclient

yumeclient — HTTP-клиент для Python с API в стиле `requests`, который отправляет запросы так,
как их отправляют настоящие браузеры и мобильные приложения: тот же TLS ClientHello, те же
параметры HTTP/2 и HTTP/3/QUIC, те же заголовки в том же порядке. Под капотом — Go-библиотека
на основе [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) и
[uTLS](https://github.com/refraction-networking/utls), подключённая через `ctypes`.

Начать проще всего с [руководства с примерами](../USAGE.md). Этот раздел — справочник:
каждая страница описывает одну тему полностью.

## Разделы

| Страница | О чём |
|---|---|
| [Установка](installation.md) | wheels, платформы, сборка из исходников, `YUMECLIENT_LIBRARY` |
| [Сессии](sessions.md) | `Session` и `AsyncSession`, все параметры конструктора, жизненный цикл, one-shot функции |
| [Запросы](requests.md) | параметры запроса, тело (form, JSON, файлы), заголовки и их порядок, редиректы |
| [Ответы и стриминг](responses.md) | `Response`, история редиректов, `connection_info`, `fingerprint`, потоковое чтение |
| [Профили](profiles.md) | список профилей, `client_os`, базовые заголовки, HTTP-слой okhttp |
| [Протоколы](protocols.md) | `http_version`, HTTP/2, h2c, HTTP/3 и QUIC, ALPN, гонка протоколов |
| [Свой TLS-отпечаток](custom-tls.md) | `ja3_string` и низкоуровневые параметры TLS, HTTP/2, HTTP/3 |
| [Таймауты, ошибки, отмена](timeouts-and-errors.md) | `TimeoutConfig`, иерархия исключений, повторы, отмена и Ctrl+C |
| [Cookies](cookies.md) | `CookieJar`, правила RFC 6265, импорт и экспорт |
| [Прокси и сеть](proxies.md) | HTTP(S) и SOCKS прокси, `udp_proxy`, `local_address`, `verify` |
| [Диагностика](diagnostics.md) | `export_profile`/`from_profile`, `fingerprint_diff`, `Response.trace()` |
| [Ограничения](limitations.md) | что сознательно не поддерживается и чем это видно |
| [Разработка](development.md) | сборка, тесты, патчи upstream-модулей, запись отпечатков браузеров, релиз |

## Как это устроено

```
Python (yumeclient/)                       Go (native/, c-shared библиотека)
──────────────────────                     ──────────────────────────────────────────
Session / AsyncSession                      yumeclient_call(json) ─► профиль: uTLS ClientHello,
  заголовки, cookies (CookieJar),                                    HTTP/2 SETTINGS, QUIC/HTTP3
  проверка параметров, исключения  ──ctypes──► redirect-хопы, cookie по RFC 6265 на каждом хопе
Response (буфер или поток)        ◄─────────  тело, история, тайминги, отпечаток с провода
```

- **Python** хранит состояние сессии: заголовки, cookie jar, параметры. Каждый запрос получает
  снимок jar'а; Go выбирает cookie для каждого хопа редиректа и возвращает только изменения.
- **Go** держит соединения (пулы по сессиям), строит ClientHello профиля через uTLS, говорит
  HTTP/1.1, HTTP/2 и HTTP/3, ходит через прокси и считает отпечаток (JA3, JA4, Akamai) того,
  что реально ушло в сеть.
- Upstream-модули (`fhttp`, `tls-client`, `utls`, `quic-go-utls`, `qpack`) лежат в
  `native/third_party` с патчами — см. [Разработка](development.md).

## Соглашения

- Время — в секундах (`float`), размеры — в байтах.
- Неверная конфигурация — `SessionConfigurationError` при создании сессии, до сети.
  Неверный запрос — `InvalidRequestError` до отправки.
- «Профиль» — значение `client_identifier` (`"chrome_152"`, `"firefox_148"`, ...).
- Примеры используют `https://httpbin.org`. Без интернета — локальная замена из репозитория:
  `python tests/httpbin_local.py 8080`, затем `HTTPBIN=http://127.0.0.1:8080` для
  скриптов из [`examples/`](../examples/).
