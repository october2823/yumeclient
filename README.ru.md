# yumeclient

[English](README.md) | **Русский**

[![PyPI](https://img.shields.io/pypi/v/yumeclient)](https://pypi.org/project/yumeclient/)
[![Python](https://img.shields.io/pypi/pyversions/yumeclient)](https://pypi.org/project/yumeclient/)
[![test](https://github.com/october2823/yumeclient/actions/workflows/test.yml/badge.svg)](https://github.com/october2823/yumeclient/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

HTTP-клиент для Python, который отправляет запросы так же, как настоящие браузеры и мобильные
приложения: тот же TLS ClientHello, то же рукопожатие HTTP/2 и HTTP/3/QUIC, те же заголовки в
том же порядке. Синхронный и asyncio API в стиле `requests`.

```python
from yumeclient import Session

with Session(client_identifier="chrome_152") as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.http_version, r.fingerprint["ja4"])
```

## Возможности

- **93 профиля клиентов**: Chrome 103–152, Edge, Brave, Opera, Firefox 102–148, Safari на
  macOS, iOS и iPadOS, Tor Browser, Android-приложения на okhttp. Каждый профиль — это
  ClientHello, настройки HTTP/2 и набор заголовков по умолчанию для браузера и его ОС.
- **HTTP/3 и QUIC, снятые с настоящих браузеров**, для 53 профилей: QUIC ClientHello,
  transport parameters, раскладка пакетов, HTTP/3 SETTINGS, приоритеты и потоки QPACK.
- **HTTP/1.1, HTTP/2, HTTP/3 и h2c.** Выбор протокола строгий: запрос HTTP/2 никогда не
  откатывается на HTTP/1.1 молча.
- **Синхронный `Session` и asyncio `AsyncSession`.** Отмена asyncio-задачи отменяет запрос
  на проводе, а Ctrl+C прерывает блокирующий вызов.
- **Типизированные ошибки, таймауты и повторы.** Раздельные таймауты на подключение, чтение,
  запись и общий, автоматические повторы (`retries=`), потоковые ответы.
- **Cookies как в браузере.** Cookie jar по RFC 6265 со списком публичных суффиксов; его
  можно экспортировать и импортировать (JSON Cookie-Editor).
- **Прокси.** HTTP(S), SOCKS4/4a/5/5h и QUIC через SOCKS5 с тем же отпечатком.
- **Свой TLS.** ClientHello из строки JA3, низкоуровневые параметры TLS, HTTP/2 и ECH.
- **Диагностика.** В каждом ответе есть отпечаток того, что реально ушло в сеть (JA3, JA4,
  Akamai). Можно сравнить два отпечатка, сохранить настройку клиента как JSON-профиль и
  получить трейс без секретов для сообщения об ошибке.
- **Готовые wheel** без зависимостей на Python.

## Установка

```bash
pip install yumeclient
```

Wheel публикуются для Windows x64, Linux x86-64 и aarch64 (glibc 2.17+) и macOS 11+
(universal2), все — для Python 3.11+. На других платформах нативную библиотеку можно собрать
из исходников, см. [Установку](docs/ru/installation.md).

## Быстрый старт

```python
import yumeclient

# один запрос с профилем по умолчанию (последний Chrome)
r = yumeclient.get("https://httpbin.org/get", params={"q": "test"})
print(r.json()["args"])

# сессия хранит соединения, cookie и заголовки
with yumeclient.Session(client_identifier="firefox_148", timeout=20) as s:
    s.headers["Referer"] = "https://example.com/"
    r = s.post("https://httpbin.org/post", json={"name": "yume"})
    r.raise_for_status()
    print(r.http_version, r.json()["json"])
```

```python
import asyncio
from yumeclient import AsyncSession

async def main():
    async with AsyncSession(client_identifier="safari_ios_18_5") as s:
        responses = await asyncio.gather(*(s.get(f"https://httpbin.org/get?i={i}") for i in range(10)))
        print([r.status_code for r in responses])

asyncio.run(main())
```

```python
from yumeclient import Session, TimeoutConfig, ReadTimeout, ProxyError

with Session(proxy="socks5://user:pass@127.0.0.1:1080",
             timeout=TimeoutConfig(total=60, connect=5, read=15),
             retries=3,                         # повторять таймауты и оборванные соединения
             http_version="3") as s:            # HTTP/3 наперегонки с TCP, как в Chrome
    try:
        with s.get("https://example.com/large.bin", stream=True) as r:
            for chunk in r.iter_bytes(1 << 20):
                ...
    except (ReadTimeout, ProxyError) as e:
        print(e.kind, e.stage, e.retryable)
```

## Документация

Документация есть на русском и на английском; в начале каждой страницы — ссылка на перевод.

- **[USAGE.ru.md](USAGE.ru.md)**: руководство с примерами для типичных задач.
- **[docs/ru/](docs/ru/index.md)**: справочник, по странице на тему:
  - [сессии](docs/ru/sessions.md), [запросы](docs/ru/requests.md) и [ответы](docs/ru/responses.md);
  - [профили](docs/ru/profiles.md) и [протоколы](docs/ru/protocols.md);
  - [свой TLS-отпечаток](docs/ru/custom-tls.md), [таймауты и ошибки](docs/ru/timeouts-and-errors.md),
    [cookies](docs/ru/cookies.md) и [прокси](docs/ru/proxies.md);
  - [диагностика](docs/ru/diagnostics.md), [ограничения](docs/ru/limitations.md) и
    [разработка](docs/ru/development.md).
- **[examples/](examples/README.ru.md)**: готовые скрипты. Все они запускаются в CI против локального сервера.
- **[CHANGELOG.ru.md](CHANGELOG.ru.md)**: история изменений.

У самого API есть docstrings и аннотации типов (`py.typed`).

## Участие в разработке

Сообщения об ошибках, записи отпечатков и pull request'ы приветствуются, на русском или
английском. См. [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md). Об уязвимостях сообщайте закрыто,
как описано в [SECURITY.ru.md](SECURITY.ru.md). Участники следуют
[Кодексу поведения](CODE_OF_CONDUCT.ru.md).

## Как это устроено

Python-пакет — тонкий слой: сессии, заголовки, cookie jar, проверка параметров и ошибки. Он
вызывает Go-библиотеку через `ctypes`. Go-часть построена на
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client),
[uTLS](https://github.com/refraction-networking/utls) и
[quic-go](https://github.com/quic-go/quic-go). Эти модули лежат в репозитории с патчами в
`native/third_party/`, и CI проверяет, что копии совпадают с upstream плюс патчи. Go-часть
строит рукопожатия каждого профиля, держит пулы соединений, проходит редиректы с cookie на
каждом хопе и измеряет отпечаток того, что отправила.

Библиотека воспроизводит то, что клиент отправляет по сети. Она не воспроизводит TCP/IP-стек
другой ОС, JavaScript и поведение браузера. См.
[ограничения](docs/ru/limitations.md).

## Разработка

```bash
./scripts/build-native.ps1        # Windows; Linux/macOS: sh ./scripts/build-native.sh
pip install -e ".[test]"
python -m pytest -q               # без сети: локальные серверы HTTP/1.1, HTTP/2, HTTP/3 и прокси
```

Для сборки нужны Go 1.24.1+ и компилятор C. Патчи upstream-модулей, запись отпечатков браузеров
и релизы — в разделе [Разработка](docs/ru/development.md).

## Лицензия

MIT, см. [LICENSE](LICENSE). Нативная библиотека содержит код bogdanfinn/tls-client
(лицензия в стиле BSD, [UPSTREAM-LICENSE](UPSTREAM-LICENSE)), `net/http` из Go и uTLS
(BSD 3-clause), quic-go и qpack (MIT). This product includes software developed by
Bogdan Finn (этот продукт включает программное обеспечение, разработанное Bogdan Finn).
Подробности — в [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Используйте библиотеку для тестирования, исследований и совместимости и соблюдайте условия
сервисов, к которым отправляете запросы.

Участники: [randomtempusername123](https://github.com/randomtempusername123).
