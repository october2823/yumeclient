# Примеры

Каждый скрипт — законченная программа. По умолчанию они ходят на `https://httpbin.org`;
без интернета запустите локальную замену и укажите её адрес:

```bash
python tests/httpbin_local.py 8080 &
HTTPBIN=http://127.0.0.1:8080 python examples/quickstart.py
```

| Скрипт | Что показывает |
|---|---|
| [quickstart.py](quickstart.py) | one-shot запрос, сессия, параметры запроса, JSON, форма, статусы, редиректы |
| [async_requests.py](async_requests.py) | `AsyncSession`: параллельные запросы, ограничение параллелизма, таймаут, отмена |
| [profiles_and_headers.py](profiles_and_headers.py) | выбор профиля и ОС, базовые заголовки, добавление, удаление и порядок заголовков, okhttp |
| [cookies.py](cookies.py) | cookie jar, ручные cookie, cookie на один запрос, сохранение в файл и загрузка |
| [streaming_download.py](streaming_download.py) | скачивание в файл по частям, `max_content_size`, асинхронный поток |
| [upload_files.py](upload_files.py) | загрузка файлов (multipart/form-data) |
| [errors_and_retries.py](errors_and_retries.py) | типы исключений, их поля, повтор с backoff для идемпотентных запросов |
| [proxies.py](proxies.py) | прокси сессии, другой прокси или без прокси для одного запроса (`PROXY=...`) |
| [fingerprint.py](fingerprint.py) | JA3/JA4/Akamai, сравнение отпечатков, экспорт профиля, трасса для баг-репорта |
| [custom_ja3.py](custom_ja3.py) | свой ClientHello из JA3 и HTTP/2-параметры, как у Firefox |

Все примеры прогоняются в тестах (`tests/test_examples.py`) против локального сервера.
