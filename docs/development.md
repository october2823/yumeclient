# Разработка

Как устроен репозиторий, как собрать нативную библиотеку, запустить тесты, обновить
upstream-модули, снять новые отпечатки и выпустить релиз.

## Структура

```text
yumeclient/            Python-пакет
  __init__.py          Session, AsyncSession, Response, исключения, сборка запроса
  _headers.py          Headers — регистронезависимый упорядоченный dict
  cookies.py           CookieJar (RFC 6265, PSL), JarCookie
  profiles.py          идентификаторы профилей, базовые заголовки, HTTP3_FINGERPRINTS, NO_HTTP3
  diagnostics.py       export_profile / from_profile, fingerprint_diff, trace
  multipart.py         encode_multipart
native/                Go c-shared библиотека (yumeclient.dll / .so / .dylib)
  main.go              создание клиентов, профили, custom JA3, сессии
  call.go              yumeclient_call: запрос, чтение тела, стриминг, ответ в JSON
  control.go           отмена, стадийные таймауты, редиректы, классификация ошибок
  cookiejar.go         RFC 6265 jar одного запроса (снимок из Python + изменения)
  plain.go             http://: HTTP/1.1 и h2c через транспорт сессии
  okhttp.go            HTTP-слой okhttp4 (header_style="okhttp")
  wire.go              запись ClientHello для r.fingerprint, JA3/JA4/Akamai
  h3profiles.go/.json  отпечатки HTTP/3, снятые с браузеров
  third_party/         копии upstream-модулей с правками (см. ниже)
scripts/               сборка, проверка wheel, инструменты записи отпечатков
tests/                 pytest-тесты (локальные серверы; сеть не нужна)
docs/                  документация
```

Python вызывает нативную библиотеку через `ctypes`. Запрос — JSON-строка, ответ — JSON
(тело в base64). Функции библиотеки: `yumeclient_call`, `yumeclient_cancel`,
`yumeclient_stream_read`, `yumeclient_stream_close`, `yumeclient_close`, `yumeclient_free`,
`yumeclient_debug_stats`.

## Сборка

Нужны Go 1.24.1+ (CI собирает на Go 1.24.x) и C-компилятор для cgo: на Windows —
MinGW-w64 (`gcc` в `PATH`), на Linux — gcc, на macOS — Xcode Command Line Tools.

```bash
# Windows (PowerShell)
./scripts/build-native.ps1            # → yumeclient/yumeclient.dll

# Linux / macOS
sh ./scripts/build-native.sh          # → yumeclient/yumeclient.so или .dylib
```

На macOS по умолчанию собирается universal2 (`YUMECLIENT_MAC_ARCHS="arm64 amd64"`) с
`MACOSX_DEPLOYMENT_TARGET=11.0`. Для разработки быстрее одна архитектура:
`YUMECLIENT_MAC_ARCHS=arm64 sh ./scripts/build-native.sh`.

После сборки пакет можно использовать прямо из репозитория (`pip install -e ".[test]"`) или
указать библиотеку явно: `YUMECLIENT_LIBRARY=/path/to/yumeclient.so`.

Wheel:

```bash
python setup.py bdist_wheel                 # wheel с текущей нативной библиотекой
python scripts/check_wheel.py dist/*.whl    # тег py3-none-<платформа>, одна библиотека нужного формата
sh scripts/build-linux-wheel.sh x86_64      # manylinux2014 в Docker; архитектура = архитектура хоста
```

## Тесты

```bash
pip install -e ".[test]"        # pytest, pytest-asyncio, aioquic
python -m pytest -q             # ~580 тестов, локальные серверы
python -m pytest -q --run-online   # + тесты против httpbin.org
(cd native && go test ./...)    # Go-тесты: QPACK, отпечатки HTTP/3, ECH
```

Тесты поднимают свои серверы на `127.0.0.1`: HTTP/1.1, TLS-сниффер ClientHello, HTTP/2 на
сырых кадрах (`tests/test_protocol.py::H2Server`), HTTP/3 на aioquic (`tests/h3raw.py`,
`tests/test_http3.py::H3Server`), прокси (HTTP CONNECT, SOCKS5 с UDP ASSOCIATE —
`tests/socks5udp.py`). Тесты HTTP/3 пропускаются, если aioquic не установлен.

Регрессионный тест должен падать на старой версии и проходить на новой. Проверка: соберите
DLL прошлого релиза (`git worktree add ../old vX.Y.Z`, сборка там) и запустите тест с
`YUMECLIENT_LIBRARY=../old/yumeclient/yumeclient.dll`.

## Upstream-модули (`native/third_party`)

`native/go.mod` заменяет `fhttp`, `tls-client`, `utls`, `quic-go-utls` и `qpack` локальными
копиями (`replace ... => ./third_party/<имя>`). Каждая копия — upstream-модуль той версии,
что указана в `go.mod`, без тестов и примеров, плюс правки из
`native/third_party/patches/<имя>.patch`. Патч — unified diff; это одновременно и запись для
ревью.

```bash
python scripts/third_party.py check   # копии == upstream + патч, лишних файлов нет (CI)
python scripts/third_party.py diff    # пересобрать патчи из отредактированных копий
python scripts/third_party.py sync    # свежие копии из upstream + git apply патчей
                                      # (после смены версии в go.mod)
```

Правка upstream-кода: отредактируйте файл в `native/third_party/<имя>/`, выполните `diff`,
закоммитьте и копию, и патч. Изменения в upstream-коде помечайте комментарием
`// yumeclient: ...` с причиной.

## Отпечатки профилей

### TLS / HTTP/2 / заголовки

`tests/fixtures/profiles.json` — эталонный ClientHello и HTTP/2 каждого профиля;
`tests/fixtures/browser_headers.json` — заголовки, снятые с браузеров.

```bash
python scripts/profile_fixtures.py            # отличия текущей сборки от эталона
python scripts/profile_fixtures.py --update   # перезаписать эталон
```

### HTTP/3 и QUIC

Отпечатки HTTP/3 снимаются с настоящих браузеров (Windows x64):

```bash
pip install aioquic
# скачать сборки и записать рукопожатие (по 2 прогона, чтобы отделить случайные поля)
python scripts/h3_browsers.py chrome 133 144 --repeat 2 --out captures
python scripts/h3_browsers.py firefox 147.0 --repeat 2 --out captures
python scripts/h3_browsers.py opera 91.0.4516.77 --repeat 2 --out captures
python scripts/h3_browsers.py chrome 116 --tag pq --chrome-flag=--enable-features=PostQuantumKyber --out captures

# собрать native/h3profiles.json и список profiles.HTTP3_FINGERPRINTS
python scripts/h3_profiles.py captures --out native/h3profiles.json
```

- Chrome 113+ скачивается из Chrome for Testing, более старые — снапшоты Chromium на позиции
  ветки релиза; Firefox — с archive.mozilla.org; Opera — с get.geo.opera.com. Кэш —
  `--cache` или переменная `YC_BROWSER_CACHE`.
- `scripts/h3_capture.py` — сервер-регистратор на aioquic: расшифровывает Initial-пакеты
  клиента и записывает ClientHello, транспортные параметры, раскладку пакетов, кадры
  HTTP/3 и QPACK-потоки. Отдельно: `python scripts/h3_capture.py serve --port 4433` —
  направьте на него устройство (Safari, приложение) и получите запись при Ctrl+C.
- Соответствие записей профилям — `PROFILE_SOURCES` в `scripts/h3_profiles.py`.
- `tests/test_h3_fingerprints.py` проверяет каждый профиль с записью против
  `native/h3profiles.json`.

## CI и релиз

- `.github/workflows/test.yml` — на каждый push и PR: `third_party.py check`, сборка, Go-тесты,
  pytest на Windows, Linux и macOS.
- `.github/workflows/release.yml` — сборка 4 wheel (Windows x64, manylinux2014 x86_64 и
  aarch64, macOS universal2), `check_wheel.py`, smoke-тест каждого wheel на 5 раннерах ×
  Python 3.11–3.14 и на образе с glibc 2.17, публикация на PyPI через Trusted Publishing.
  Пробный прогон без публикации: `gh workflow run release.yml --ref <ветка> -f publish=false`.

Выпуск версии:

1. Версия — в `pyproject.toml` и `yumeclient/__init__.py` (`__version__`; тест проверяет
   совпадение). Раздел в `CHANGELOG.md`.
2. Зелёные `test.yml` и пробный `release.yml` на ветке.
3. Слить в `main`, поставить тег `vX.Y.Z`, создать GitHub Release (текст — раздел CHANGELOG).
   Публикация на PyPI запускается релизом.
4. Проверить: `pip install yumeclient==X.Y.Z` в чистом окружении и
   `python scripts/smoke_wheel.py`.
