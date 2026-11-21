# Установка

```sh
python -m pip install yumeclient
```

Нужен Python 3.11 или новее. Зависимостей на Python нет: wheel содержит готовую нативную
библиотеку.

## Платформы

| Платформа | Wheel | Примечание |
|---|---|---|
| Windows x64 | `win_amd64` | Windows 10+ |
| Linux x86_64 | `manylinux2014_x86_64` | glibc ≥ 2.17; CI запускает wheel в образе manylinux2014 |
| Linux aarch64 | `manylinux2014_aarch64` | glibc ≥ 2.17 |
| macOS | `macosx_11_0_universal2` | macOS 11+, Apple Silicon и Intel в одной библиотеке |

Wheels помечены `py3-none-<платформа>`: нативная часть загружается через `ctypes` и не
зависит от версии CPython, поэтому один wheel подходит для 3.11, 3.12, 3.13, 3.14 и будущих
3.x. Для musl (Alpine), Windows ARM, 32-битных систем и FreeBSD wheel нет — соберите
библиотеку сами (ниже).

Проверка после установки:

```python
import yumeclient

r = yumeclient.get("https://httpbin.org/get")
print(yumeclient.__version__, r.status_code, r.http_version)
```

## Сборка из исходников

Нужны Go 1.24+ (cgo), C-компилятор и исходники из репозитория.

```sh
git clone https://github.com/october2823/yumeclient
cd yumeclient
```

**Windows** (MinGW-w64, например из MSYS2):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/build-native.ps1
python -m pip install -e .
```

Скрипт собирает `yumeclient/yumeclient.dll` (`go build -trimpath -buildmode=c-shared`).

**Linux и macOS:**

```sh
sh scripts/build-native.sh        # yumeclient/yumeclient.so или .dylib
python -m pip install -e .
```

На macOS скрипт собирает arm64 и amd64 и склеивает их `lipo`; набор архитектур задаёт
`YUMECLIENT_MAC_ARCHS` (по умолчанию `"arm64 amd64"`), минимальную версию —
`MACOSX_DEPLOYMENT_TARGET` (по умолчанию `11.0`).

Wheel для Linux, совместимый с manylinux2014, собирается в Docker:

```sh
sh scripts/build-linux-wheel.sh x86_64     # или aarch64; wheel появится в dist/
python scripts/check_wheel.py dist/*.whl
```

`scripts/check_wheel.py` проверяет, что в wheel ровно одна нативная библиотека нужного
формата и архитектуры (PE, ELF, Mach-O) и что тег платформы ей соответствует.

## Своя нативная библиотека

Переменная окружения `YUMECLIENT_LIBRARY` задаёт путь к библиотеке вместо той, что лежит в
пакете. Это удобно, если вы собрали библиотеку с изменениями или под другую платформу:

```sh
YUMECLIENT_LIBRARY=/opt/yumeclient/yumeclient.so python app.py
```

Библиотека загружается при первом запросе. Если файла нет, запрос бросает `TLSClientError`
с путём, который пытались открыть; если файл есть, но не загружается (другая архитектура,
нет нужной libc), — `OSError` от `ctypes`.

## Тестовые зависимости

```sh
python -m pip install -e ".[test]"     # pytest, pytest-asyncio, aioquic
python -m pytest -q
```

Тесты не ходят в интернет: серверы TLS, HTTP/2, HTTP/3 и прокси поднимаются локально.
`--run-online` добавляет несколько проверок против httpbin.org. Подробнее —
[Разработка](development.md).
