# Installation

**English** | [Русский](ru/installation.md)

```sh
python -m pip install yumeclient
```

Python 3.11 or newer is required. There are no Python dependencies: the wheel contains a
prebuilt native library.

## Platforms

| Platform | Wheel | Notes |
|---|---|---|
| Windows x64 | `win_amd64` | Windows 10+ |
| Linux x86_64 | `manylinux2014_x86_64` | glibc ≥ 2.17; CI runs the wheel in a manylinux2014 image |
| Linux aarch64 | `manylinux2014_aarch64` | glibc ≥ 2.17 |
| macOS | `macosx_11_0_universal2` | macOS 11+, Apple Silicon and Intel in one library |

Wheels are tagged `py3-none-<platform>`: the native part is loaded through `ctypes` and does not
depend on the CPython version, so one wheel works for 3.11, 3.12, 3.13, 3.14 and future 3.x
releases. There are no wheels for musl (Alpine), Windows ARM, 32-bit systems or FreeBSD; build
the library yourself (see below).

Check after installing:

```python
import yumeclient

r = yumeclient.get("https://httpbin.org/get")
print(yumeclient.__version__, r.status_code, r.http_version)
```

## Building from source

You need Go 1.24.1+ (cgo), a C compiler and the sources from the repository.

```sh
git clone https://github.com/october2823/yumeclient
cd yumeclient
```

**Windows** (MinGW-w64, for example from MSYS2):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/build-native.ps1
python -m pip install -e .
```

The script builds `yumeclient/yumeclient.dll` (`go build -trimpath -buildmode=c-shared`).

**Linux and macOS:**

```sh
sh scripts/build-native.sh        # yumeclient/yumeclient.so or .dylib
python -m pip install -e .
```

On macOS the script builds arm64 and amd64 and merges them with `lipo`; the set of
architectures is set by `YUMECLIENT_MAC_ARCHS` (default `"arm64 amd64"`), the minimum version
by `MACOSX_DEPLOYMENT_TARGET` (default `11.0`).

A manylinux2014-compatible Linux wheel is built in Docker:

```sh
sh scripts/build-linux-wheel.sh x86_64     # or aarch64; the wheel appears in dist/
python scripts/check_wheel.py dist/*.whl
```

`scripts/check_wheel.py` checks that the wheel contains exactly one native library of the
right format and architecture (PE, ELF, Mach-O) and that the platform tag matches it.

## Custom native library

The `YUMECLIENT_LIBRARY` environment variable sets a path to a library to use instead of the
one bundled in the package. This is useful if you built the library with changes or for
another platform:

```sh
YUMECLIENT_LIBRARY=/opt/yumeclient/yumeclient.so python app.py
```

The library is loaded on the first request. If the file does not exist, the request raises
`TLSClientError` with the path it tried to open; if the file exists but does not load (a
different architecture, a missing libc), you get `OSError` from `ctypes`.

## Test dependencies

```sh
python -m pip install -e ".[test]"     # pytest, pytest-asyncio, aioquic
python -m pytest -q
```

The tests do not go to the internet: TLS, HTTP/2, HTTP/3 and proxy servers run locally.
`--run-online` adds a few checks against httpbin.org. More in
[Development](development.md).
