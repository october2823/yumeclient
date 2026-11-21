# Development

**English** | [Русский](ru/development.md)

How the repository is organized, how to build the native library, run the tests, update the
upstream modules, capture new fingerprints and make a release.

## Structure

```text
yumeclient/            Python package
  __init__.py          Session, AsyncSession, Response, exceptions, request building
  _headers.py          Headers, a case-insensitive ordered dict
  cookies.py           CookieJar (RFC 6265, PSL), JarCookie
  profiles.py          profile identifiers, default headers, HTTP3_FINGERPRINTS, NO_HTTP3
  diagnostics.py       export_profile / from_profile, fingerprint_diff, trace
  multipart.py         encode_multipart
native/                Go c-shared library (yumeclient.dll / .so / .dylib)
  main.go              client creation, profiles, custom JA3, sessions
  call.go              yumeclient_call: request, body reading, streaming, response as JSON
  control.go           cancellation, stage timeouts, redirects, error classification
  cookiejar.go         RFC 6265 jar for one request (snapshot from Python + changes)
  plain.go             http://: HTTP/1.1 and h2c through the session transport
  okhttp.go            okhttp4 HTTP layer (header_style="okhttp")
  wire.go              ClientHello recording for r.fingerprint, JA3/JA4/Akamai
  h3profiles.go/.json  HTTP/3 fingerprints captured from browsers
  third_party/         copies of upstream modules with patches (see below)
scripts/               build, wheel checks, fingerprint capture tools
tests/                 pytest tests (local servers; no network needed)
docs/                  reference in English; docs/ru/ in Russian
```

Python calls the native library through `ctypes`. A request is a JSON string, and the response
is JSON (with the body in base64). Library functions: `yumeclient_call`, `yumeclient_cancel`,
`yumeclient_stream_read`, `yumeclient_stream_close`, `yumeclient_close`, `yumeclient_free`,
`yumeclient_debug_stats`.

## Building

You need Go 1.24.1+ (CI builds with Go 1.24.x) and a C compiler for cgo: on Windows,
MinGW-w64 (`gcc` in `PATH`); on Linux, gcc; on macOS, the Xcode Command Line Tools.

```bash
# Windows (PowerShell)
./scripts/build-native.ps1            # → yumeclient/yumeclient.dll

# Linux / macOS
sh ./scripts/build-native.sh          # → yumeclient/yumeclient.so or .dylib
```

On macOS, universal2 is built by default (`YUMECLIENT_MAC_ARCHS="arm64 amd64"`) with
`MACOSX_DEPLOYMENT_TARGET=11.0`. For development, a single architecture is faster:
`YUMECLIENT_MAC_ARCHS=arm64 sh ./scripts/build-native.sh`.

After building, you can use the package straight from the repository (`pip install -e ".[test]"`)
or point to the library explicitly: `YUMECLIENT_LIBRARY=/path/to/yumeclient.so`.

Wheels:

```bash
python setup.py bdist_wheel                 # wheel with the current native library
python scripts/check_wheel.py dist/*.whl    # tag py3-none-<platform>, one library of the right format
sh scripts/build-linux-wheel.sh x86_64      # manylinux2014 in Docker; architecture = host architecture
```

## Tests

```bash
pip install -e ".[test]"        # pytest, pytest-asyncio, aioquic
python -m pytest -q             # ~700 tests, local servers
python -m pytest -q --run-online   # + tests against httpbin.org
(cd native && go test ./...)    # Go tests: QPACK, HTTP/3 fingerprints, ECH
```

The tests start their own servers on `127.0.0.1`: HTTP/1.1, a TLS ClientHello sniffer, HTTP/2 on
raw frames (`tests/test_protocol.py::H2Server`), HTTP/3 on aioquic (`tests/h3raw.py`,
`tests/test_http3.py::H3Server`), proxies (HTTP CONNECT, SOCKS5 with UDP ASSOCIATE:
`tests/socks5udp.py`). The HTTP/3 tests are skipped if aioquic is not installed.

A regression test must fail on the old version and pass on the new one. To check this, build
the DLL of the previous release (`git worktree add ../old vX.Y.Z`, then build there) and run the
test with `YUMECLIENT_LIBRARY=../old/yumeclient/yumeclient.dll`.

## Documentation

The documentation is in English and Russian. English pages are at the usual paths (`README.md`,
`USAGE.md`, `CHANGELOG.md`, `docs/*.md`, `examples/README.md`), Russian ones next to them
(`*.ru.md`, `docs/ru/*.md`). A change goes into both versions.

```bash
python -m pytest -q tests/test_docs_i18n.py tests/test_examples.py
```

- `tests/test_docs_i18n.py` checks that the two versions of a page have the same structure:
  heading levels, code blocks (the same code apart from comments and Russian strings), table
  rows, list items and links. It also checks the language switcher under the title, that
  English pages contain no Cyrillic and that every `#anchor` in links exists.
- `tests/test_examples.py` runs the scripts from `examples/` against a local httpbin, compiles
  every `python` block in the documentation and checks relative links.
- `README.md` is also the project description on PyPI, so its links are absolute
  (`https://github.com/october2823/yumeclient/blob/main/...`).

## Upstream modules (`native/third_party`)

`native/go.mod` replaces `fhttp`, `tls-client`, `utls`, `quic-go-utls` and `qpack` with local
copies (`replace ... => ./third_party/<name>`). Each copy is the upstream module at the version
given in `go.mod`, without tests and examples, plus the patches from
`native/third_party/patches/<name>.patch`. A patch is a unified diff; it also serves as the
record for review.

```bash
python scripts/third_party.py check   # copies == upstream + patch, no extra files (CI)
python scripts/third_party.py diff    # rebuild the patches from the edited copies
python scripts/third_party.py sync    # fresh copies from upstream + git apply of the patches
                                      # (after changing the version in go.mod)
```

To patch upstream code: edit the file in `native/third_party/<name>/`, run `diff`, and commit
both the copy and the patch. Mark changes in upstream code with a `// yumeclient: ...` comment
that gives the reason.

## Profile fingerprints

### TLS / HTTP/2 / headers

`tests/fixtures/profiles.json` is the reference ClientHello and HTTP/2 of each profile;
`tests/fixtures/browser_headers.json` holds headers captured from browsers.

```bash
python scripts/profile_fixtures.py            # differences between the current build and the reference
python scripts/profile_fixtures.py --update   # overwrite the reference
```

### HTTP/3 and QUIC

HTTP/3 fingerprints are captured from real browsers (Windows x64):

```bash
pip install aioquic
# download the builds and capture the handshake (2 runs each, to separate out the random fields)
python scripts/h3_browsers.py chrome 133 144 --repeat 2 --out captures
python scripts/h3_browsers.py firefox 147.0 --repeat 2 --out captures
python scripts/h3_browsers.py opera 91.0.4516.77 --repeat 2 --out captures
python scripts/h3_browsers.py chrome 116 --tag pq --chrome-flag=--enable-features=PostQuantumKyber --out captures

# build native/h3profiles.json and the profiles.HTTP3_FINGERPRINTS list
python scripts/h3_profiles.py captures --out native/h3profiles.json
```

- Chrome 113+ is downloaded from Chrome for Testing, older versions are Chromium snapshots at
  the release branch position; Firefox comes from archive.mozilla.org; Opera from
  get.geo.opera.com. Cache: `--cache` or the `YC_BROWSER_CACHE` variable.
- `scripts/h3_capture.py` is a recording server on aioquic: it decrypts the client's Initial
  packets and records the ClientHello, transport parameters, packet layout, HTTP/3 frames and
  QPACK streams. Standalone: `python scripts/h3_capture.py serve --port 4433`; point a device
  (Safari, an app) at it and get the capture on Ctrl+C.
- The mapping of captures to profiles is `PROFILE_SOURCES` in `scripts/h3_profiles.py`.
- `tests/test_h3_fingerprints.py` checks each profile that has a capture against
  `native/h3profiles.json`.

## CI and releases

- `.github/workflows/test.yml`: on every push and PR, `third_party.py check`, build, Go tests,
  pytest on Windows, Linux and macOS.
- `.github/workflows/release.yml`: builds 4 wheels (Windows x64, manylinux2014 x86_64 and
  aarch64, macOS universal2), runs `check_wheel.py`, smoke-tests each wheel on 5 runners ×
  Python 3.11–3.14 and on an image with glibc 2.17, and publishes to PyPI through Trusted
  Publishing. A dry run without publishing: `gh workflow run release.yml --ref <branch> -f publish=false`.

Releasing a version:

1. The version goes in `pyproject.toml` and `yumeclient/__init__.py` (`__version__`; a test
   checks that they match). In `CHANGELOG.md` and `CHANGELOG.ru.md`, `[Unreleased]` becomes
   `[X.Y.Z] — date` (the PyPI upload date, UTC), and the link definitions at the end of the
   file get the new version.
2. Green `test.yml` and a dry run of `release.yml` on the branch.
3. Merge into `main`, tag `vX.Y.Z`, create a GitHub Release (the text is the `CHANGELOG.md`
   section). The release triggers publishing to PyPI.
4. Check: `pip install yumeclient==X.Y.Z` in a clean environment and
   `python scripts/smoke_wheel.py`.
