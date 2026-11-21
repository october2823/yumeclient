# Contributing to yumeclient

**English** | [Русский](CONTRIBUTING.ru.md)

Bug reports, fingerprint captures and pull requests are welcome. Write in English or Russian.
Vulnerabilities are reported privately, see [SECURITY.md](SECURITY.md). Everyone taking part
follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a bug

Open an issue with the "Bug report" form and include:

- `yumeclient.__version__`, the Python version and the OS;
- the profile (`client_identifier`) and the session options;
- the smallest code that shows the problem, and what you expected instead;
- for an exception: its type and the `kind`, `stage` and `retryable` attributes
  ([timeouts and errors](docs/timeouts-and-errors.md));
- for a wrong request or response: the output of `r.trace()`. It hides query values, cookies,
  credentials and token-like headers, and keeps only the length and SHA-256 of the bodies
  ([diagnostics](docs/diagnostics.md#responsetrace)). Read it before you post it.

## Reporting a fingerprint mismatch

If a profile does not look like the browser or app it is named after, open an issue with the
"Fingerprint mismatch" form. Say what differs and how you know it:

- the same page fetched by the real client and by yumeclient, for example the JSON of
  `https://tls.peet.ws/api/all` opened in the browser and `r.fingerprint` from yumeclient;
- the browser version, its OS and the network (proxy, VPN), since some fields depend on them.

Safari on macOS, iOS and iPadOS and the mobile app profiles have not been captured from real
devices yet ([limitations](docs/limitations.md)). Captures from those devices help the most.
How to record an HTTP/3 handshake with `scripts/h3_capture.py` is described in
[development](docs/development.md#http3-and-quic).

## Pull requests

Build and test (Go 1.24.1+ and a C compiler; on Windows, MinGW-w64 `gcc` in `PATH`):

```bash
./scripts/build-native.ps1          # Windows; Linux/macOS: sh ./scripts/build-native.sh
pip install -e ".[test]"
python -m pytest -q                 # offline: the tests start their own local servers
(cd native && go test ./...)
python scripts/third_party.py check
```

- **A fix comes with a test that fails without it.** The tests run against local servers
  (HTTP/1.1, HTTP/2 on raw frames, HTTP/3 on aioquic, HTTP CONNECT and SOCKS5 proxies) and do
  not need the internet. To check a test against the previous release, point
  `YUMECLIENT_LIBRARY` at the native library of that release.
- **Upstream modules** (`native/third_party/`) are patched copies. Edit the copy, run
  `python scripts/third_party.py diff` and commit both the copy and the patch in
  `native/third_party/patches/`. Mark each change with a `// yumeclient: <reason>` comment.
  CI checks that every copy equals upstream plus its patch.
- **Keep the diff focused.** Do not reformat code you do not change: some Go files are not
  gofmt-formatted, and a whole-file reformat would hide the real change.
- **Documentation is in two languages.** English pages are at the usual paths (`docs/*.md`,
  `USAGE.md`, ...), Russian ones next to them (`docs/ru/*.md`, `USAGE.ru.md`, ...). Change
  both; `tests/test_docs_i18n.py` checks that the two versions have the same structure. If you
  can write only one of the languages, say so in the pull request.
- **Documentation follows the code.** Defaults, exception types, error messages and behavior on
  the wire in the docs are checked against the code or a test. Scripts in `examples/` run in
  the test suite, and Python snippets in the docs must compile.
- **Changelog.** Describe user-visible changes under `[Unreleased]` in `CHANGELOG.md` and
  `CHANGELOG.ru.md`.

The project layout, recording browser fingerprints and the release process are described in
[development](docs/development.md).

By contributing, you agree that your contribution is licensed under the [MIT license](LICENSE).
