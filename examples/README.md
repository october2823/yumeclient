# Examples

**English** | [Русский](README.ru.md)

Each script is a complete program. By default they send requests to `https://httpbin.org`;
without internet access, start the local replacement and give its address:

```bash
python tests/httpbin_local.py 8080 &
HTTPBIN=http://127.0.0.1:8080 python examples/quickstart.py
```

| Script | What it shows |
|---|---|
| [quickstart.py](quickstart.py) | one-shot request, session, request parameters, JSON, form, status codes, redirects |
| [async_requests.py](async_requests.py) | `AsyncSession`: concurrent requests, limiting concurrency, timeout, cancellation |
| [profiles_and_headers.py](profiles_and_headers.py) | choosing a profile and OS, default headers, adding, removing and ordering headers, okhttp |
| [cookies.py](cookies.py) | cookie jar, manual cookies, per-request cookies, saving to a file and loading |
| [streaming_download.py](streaming_download.py) | downloading to a file in chunks, `max_content_size`, async stream |
| [upload_files.py](upload_files.py) | uploading files (multipart/form-data) |
| [errors_and_retries.py](errors_and_retries.py) | exception types, their fields, built-in retries (`retries=`) and your own retry loop |
| [proxies.py](proxies.py) | session proxy, a different proxy or no proxy for a single request (`PROXY=...`) |
| [fingerprint.py](fingerprint.py) | JA3/JA4/Akamai, fingerprint comparison, profile export, trace for a bug report |
| [custom_ja3.py](custom_ja3.py) | custom ClientHello from JA3 and HTTP/2 parameters, like Firefox |

All examples run in the tests (`tests/test_examples.py`) against a local server.
