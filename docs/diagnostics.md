# Diagnostics: profiles, fingerprint diffs, traces

**English** | [Русский](ru/diagnostics.md)

Three tools:

- **`export_profile` / `from_profile`**: save a session's configuration to JSON and restore it
  on another machine;
- **`fingerprint_diff`**: check that a request went out with the expected fingerprint;
- **`Response.trace()`**: describe a request and its response without secrets, to attach to a
  bug report.

The fingerprint of a single response (`r.fingerprint`) and the connection details
(`r.connection_info`) are described in [Responses and streaming](responses.md).

```python
import json
from yumeclient import Session, fingerprint_diff

with Session(client_identifier="chrome_146", http_version="2") as s:
    s.get("https://example.com/")
    profile = s.export_profile()

with open("profile.json", "w") as f:
    json.dump(profile, f, indent=1)

# later, on another machine
with open("profile.json") as f:
    profile = json.load(f)
with Session.from_profile(profile, proxy="socks5://127.0.0.1:1080") as s:
    r = s.get("https://example.com/")
    problems = [d for d in fingerprint_diff(profile, r) if d["kind"] != "order"]
    print(problems or "same fingerprint")
    print(json.dumps(r.trace(), indent=1))
```

## `export_profile`

```python
profile = session.export_profile(include_fingerprint=True, include_secrets=False)
```

Returns a dictionary that can be serialized to JSON:

```python
{
    "format": "yumeclient.profile",
    "version": 1,
    "yumeclient": "0.8.3",
    "transport": {                       # parameters that define the fingerprint
        "client_identifier": "chrome_146",
        "client_os": "windows",
        "header_style": "raw",
        "http_version": "auto",
        # + all explicitly passed ClientHello / HTTP/2 / HTTP/3 parameters
    },
    "headers": [["Connection", "keep-alive"], ["sec-ch-ua", "..."], ...],  # in the order they are sent
    "omitted_headers": ["Authorization", "X-Api-Key"],
    "fingerprint": {                     # the session's last fingerprint (if a request was made)
        "ja3": "...", "ja3_hash_md5": "...", "ja4": "...", "ja4_r": "...",
        "akamai_fingerprint": "...", "alpn_offered": [...], "tls_extensions": [...],
        "header_order": [...], "source": "wire",
    },
}
```

**What goes into `transport`:** the profile, the OS, the header style, `http_version`, and the
explicitly set fingerprint parameters: `ja3_string`, the ClientHello lists, `h2_settings`,
`pseudo_header_order`, `random_tls_extension_order`, `force_http1`, `disable_http3`,
`keep_alpn`, `trust_anchors_payload` and others. Values equal to the defaults are not written.
Byte fields (`ech_config_list`, `key_share_data`) are encoded in base64,
`trust_anchors_payload` in hex.

**What does not go in:** the proxy, `udp_proxy`, timeouts, cookies, `verify`, `local_address`,
`max_content_size`. These are environment, secrets or limits, not the fingerprint. Pass them as
`overrides` when restoring.

**Headers with credentials** are not exported: `Authorization`, `Cookie`, and headers whose
name contains `token`, `secret`, `session`, `auth`, `key`, `cookie`, `passw`,
`signature`, `credential`. Their names are listed in `omitted_headers`. Set them again after
`from_profile`, or export them with their values: `export_profile(include_secrets=True)`.

`include_fingerprint=False` leaves out the `fingerprint` block.

`fingerprint.header_order` does not include headers that depend on the particular request:
`Cookie`, `Content-Length`, `Content-Type`, `Authorization`, `Referer`, `Origin`,
`Range` and the conditional ones (`If-*`).

## `from_profile`

```python
session = Session.from_profile(profile, **overrides)
session = AsyncSession.from_profile(profile, **overrides)
```

Creates a session from an `export_profile` document. The transport parameters and headers are
restored exactly: the order, the spelling of names, the removed headers. `overrides` are any
constructor parameters (`proxy=`, `timeout=`, `verify=`, `cookies=`...); they override the
values from the profile.

Errors (`SessionConfigurationError`):

| Document | Message |
|---|---|
| a different `format` | `not a yumeclient.profile document` |
| `version` newer than supported | `profile version 2 is newer than this yumeclient supports (1); upgrade yumeclient` |
| `version` is not an integer | `invalid profile version: '1'` |
| an unknown parameter in `transport` (for example, `proxy`) | `unknown profile option(s): proxy` |
| `headers` is not a list of pairs | `profile 'headers' must be a list of [name, value] pairs` |
| conflicting parameters | the same message as from the constructor |

## `fingerprint_diff`

```python
differences = fingerprint_diff(expected, actual)
```

`expected` and `actual` are a `Response`, an `export_profile` document, or a fingerprint
dictionary (`r.fingerprint`). Only the fields present in `expected` are checked. An empty list
means the fingerprints match.

Each difference is a dictionary `{"field", "kind", "expected", "actual"}` (for `set`, also
`missing` and `unexpected`):

| `kind` | Meaning |
|---|---|
| `value` | the values differ |
| `missing` | the field is in `expected` but not in `actual` |
| `order` | the same elements in a different order |
| `set` | a different set of elements; `missing` is what `actual` lacks, `unexpected` is what is extra |

Compared fields: `ja4`, `ja4_r`, `ja3` (by component: `ja3.version`, `ja3.ciphers`,
`ja3.extensions`, `ja3.groups`, `ja3.point_formats`), `ja3_hash_md5` (only if `ja3` is not
set), `akamai_fingerprint`, `alpn_offered`, `alpn_negotiated`, `tls_version`, `tls_cipher`,
`http_protocol`, `tls_extensions`, `header_order`. GREASE values are ignored.

**Chromium's extension order is random.** Chrome shuffles the extensions on every connection,
and the Chromium profiles do the same (`random_tls_extension_order=True`). So two requests with
the same profile give `kind="order"` differences in `ja3.extensions` and `tls_extensions`; this
is expected. JA4 does not depend on the order. Filter them out:

```python
real = [d for d in fingerprint_diff(profile, r) if d["kind"] != "order"]
```

Example of the differences between `chrome_146` and `firefox_147`:

```python
[("ja4", "value"), ("ja4_r", "value"), ("ja3.ciphers", "set"), ("ja3.extensions", "set"),
 ("ja3.groups", "set"), ("akamai_fingerprint", "value"), ("tls_extensions", "set"),
 ("header_order", "set")]
```

## `Response.trace`

```python
trace = response.trace(redact=(), values=True, redact_query=True)
```

Returns a JSON-compatible description of the request and the response:

```python
{
    "format": "yumeclient.trace", "version": 1, "yumeclient": "0.8.3",
    "request_id": "16a39d51...", "elapsed": 0.058,
    "request": {
        "method": "GET",
        "url": "https://example.com/x?token=[redacted]&q=[redacted]",
        "header_order": [...], "header_source": "wire",
        "headers": [["Host", "example.com"], ["Connection", "keep-alive"], ...],
        "body": {"length": 0, "sha256": "..."},
    },
    "response": {"status": 200, "url": "...", "http_protocol": "HTTP/2.0",
                 "headers": [...], "body": {"length": 1256, "sha256": "..."}},
    "redirects": [{"status": 302, "url": "..."}],   # history hops: status and URL
    "connection": {"alpn_negotiated": "h2", "tls_version": "1.3", "tls_cipher": "...",
                   "tls_resumed": False, "connection_reused": False,
                   "remote_address": "...", "timings": {...}},
    "tls": {"ja3": "...", "ja4": "...", "ja4_r": "...", "akamai_fingerprint": "..."},
}
```

What is hidden:

- **URLs:** the username and password are removed, and so is the fragment. Query parameter
  values are replaced with `[redacted]`; a query part without `=` is hidden entirely. The path
  is not changed. The same applies to the URL headers `Location`, `Content-Location`, `Referer`,
  `Origin`, `Link`, `Refresh`. `redact_query=False` leaves the query as it is.
- **Headers:** the values of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and
  of headers whose name contains `token`, `secret`, `session`, `auth`, `key`, `cookie`,
  `passw`, `signature`, `credential`, are replaced with `"[redacted]"`. `redact=("X-Trace",)`
  adds your own names. `values=False` removes the values of all headers (the names and the
  order remain).
- **Bodies:** only the length and SHA-256. For a request body larger than 8 MiB, only the length.

The SHA-256 of a short body with a secret (for example, a password in a form) can be
brute-forced. Keep this in mind before publishing a trace.

The request headers in the trace are in the order they were sent (`header_source: "wire"`),
including the ones added by the transport (`Host`, `Accept-Encoding`, `Content-Length`).

## Reference profile fingerprints

`tests/fixtures/profiles.json` stores a reference for each profile: JA3, JA4, JA4_r, ALPN,
extension order, Akamai, header order. The test `tests/test_profile_fixtures.py` compares the
current build with it.

```bash
python scripts/profile_fixtures.py            # show the differences
python scripts/profile_fixtures.py --update   # overwrite the reference
```

HTTP/3 fingerprints are stored separately, in `native/h3profiles.json`; they are checked by
`tests/test_h3_fingerprints.py`. For how to capture new recordings, see
[Development](development.md).
