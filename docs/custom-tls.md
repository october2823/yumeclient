# Custom TLS fingerprint

**English** | [Русский](ru/custom-tls.md)

The ready-made [profiles](profiles.md) cover most needs: each has a ClientHello, HTTP/2, HTTP/3
and headers captured from a real client. A custom fingerprint is needed when the client is not
in the list. For example, you have a traffic capture of an app, or a JA3 from server logs. You
set it with the `ja3_string` parameter and the set of low-level parameters on this page.

```python
from yumeclient import Session

JA3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
       "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037,4588-29-23-24,0")

with Session(ja3_string=JA3, random_tls_extension_order=False) as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.fingerprint["ja3"] == JA3)          # True: the extension order is as in the JA3
    print(r.fingerprint["ja4"])
```

`ja3_string` cannot be combined with `client_identifier`: a session has either a profile or a
custom fingerprint. A session with a custom fingerprint has `client_identifier == ""`. The
default headers come from `chrome_152` unless `header_style` is set.

## What JA3 sets and what it does not

JA3 is five comma-separated fields: `version,ciphers,extensions,groups,point formats`. Each
field is a list of decimal numbers separated by `-`. JA3 sets:

- the version from `ClientHello.legacy_version` (`771` = TLS 1.2, as in all modern clients);
- the cipher suites and their order;
- **which** extensions are present and in what order;
- the groups (`supported_groups`) and the EC point formats.

JA3 does **not** set the contents of most extensions (signatures, versions, key shares, ALPN,
ALPS, certificate compression, ECH), GREASE, or the HTTP/2 and HTTP/3 parameters. These parts
come from explicit parameters, and whatever is not set is filled in:

| `fill_custom_with_chrome_defaults` | What fills in the unset parts |
|---|---|
| `True` (default) | the values of `Profiles.LATEST_CHROME` (`chrome_152`): signature algorithms, versions, key shares (only for groups from the JA3), ALPN and ALPS, certificate compression, ECH GREASE, `trust_anchors`, HTTP/2 SETTINGS, WINDOW_UPDATE, HEADERS priority, pseudo-header order, the HTTP/3 fingerprint and the `priority` header |
| `False` | generic values: versions TLS 1.3 and 1.2, signatures `0403,0804,0805,0806,0401,0501,0601`, ALPN `h2,http/1.1`, HTTP/2 `1:65536;2:0;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p`, HTTP/3: quic-go values |

An explicitly set parameter always wins over the filling. Two more rules apply in both modes:

- extension 27 (`compress_certificate`) without `cert_compression_algos` gets brotli, and
  extension 28 (`record_size_limit`) gets the value 16385;
- if `key_share_curves` is not set and Chrome's key shares do not fit the JA3, the first two
  groups from the JA3 get a key share. If X25519 is listed further on, it gets a key share too.
  The hybrid `X25519MLKEM768` gets a key share only together with X25519, as in Chrome.

### Supported extensions

A JA3 may use extensions with these ids:
`0 5 10 11 13 16 18 21 22 23 27 28 34 35 41 42 43 44 45 51 13172 17513 17613 51764 65037 65281`
and GREASE (`2570`, `6682`, ..., `64250`). A JA3 with any other id cannot be built. The first
request raises the error: `InvalidRequestError`, kind `configuration`, text
`client creation failed: ja3_string: unknown extension with id N provided`.

## ClientHello parameters

All parameters in this section except `server_name_overwrite`, `disable_session_tickets` and
`random_tls_extension_order` require `ja3_string`. Without it: `SessionConfigurationError` ("... requires ja3_string").

| Parameter | Type | What it does |
|---|---|---|
| `supported_signature_algorithms` | list | extensions 13 (`signature_algorithms`) and 34 (`delegated_credentials`) |
| `supported_versions` | list | extension 43 |
| `key_share_curves` | list | which groups get a key share (extension 51) |
| `key_share_data` | `{group: bytes}` | ready-made key share bytes for a group, to reproduce a capture byte for byte |
| `alpn_protocols` | list of strings | extension 16 (ALPN), for example `["h2", "http/1.1"]` |
| `alps_protocols` | list of strings | ALPS extension (17513 or 17613), for example `["h2"]` |
| `cert_compression_algos` | list | extension 27 |
| `trust_anchors_payload` | `bytes` or hex | data of extension 51764 (`trust_anchors`, Chrome 146+) with a 2-byte length prefix |
| `ech_config_list` | `bytes` | real ECH ([below](#encrypted-client-hello)) |
| `tls_extension_order` | list of int | the exact extension order on the wire |
| `random_tls_extension_order` | `bool` | shuffle extensions on every connection, like Chrome (default `True`; for profiles it applies only to Chromium) |
| `grease` | `bool` | add (`True`) or remove (`False`) GREASE |
| `psk_mode` | `"psk"` / `"no_psk"` | keep or remove extension 45 (`psk_key_exchange_modes`) |
| `server_name_overwrite` | `str` | SNI instead of the host from the URL; works with profiles too |
| `disable_session_tickets` | `bool` | do not resume TLS sessions; works with profiles too |

### List values

Lists accept upstream names or numeric ids: an `int`, a decimal string or a string with `0x`.
An unknown value raises `SessionConfigurationError` before any network access. Upstream
silently dropped such a value from the hello.

| Parameter | Names | Example |
|---|---|---|
| `key_share_curves` | `X25519`, `X25519MLKEM768` (4588), `P256` (23), `P384` (24), `P521` (25), `X25519Kyber768` (0x6399), `X25519Kyber512D`, `X25519Kyber768Old`, `P256Kyber768`, `GREASE` | `["GREASE", "X25519MLKEM768", "X25519"]` |
| `supported_versions` | `"1.3"` (772), `"1.2"` (771), `"1.1"`, `"1.0"`, `GREASE` | `["GREASE", "1.3", "1.2"]` |
| `cert_compression_algos` | `zlib` (1), `brotli` (2), `zstd` (3) | `["brotli"]` |
| `supported_signature_algorithms` | `ECDSAWithP256AndSHA256`, `PSSWithSHA256`, `PKCS1WithSHA256`, `ECDSAWithP384AndSHA384`, `PSSWithSHA384`, `PKCS1WithSHA384`, `PSSWithSHA512`, `PKCS1WithSHA512`, `ECDSAWithP521AndSHA512`, `PKCS1WithSHA1`, `ECDSAWithSHA1`, `Ed25519`, `SHA224_RSA`, `SHA224_ECDSA` | `["ECDSAWithP256AndSHA256", 0x0804, "0401"]` |

For signatures, a string of digits without a leading zero is read as a decimal number
(`"1027"` = 0x0403). A string with a leading zero or with letters is read as hex (`"0403"`,
`"0x0804"`).

```python
with Session(ja3_string=JA3,
             supported_signature_algorithms=["ECDSAWithP256AndSHA256", "PSSWithSHA256", "PKCS1WithSHA256"],
             supported_versions=["GREASE", "1.3", "1.2"],
             key_share_curves=["GREASE", "X25519MLKEM768", "X25519"],
             alpn_protocols=["h2", "http/1.1"], alps_protocols=["h2"],
             cert_compression_algos=["brotli"]) as s:
    print(s.get("https://tls.peet.ws/api/all").fingerprint["ja4"])
```

### Extension order and GREASE

- `random_tls_extension_order=True` (the default) shuffles extensions on every connection the
  way Chrome does since version 110. This applies to a custom JA3 too, so
  `r.fingerprint["ja3"]` changes from connection to connection, while JA4 does not: JA4 sorts
  the extensions. For the fingerprint of a non-Chromium client, set `False`.
- `tls_extension_order=[...]` puts the extensions in exactly this order and turns off
  shuffling. Extensions missing from the list go after the listed ones.
- `grease=True` adds GREASE the way Apple CFNetwork does: a cipher suite at the start, an empty
  extension first and an extension with a `0x00` byte last, a value at the start of the
  groups, key shares and versions. `grease=False` removes all GREASE. Without the parameter,
  GREASE is present where it is given explicitly in the JA3 or in the lists, and in whatever is
  taken from Chrome: with `fill_custom_with_chrome_defaults=True` the `supported_versions` list
  is copied from Chrome together with GREASE. A JA3 measured from a real client has no GREASE:
  the JA3 definition drops it.

```python
APPLE_JA3 = ("771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-"
             "49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0")

with Session(ja3_string=APPLE_JA3, grease=True, random_tls_extension_order=False,
             fill_custom_with_chrome_defaults=False) as s:
    r = s.get("https://tls.peet.ws/api/all")
```

### Encrypted Client Hello

Without `ech_config_list`, extension 65037 from the JA3 is GREASE ECH, like Chrome without an
ECH config: the outer hello carries the real SNI. With `ech_config_list` the hello is really
encrypted (draft-ietf-tls-esni). The outer SNI is the `public_name` from the config, and the
real host goes inside the encrypted part.

```python
import base64

# ECHConfigList from the server's HTTPS DNS record (the ech= parameter, base64; truncated here)
ech = base64.b64decode("AEX+DQBB...")

with Session(ja3_string=JA3, ech_config_list=ech) as s:
    s.get("https://crypto.cloudflare.com/cdn-cgi/trace")
```

Requirements (otherwise `SessionConfigurationError`):

- the value is a serialized `ECHConfigList` with a 2-byte length prefix, exactly as in DNS;
- the JA3 has extension 65037;
- `http_version` is not `"3"`: ECH works only over TCP.

If the server did not accept the config (for example, the key changed), the handshake fails
with `TLSError`. In that case the certificate is verified for `public_name`, even with
`verify=False`. The library does not repeat the handshake with the `retry_configs` sent by the
server: take a fresh config from DNS and create a new session.

## HTTP/2 parameters

These parameters require `ja3_string`. Without them, the values come from
`chrome_152` (with `fill_custom_with_chrome_defaults=True`) or are generic (with `False`).

| Parameter | Example | On the wire |
|---|---|---|
| `h2_settings` | `{"HEADER_TABLE_SIZE": 65536, "INITIAL_WINDOW_SIZE": 6291456}` | SETTINGS frame |
| `h2_settings_order` | `["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE"]` | order of the entries in SETTINGS |
| `connection_flow` | `15663105` | connection WINDOW_UPDATE after SETTINGS |
| `pseudo_header_order` | `[":method", ":authority", ":scheme", ":path"]` | pseudo-header order |
| `header_priority` | `{"streamDep": 0, "exclusive": True, "weight": 255}` | priority in the HEADERS frame |
| `priority_frames` | `[{"streamID": 3, "priorityParam": {"streamDep": 0, "exclusive": False, "weight": 200}}]` | PRIORITY frames after SETTINGS (the `firefox_102`–`firefox_123` profiles) |

- `h2_settings` keys and `h2_settings_order` items accept RFC 9113 names
  (`HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`,
  `MAX_FRAME_SIZE`, `MAX_HEADER_LIST_SIZE`), `ENABLE_CONNECT_PROTOCOL` (8),
  `NO_RFC7540_PRIORITIES` (9), upstream names `UNKNOWN_SETTING_<id>` or the id itself (`9`,
  `"0x4a4a"`). Values are integers 0..2³²−1.
- If `h2_settings_order` is not set, the entries go in the key order of the `h2_settings` dict.
- `pseudo_header_order` must list all four pseudo-headers, each once. The forms `":method"`,
  `"method"` and `"m"` are equivalent.
- `weight` is the value on the wire (0–255). In the Akamai fingerprint it is one higher.

```python
FIREFOX_LIKE = dict(
    h2_settings={"HEADER_TABLE_SIZE": 65536, "INITIAL_WINDOW_SIZE": 131072, "MAX_FRAME_SIZE": 16384,
                 "NO_RFC7540_PRIORITIES": 1},
    h2_settings_order=["HEADER_TABLE_SIZE", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "NO_RFC7540_PRIORITIES"],
    connection_flow=12517377,
    pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
)

with Session(ja3_string=JA3, http_version="2", **FIREFOX_LIKE) as s:
    print(s.get("https://tls.peet.ws/api/all").fingerprint["akamai_fingerprint"])
    # 1:65536;4:131072;5:16384;9:1|12517377|0|m,p,a,s
```

## HTTP/3

A custom JA3 describes the TCP ClientHello. The QUIC handshake of browsers is different: TLS
1.3 only, transport parameters, and some of the TCP extensions are missing. So JA3 does not
define it.

- `fill_custom_with_chrome_defaults=True`: with `http_version="3"` the session uses the whole
  HTTP/3 fingerprint of `chrome_152`. That is its QUIC ClientHello, transport parameters,
  SETTINGS and priorities.
- `False`: quic-go defaults. This fingerprint does not look like any browser.
- A JA3 with `X25519MLKEM768` (4588), as in modern Chrome, does not get in the way of HTTP/3:
  the QUIC ClientHello is not taken from the JA3. Before 0.8.1, such a session silently stayed
  on TCP.

If you need the HTTP/3 of a specific browser, use its profile. The list of profiles with
captured HTTP/3 is `yumeclient.profiles.HTTP3_FINGERPRINTS`; see [Protocols](protocols.md#http3-and-quic) for details.

## How to reproduce a capture

1. Get the client's JA3, JA4 and Akamai fingerprint: from server logs, from `tls.peet.ws` or
   from your own capture (Wireshark 4.2+ shows JA3 and JA4 for a ClientHello).
2. Create a session with `ja3_string`. Choose `fill_custom_with_chrome_defaults`: `True` for
   Chromium clients, `False` for the others.
3. Set the extension contents: signatures, versions, key shares, ALPN, ALPS. For a
   non-Chromium client, turn off `random_tls_extension_order`.
4. Compare the result with the target using `yumeclient.fingerprint_diff(r.fingerprint, target)`
   ([Diagnostics](diagnostics.md)). The fingerprint in `r.fingerprint` is computed from the
   bytes that went out to the network.
5. Save the setup with `s.export_profile()` and create sessions with `Session.from_profile(...)`.

## Configuration errors

| Situation | Exception |
|---|---|
| `ja3_string` together with `client_identifier` | `SessionConfigurationError` before any network access |
| a parameter from this page without `ja3_string` | `SessionConfigurationError` before any network access |
| an unknown group, version, signature, compression algorithm or HTTP/2 setting name | `SessionConfigurationError` before any network access |
| an invalid `pseudo_header_order`, `ech_config_list` or `trust_anchors_payload` | `SessionConfigurationError` before any network access |
| a JA3 with an unsupported extension or a format error | `InvalidRequestError` (kind `configuration`) on the first request |
| the server rejected the hello (for example, a key share for a group that uTLS does not support) | `TLSError` |

Known limitation: if `X25519MLKEM768` (4588) is in the groups but has no key share, a server
with ML-KEM answers with a HelloRetryRequest. uTLS fails on such a reply with the error
`tls: CurvePreferences includes unsupported curve`. Send a key share for 4588 together with
X25519, as Chrome does; the default filling does this too.
