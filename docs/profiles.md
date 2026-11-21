# Profiles

**English** | [Русский](ru/profiles.md)

A profile (`client_identifier`) sets everything the server sees of the client before the
first byte of the response:

- TLS ClientHello: cipher suites, extensions and their order, groups and key shares, ALPN,
  GREASE, ECH;
- HTTP/2: SETTINGS, WINDOW_UPDATE, priorities, pseudo-header order;
- HTTP/3 and QUIC (53 profiles): the ClientHello inside QUIC, transport parameters, the layout
  of Initial packets, SETTINGS and QPACK ([Protocols](protocols.md#http3-and-quic));
- default headers and the HTTP layer (browser or okhttp).

```python
from yumeclient import Session, Profiles, ALL_IDENTIFIERS, find

Session(client_identifier="firefox_148")
Session(client_identifier=Profiles.SAFARI_IOS_18_5)
find("safari_ios")         # ['safari_ios_15_5', 'safari_ios_15_6', ..., 'safari_ios_26_0']
len(ALL_IDENTIFIERS)       # 93
```

The default is `Profiles.LATEST_CHROME` (`"chrome_152"`). `Profiles.<NAME>` holds constants for
all profiles (the name in upper case). An unknown profile raises `SessionConfigurationError`
that lists similar names.

## Profile list

| Family | Profiles | HTTP/3 |
|---|---|---|
| Chrome | `chrome_103` … `chrome_112`, `chrome_116_PSK`, `chrome_116_PSK_PQ`, `chrome_117`, `chrome_120`, `chrome_124`, `chrome_130_PSK`, `chrome_131`, `chrome_131_PSK`, `chrome_133`, `chrome_133_PSK`, `chrome_144`, `chrome_144_PSK`, `chrome_146`, `chrome_146_PSK`, `chrome_150`, `chrome_150_PSK`, `chrome_152`, `chrome_152_PSK` | recorded from the browser |
| Edge | `edge_99`, `edge_101`, `edge_131`, `edge_latest` (= 131) | Chromium of the same version |
| Brave | `brave_146`, `brave_146_PSK` | Chromium 146 |
| Opera | `opera_89`, `opera_90`, `opera_91` | recorded from the browser |
| Firefox | `firefox_102` … `firefox_135` (102, 104, 105, 106, 108, 110, 117, 120, 123, 132, 133, 135), `firefox_146_PSK`, `firefox_147`, `firefox_147_PSK`, `firefox_148` | recorded from the browser |
| Tor Browser | `tor_145` (Firefox ESR 128 TLS) | no, Tor does not use HTTP/3 |
| Safari macOS | `safari_15_6_1`, `safari_16_0`, `safari_macos_17_0`, `safari_macos_18_0`, `safari_macos_26_0` | library values |
| Safari iOS / iPadOS | `safari_ios_15_5`, `safari_ios_15_6`, `safari_ios_16_0`, `safari_ios_17_0`, `safari_ios_18_0`, `safari_ios_18_5`, `safari_ios_26_0`, `safari_ipad_15_6` | library values |
| Android, okhttp | `okhttp4_android_7` … `okhttp4_android_13`, `okhttp4_conscrypt`, `conscrypt_android_latest` | no |
| Apps | `zalando_android_mobile`, `zalando_ios_mobile`, `nike_android_mobile`, `nike_ios_mobile`, `mms_ios`, `mms_ios_1` … `_3`, `mesh_ios`, `mesh_ios_1`, `mesh_ios_2`, `mesh_android`, `mesh_android_1`, `mesh_android_2`, `confirmed_ios`, `confirmed_android` | library values |
| Other | `cloudscraper` (TLS 1.2, CBC cipher suites only) | no |

Suffixes:

- `_PSK`: a ClientHello with the `pre_shared_key` extension. Repeat connections to a server
  that issued a ticket resume the TLS 1.3 session, like a browser on a repeat visit. Without
  `_PSK`, every connection is a full handshake.
- `_PQ`: with post-quantum key exchange (`chrome_116_PSK_PQ`: X25519Kyber768, like Chrome 116
  with PostQuantumKyber enabled).

83 profiles come from [tls-client](https://github.com/bogdanfinn/tls-client) v1.16.0, and 10
were added by yumeclient: `edge_*`, `tor_145`, `safari_macos_*`, `conscrypt_android_latest`,
`okhttp4_conscrypt`. The reference ClientHello of each profile (JA3, JA4, ALPN, extension
order, Akamai) is stored in `tests/fixtures/profiles.json`; a test checks every build against it.

### Notes by family

- **Chromium** (Chrome, Edge, Brave, Opera) shuffles the ClientHello extensions on every
  connection; `random_tls_extension_order=True` (the default) does the same. Other stacks send
  their own fixed order, and the parameter has no effect on them.
- **Edge** uses the Chromium TLS stack (`edge_99` = the Chrome 100 hello, `edge_101` = Chrome
  110, `edge_131`/`edge_latest` = Chrome 131) with Edge headers (`Edg/`, the brand in
  `Sec-CH-UA`); HTTP/2 SETTINGS, `priority` and HTTP/3 are those of Chromium of the same version.
- **Safari 17+ on macOS**: Apple has not changed the ClientHello since Safari 16, so
  `safari_macos_*` has the same JA4 as `safari_16_0`; the headers differ.
- **Android apps on okhttp**: `okhttp4_android_7` … `_9` are the TLS 1.2 of old Android;
  `okhttp4_android_10` … `_13`, `conscrypt_android_latest` and `okhttp4_conscrypt` are one and
  the same ClientHello of modern Android (okhttp on top of the system Conscrypt, TLS 1.3): 15
  cipher suites without GREASE, 13 extensions with padding to 512 bytes, X25519 as the only key
  share. A repeat connection with a ticket sends a resumption hello with `pre_shared_key` (turn
  it off with `disable_session_tickets=True`). HTTP/2 is like okhttp: Akamai
  `4:16777216|16711681|0|m,p,a,s`. For an app on current Android, use
  `conscrypt_android_latest` or `okhttp4_conscrypt`.
- **cloudscraper**: TLS 1.2, CBC cipher suites only, and `encrypt_then_mac` (RFC 7366, fully
  implemented; it also works with OpenSSL servers).
- Clients without HTTP/3 (`profiles.NO_HTTP3`: `okhttp4_*`, `okhttp4_conscrypt`,
  `conscrypt_android_latest`, `cloudscraper`, `tor_145`) raise `SessionConfigurationError`
  with `http_version="3"`: the real clients do not use QUIC.

## client_os

`client_os` is `"windows"`, `"macos"`, `"android"` or `"ios"`. It changes only the default
headers, not TLS: Chrome sends the same ClientHello on Windows and on Android. What exactly
changes for Chromium: on every OS, the User-Agent and `sec-ch-ua-platform`; on `android`, also
`sec-ch-ua-mobile: ?1`, and there is no `Upgrade-Insecure-Requests` or `Sec-Fetch-User`; on
`ios`, the whole set (Chrome on iOS runs on WebKit: User-Agent `CriOS`, no client hints and no
`Sec-Fetch-*`). Only the desktop variants (Windows) are checked against browser captures.

By default the OS is derived from the profile: `*_ios*`, `safari_ipad_*` → `ios`;
`*_android*`, `okhttp4_*`, `conscrypt_*` → `android`; `safari_15_6_1`, `safari_16_0`,
`safari_macos_*` → `macos`; all others → `windows`.

```python
Session(client_identifier="chrome_152", client_os="android")   # Chrome on Android
Session(client_identifier="chrome_152", client_os="ios")       # CriOS: no client hints, like the real Chrome on iOS
```

## Default headers

A session does not start with empty headers. It starts with the headers the browser sends when
it navigates to a page, in the browser's order and spelling. For Chrome, Edge, Brave, Opera,
Firefox and Tor they are checked against captures from the browsers themselves
(`tests/fixtures/browser_headers.json`) over HTTP/1.1 and HTTP/2:

- the set, order and values depend on the version: `Sec-CH-UA` follows the Chromium algorithm
  (the GREASE brand, its version and the brand order change from version to version), `Accept`
  has `signed-exchange;v=b3;q=0.9` up to Chrome 109 and `q=0.7` from Chrome 110, `zstd` is in
  `Accept-Encoding` from Chrome 123 and Firefox 128, and so on;
- over HTTP/1.1, `Host` comes first, `Connection: keep-alive` is sent, and names are spelled as
  the browser spells them (`User-Agent`, but `sec-ch-ua` in Chromium);
- over HTTP/2 and HTTP/3, names are lower case and `Connection` is not sent;
- Chromium from version 124 adds `priority: u=0, i` last over HTTP/2 and HTTP/3; Firefox from
  128 sends `Priority: u=0, i` over all protocols, and also `te: trailers` over HTTP/2.

```python
from yumeclient import default_headers, profiles

default_headers("chrome_152")                 # Headers: the profile's default headers
default_headers("firefox_148", "macos")
profiles.sec_ch_ua(131, "Microsoft Edge")     # Sec-CH-UA of Chromium 131 with the Edge brand
```

**Safari and apps have no captures.** For `safari_*` and `mms_*` the default set is four
headers (`user-agent`, `accept`, `accept-language`, `accept-encoding`); for the other apps it
is a plausible set for the app. They are not checked against devices: they lack the
`Sec-Fetch-*` and `Priority` headers that modern Safari sends, and the names are lower case
even over HTTP/1.1 (Safari capitalizes them). Over HTTP/2 and HTTP/3 case does not matter. For
exact emulation, set the headers yourself (`s.headers = {...}`, the order with
`header_order`); pass the User-Agent and the headers of a specific app yourself too.

## okhttp HTTP layer

`header_style="okhttp"` builds the request the way okhttp 4.x builds it (`BridgeInterceptor`).
It is the default style for `okhttp4_*`, `okhttp4_conscrypt` and `conscrypt_android_latest`
(`profiles.OKHTTP_IDENTIFIERS`); the other profiles use `"raw"`.

```
POST /v1/api HTTP/1.1
x-app-version: 5.2.0               ← app headers: as passed, in order
user-agent: MyApp/5.2.0 (Android 14)
Content-Type: application/json     ← on requests with a body
Content-Length: 9
Host: api.example.com
Connection: Keep-Alive
Accept-Encoding: gzip              ← if you did not set Accept-Encoding or Range
Cookie: a=1; b=2                   ← from the cookie jar
User-Agent: okhttp/4.12.0          ← if you did not set your own user-agent
```

- The session starts with empty headers: okhttp has no app-level headers.
- The `Host`, `Connection`, `Accept-Encoding` and `User-Agent` that you set stay in your
  position and in your casing; okhttp adds only the missing ones. `None` removes them as well.
- `json=` gives `application/json`, `data=dict` gives `application/x-www-form-urlencoded`, and
  `data=bytes` has no implicit `Content-Type` (like a `RequestBody` without a `MediaType`). If
  the app sends `application/json; charset=utf-8`, pass it explicitly.
- Connections are reused as in the okhttp `ConnectionPool`: up to 5 idle ones for 5 minutes.
- A request of up to 8 KiB (headers and body) goes out in one write, as one TLS record, like
  Conscrypt does.
- HTTP/2: the same order, `Host` becomes `:authority`; SETTINGS `4:16777216`, WINDOW_UPDATE
  `16711681`, pseudo-headers `m,p,a,s`, first stream id 3. One difference from okhttp: the
  HTTP/2 encoder splits `cookie` into separate fields, while okhttp sends one.
- Redirects: a 302 after POST becomes a GET without a body and without `Referer`; a 307 keeps
  the body.
- Checked byte for byte against real okhttp 4.12.0 on the same local server.

`header_style="raw"` on an okhttp profile restores the normal behavior: headers exactly as
passed.
