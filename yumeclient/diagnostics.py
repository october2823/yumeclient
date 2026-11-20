"""Reproducible TLS configuration and diagnostics (0.6.0).

* :func:`export_profile` / :func:`profile_options`: a versioned, JSON-safe snapshot of a
  session's TLS/HTTP identity (``Session.export_profile()`` / ``Session.from_profile()``).
* :func:`fingerprint_diff`: field-by-field comparison of two fingerprints.
* :func:`request_trace`: a redacted, shareable description of one request
  (``Response.trace()``): header order, ALPN, protocol, TLS fingerprint, body hashes.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

PROFILE_FORMAT = "yumeclient.profile"
PROFILE_VERSION = 1
TRACE_FORMAT = "yumeclient.trace"
TRACE_VERSION = 1

# constructor options that shape the ClientHello / HTTP layer. Not part of a profile:
# proxy, udp_proxy, timeout, cookies, verify, trust_anchors_payload, local_address,
# max_content_size (environment, secrets or limits, not identity)
_IDENTITY_OPTIONS = (
    "client_identifier", "client_os", "header_style", "http_version", "random_tls_extension_order",
    "header_order", "force_http1", "disable_http3", "disable_session_tickets", "server_name_overwrite",
    "keep_alpn", "ja3_string", "supported_signature_algorithms", "key_share_curves", "supported_versions",
    "alpn_protocols", "alps_protocols", "cert_compression_algos", "h2_settings", "h2_settings_order",
    "connection_flow", "pseudo_header_order", "priority_frames", "header_priority",
    "fill_custom_with_chrome_defaults", "tls_extension_order", "ech_config_list", "grease", "psk_mode",
    "key_share_data")
_FINGERPRINT_KEYS = ("ja3", "ja3_hash_md5", "ja4", "ja4_r", "akamai_fingerprint", "alpn_offered",
                     "tls_extensions", "header_order", "source")

# compared by fingerprint_diff, in this order
_DIFF_FIELDS = ("ja4", "ja4_r", "ja3", "ja3_hash_md5", "akamai_fingerprint", "alpn_offered", "alpn_negotiated",
                "tls_version", "tls_cipher", "http_protocol", "tls_extensions", "header_order")
_JA3_PARTS = ("version", "ciphers", "extensions", "groups", "point_formats")
# present or not depending on the request (state, body, credentials), not on the profile:
# left out of header_order comparisons and exported profiles
_REQUEST_DEPENDENT = frozenset({"cookie", "content-length", "content-type", "transfer-encoding", "authorization",
                                "proxy-authorization", "referer", "origin", "range", "if-none-match",
                                "if-modified-since", "if-match", "if-unmodified-since", "if-range"})

_SENSITIVE_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
                                "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
                                "x-amz-security-token"})
_SENSITIVE_PARTS = re.compile(r"token|secret|passw|session|signature|auth|key|cookie|credential", re.I)
# headers whose value is (or contains) a URL: query values redacted like the request URL
_URL_HEADERS = frozenset({"location", "content-location", "referer", "origin", ":path"})
REDACTED = "[redacted]"
_HASH_LIMIT = 8 << 20  # request bodies above this are not hashed (cost); length is always reported


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------

def _jsonable(name: str, value: Any) -> Any:
    if name == "ech_config_list" and value is not None:
        return base64.b64encode(bytes(value)).decode("ascii")
    if name == "key_share_data" and value is not None:
        return {str(int(group)): base64.b64encode(bytes(data)).decode("ascii") for group, data in value.items()}
    if isinstance(value, tuple): return list(value)
    return value


def _native(name: str, value: Any) -> Any:
    if name == "ech_config_list" and value is not None:
        return base64.b64decode(value)
    if name == "key_share_data" and value is not None:
        return {int(group): base64.b64decode(data) for group, data in value.items()}
    return value


def _fingerprintOf(obj: Any) -> dict[str, Any]:
    """Fingerprint dict of a Response, an exported profile or a plain mapping."""
    if hasattr(obj, "fingerprint") and hasattr(obj, "status_code"):  # Response
        fp = dict(obj.fingerprint or {})
        for key, value in (obj.connection_info or {}).items():
            fp.setdefault(key, value)
    elif isinstance(obj, Mapping) and obj.get("format") == PROFILE_FORMAT:
        fp = dict(obj.get("fingerprint") or {})
    elif isinstance(obj, Mapping):
        fp = dict(obj)
    else:
        raise TypeError("expected a Response, an exported profile or a fingerprint mapping")
    if "header_order" not in fp and fp.get("request_headers"):
        fp["header_order"] = _stableOrder(name for name, _ in fp["request_headers"])
    return fp


def _stableOrder(names: Iterable[Any]) -> list[str]:
    return [lowered for lowered in (str(name).lower() for name in names) if lowered not in _REQUEST_DEPENDENT]


def export_profile(session: Any, *, include_fingerprint: bool = True, include_secrets: bool = False) -> dict[str, Any]:
    """Versioned, JSON-safe snapshot of ``session``'s TLS/HTTP identity.

    Contains the resolved profile name, OS and header style, every explicitly set
    ClientHello/HTTP option, the session's default headers in wire order and (when a
    request was made) the last observed fingerprint. Proxy, timeouts, cookies, certificate
    settings and the local address are deliberately not included, nor are credential-like
    default headers unless ``include_secrets=True`` (their names go to ``omitted_headers``).
    """
    from . import __version__
    core = session._core
    options = core._options
    transport: dict[str, Any] = {}
    for name in _IDENTITY_OPTIONS:
        if name == "client_identifier":
            value = core.client_identifier or None
        elif name == "client_os":
            value = core.client_os if core.client_identifier else options.get("client_os")
        elif name == "header_style":
            value = core.header_style
        elif name == "http_version":
            value = core.http_version
        else:
            if name not in options: continue
            value = options[name]
        if value is None: continue
        transport[name] = _jsonable(name, value)
    headers, omitted = [], []
    for name, value in core.headers.items():
        if not include_secrets and _sensitive(name, frozenset()): omitted.append(name)
        else: headers.append([name, value])
    profile: dict[str, Any] = {"format": PROFILE_FORMAT, "version": PROFILE_VERSION, "yumeclient": __version__,
                               "transport": transport, "headers": headers}
    if omitted: profile["omitted_headers"] = omitted
    if include_fingerprint and core.last_fingerprint:
        fp = _fingerprintOf(core.last_fingerprint)
        profile["fingerprint"] = {key: fp[key] for key in _FINGERPRINT_KEYS if fp.get(key) is not None}
    return profile


def profile_options(profile: Mapping[str, Any]) -> tuple[dict[str, Any], list[tuple[str, str]] | None]:
    """Session keyword arguments and default headers of an exported profile (validated)."""
    from . import SessionConfigurationError
    if not isinstance(profile, Mapping) or profile.get("format") != PROFILE_FORMAT:
        raise SessionConfigurationError(f"not a {PROFILE_FORMAT} document")
    version = profile.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise SessionConfigurationError(f"invalid profile version: {version!r}")
    if version > PROFILE_VERSION:
        raise SessionConfigurationError(f"profile version {version} is newer than this yumeclient supports "
                                        f"({PROFILE_VERSION}); upgrade yumeclient")
    transport = profile.get("transport") or {}
    if not isinstance(transport, Mapping): raise SessionConfigurationError("profile 'transport' must be an object")
    unknown = sorted(set(transport) - set(_IDENTITY_OPTIONS))
    if unknown: raise SessionConfigurationError(f"unknown profile option(s): {', '.join(unknown)}")
    kwargs = {name: _native(name, value) for name, value in transport.items()}
    headers = profile.get("headers")
    if headers is not None:
        try: headers = [(str(name), str(value)) for name, value in headers]
        except (TypeError, ValueError) as exc:
            raise SessionConfigurationError("profile 'headers' must be a list of [name, value] pairs") from exc
    return kwargs, headers


# ---------------------------------------------------------------------------
# fingerprint comparison
# ---------------------------------------------------------------------------

def _grease(value: Any) -> bool:
    return isinstance(value, int) and value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def _listDiff(field: str, expected: list[Any], actual: list[Any]) -> list[dict[str, Any]]:
    if expected == actual: return []
    if sorted(map(str, expected)) == sorted(map(str, actual)):
        return [{"field": field, "kind": "order", "expected": expected, "actual": actual}]
    return [{"field": field, "kind": "set", "expected": expected, "actual": actual,
             "missing": [x for x in expected if x not in actual],
             "unexpected": [x for x in actual if x not in expected]}]


def _ja3Diff(expected: str, actual: str) -> list[dict[str, Any]]:
    left, right = str(expected).split(","), str(actual).split(",")
    if len(left) != 5 or len(right) != 5:
        return [] if expected == actual else [{"field": "ja3", "kind": "value", "expected": expected, "actual": actual}]
    out: list[dict[str, Any]] = []
    for part, a, b in zip(_JA3_PARTS, left, right):
        if a == b: continue
        if part == "version":
            out.append({"field": "ja3.version", "kind": "value", "expected": a, "actual": b})
        else:
            out += _listDiff(f"ja3.{part}", a.split("-") if a else [], b.split("-") if b else [])
    return out


def fingerprint_diff(expected: Any, actual: Any) -> list[dict[str, Any]]:
    """Compare two fingerprints; an empty list means no difference.

    ``expected`` / ``actual``: a :class:`~yumeclient.Response`, an exported profile (its
    ``fingerprint``) or a fingerprint mapping. Only fields present in ``expected`` are
    checked. Each difference is ``{"field", "kind", "expected", "actual"}`` where ``kind`` is
    ``"value"``, ``"missing"`` (absent in ``actual``), ``"order"`` (same items, different
    order: e.g. Chrome's randomized extension order) or ``"set"`` (items differ; with
    ``"missing"`` / ``"unexpected"`` lists). GREASE values are ignored; JA3 is compared per
    component (``ja3.ciphers``, ``ja3.extensions``, ...), and its MD5 is then skipped.
    ``header_order`` ignores request-dependent headers (Cookie, Content-Length,
    Content-Type, Authorization, Referer, Origin, Range, conditional headers).
    """
    exp, act = _fingerprintOf(expected), _fingerprintOf(actual)
    out: list[dict[str, Any]] = []
    for field in _DIFF_FIELDS:
        want = exp.get(field)
        if want is None: continue
        have = act.get(field)
        if field == "ja3_hash_md5" and exp.get("ja3") and act.get("ja3"): continue
        if have is None:
            out.append({"field": field, "kind": "missing", "expected": want, "actual": None})
        elif field == "ja3":
            out += _ja3Diff(want, have)
        elif field == "tls_extensions":
            out += _listDiff(field, [x for x in want if not _grease(x)], [x for x in have if not _grease(x)])
        elif field == "header_order":
            out += _listDiff(field, _stableOrder(want), _stableOrder(have))
        elif field == "alpn_offered":
            out += _listDiff(field, list(want), list(have))
        elif want != have:
            out.append({"field": field, "kind": "value", "expected": want, "actual": have})
    return out


# ---------------------------------------------------------------------------
# redacted request trace
# ---------------------------------------------------------------------------

def _sensitive(name: str, extra: frozenset[str]) -> bool:
    lowered = name.lower()
    if lowered.startswith(":"): return lowered in extra  # HTTP/2 pseudo-headers (:authority, :path)
    return lowered in _SENSITIVE_HEADERS or lowered in extra or bool(_SENSITIVE_PARTS.search(lowered))


def _headers(pairs: Iterable[tuple[str, Any]], extra: frozenset[str], values: bool,
             redact_query: bool) -> list[list[str]]:
    out = []
    for name, value in pairs:
        if not values: out.append([name]); continue
        out.append([name, _headerValue(name, str(value), extra, redact_query)])
    return out


def _headerValue(name: str, value: str, extra: frozenset[str], redact_query: bool) -> str:
    if _sensitive(name, extra): return REDACTED
    lowered = name.lower()
    if lowered in _URL_HEADERS: return _url(value, redact_query) or value
    if lowered == "link":  # <url>; rel=next, <url>; rel=prev
        return re.sub(r"<([^>]*)>", lambda m: f"<{_url(m.group(1), redact_query)}>", value)
    if lowered == "refresh":  # 5; url=https://...
        return re.sub(r"(?i)(url\s*=\s*['\"]?)([^'\"\s;]+)", lambda m: m.group(1) + (_url(m.group(2), redact_query) or ""),
                      value)
    return value


def _url(url: str | None, redact_query: bool) -> str | None:
    """URL without credentials and fragment; query values (and bare query words) redacted."""
    if not url: return url
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError: return REDACTED
    host = parts.hostname or ""
    if ":" in host: host = f"[{host}]"
    if port is not None: host += f":{port}"
    query = parts.query
    if redact_query and query:
        # names are kept (they explain the request); a segment without "=" may itself be the
        # secret (?<token>), so it is replaced whole
        query = "&".join(f"{seg.split('=', 1)[0]}={REDACTED}" if "=" in seg else REDACTED
                         for seg in query.split("&") if seg)
    return urlunsplit((parts.scheme, host, parts.path, query, ""))


def _digest(data: bytes) -> dict[str, Any]:
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def request_trace(response: Any, *, redact: Iterable[str] = (), values: bool = True,
                  redact_query: bool = True) -> dict[str, Any]:
    """Redacted, JSON-safe description of the request behind ``response``.

    Header names and their wire order are kept; values of credential-like headers
    (Authorization, Cookie, Set-Cookie, *token*, *secret*, *session*, *auth*, *key*, ... and
    the names in ``redact``) become ``"[redacted]"``; ``values=False`` drops every value.
    URL credentials are removed and query values redacted, also in Location,
    Content-Location, Referer, Origin, Link and Refresh (``redact_query=False`` keeps them).
    URL paths are kept as they are.
    Bodies appear only as length + SHA-256 (request bodies over 8 MiB: length only).
    """
    from . import __version__
    extra = frozenset(name.lower() for name in redact)
    fp = dict(response.fingerprint or {})
    info = dict(response.connection_info or {})
    sent = getattr(response, "_request", None) or {}
    wire = fp.get("request_headers")
    requestHeaders = [(name, value) for name, value in wire] if wire else list(sent.get("headers") or [])
    request: dict[str, Any] = {
        "method": sent.get("method") or getattr(response, "_method", None),
        "url": _url(sent.get("url"), redact_query),
        "header_order": [name for name, _ in requestHeaders],
        "header_source": "wire" if wire else "session",
        "headers": _headers(requestHeaders, extra, values, redact_query),
        "body": sent.get("body")}
    stream = getattr(response, "_stream", None)
    if stream is not None and not stream.closed:
        body: dict[str, Any] = {"streamed": True, "consumed": False}
    elif stream is not None:
        body = {"streamed": True, "consumed": True}
    else:
        body = _digest(response._content)
    responseHeaders = [(name, value) for name, items in sorted(response.headers.items()) for value in items]
    trace: dict[str, Any] = {
        "format": TRACE_FORMAT, "version": TRACE_VERSION, "yumeclient": __version__,
        "request_id": response.request_id, "elapsed": response.elapsed,
        "request": request,
        "response": {"status": response.status_code, "url": _url(response.url, redact_query),
                     "http_protocol": response.used_protocol,
                     "headers": _headers(responseHeaders, extra, values, redact_query), "body": body},
        "redirects": [{"status": hop.status_code, "url": _url(hop.url, redact_query)} for hop in response.history],
        "connection": {key: info[key] for key in ("alpn_negotiated", "tls_version", "tls_cipher", "tls_resumed",
                                                   "connection_reused", "remote_address", "timings")
                       if key in info},
        "tls": {key: fp[key] for key in ("ja3", "ja3_hash_md5", "ja4", "ja4_r", "akamai_fingerprint",
                                         "alpn_offered", "tls_extensions", "client_hello_len", "source")
                if key in fp}}
    return trace


def _requestBody(body: str | None, byteRequest: bool) -> dict[str, Any] | None:
    """Length + SHA-256 of the request body as sent (called per request by the session)."""
    if body is None: return None
    if not byteRequest:
        if len(body) > _HASH_LIMIT:
            return {"length": len(body) if body.isascii() else len(body.encode("utf-8")), "sha256": None}
        raw = body.encode("utf-8")
    elif len(body) > _HASH_LIMIT * 4 // 3 + 4:
        return {"length": len(body) * 3 // 4 - body[-2:].count("="), "sha256": None}
    else:
        raw = base64.b64decode(body)
    if len(raw) > _HASH_LIMIT: return {"length": len(raw), "sha256": None}
    return _digest(raw)
