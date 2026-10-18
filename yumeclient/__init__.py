"""yumeclient — requests-style sync/async TLS client over bogdanfinn/tls-client v1.16.0.

The Python layer never swaps in another TLS implementation: every request goes
through the Go cffi adapter (native/main.go) which drives the upstream client,
its uTLS fingerprints and its cookie jar. Cookies picked up anywhere in the jar
(including redirect hops and other hosts) come back as ``jarDump`` and are
merged into the Python-side :class:`CookieJar`.
"""
from __future__ import annotations

import asyncio
import base64
import ctypes
import inspect
import json
import mimetypes
import os
import platform
import threading
import time
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlencode, urlsplit

from .cookies import CookieJar
from .profiles import (ALL_CLIENT_OS, ALL_IDENTIFIERS, ClientIdentifier, ClientOs,
                       Profiles, default_headers, find, validate, validate_os)

__all__ = ["Session", "AsyncSession", "Response", "CookieJar", "Headers", "Profiles",
           "ALL_IDENTIFIERS", "ALL_CLIENT_OS", "ClientIdentifier", "ClientOs",
           "find", "default_headers", "TLSClientError", "RequestError",
           "SessionConfigurationError", "close_runtime", "encode_multipart"]


class TLSClientError(RuntimeError): pass
class RequestError(TLSClientError): pass
class SessionConfigurationError(TLSClientError, ValueError): pass


_poolLock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=64, thread_name_prefix="yumeclient")
_library: ctypes.CDLL | None = None


def _libraryPath() -> Path:
    configured = os.getenv("YUMECLIENT_LIBRARY")
    if configured: return Path(configured)
    suffix = {"Windows": ".dll", "Darwin": ".dylib"}.get(platform.system(), ".so")
    return Path(__file__).with_name("yumeclient" + suffix)


def _native() -> ctypes.CDLL:
    global _library
    with _poolLock:
        if _library is None:
            path = _libraryPath()
            if not path.is_file():
                raise TLSClientError(f"native library not found: {path}; build native/ with `go build -buildmode=c-shared`")
            lib = ctypes.CDLL(str(path))
            lib.yumeclient_call.argtypes = [ctypes.c_char_p]; lib.yumeclient_call.restype = ctypes.c_void_p
            lib.yumeclient_close.argtypes = [ctypes.c_char_p]; lib.yumeclient_close.restype = None
            lib.yumeclient_free.argtypes = [ctypes.c_void_p]; lib.yumeclient_free.restype = None
            _library = lib
        return _library


def _call(payload: dict[str, Any]) -> dict[str, Any]:
    lib = _native()
    pointer = lib.yumeclient_call(json.dumps(payload, separators=(",", ":")).encode())
    if not pointer: raise RequestError("native client returned a null response")
    try: result = json.loads(ctypes.string_at(pointer).decode("utf-8"))
    finally: lib.yumeclient_free(pointer)
    if not result.get("status"): raise RequestError(result.get("body", "request failed"))
    return result


def _closeNative(sessionId: str) -> None:
    _native().yumeclient_close(sessionId.encode())


def _version(value: Any) -> str:
    if value is None or str(value).lower() == "auto": return "auto"
    if value in (1, "1", "1.1", "h1"): return "1.1"
    if value in (2, "2", "h2"): return "2"
    if value in (3, "3", "h3", "quic"): return "3"
    raise SessionConfigurationError(f"invalid http_version: {value!r}")


def _guessMimetype(filename: str | None) -> str:
    if not filename: return "application/octet-stream"
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def _quotePartValue(key: str, value: str) -> str:
    # percent-escape ", CR and LF exactly like requests/urllib3 and browsers do
    return f'{key}="{value.translate({10: "%0A", 13: "%0D", 34: "%22"})}"'


def _guessFilename(fileobj: Any) -> str | None:
    # like requests: basename of an open file, but not pseudo names such as "<stdin>"
    name = getattr(fileobj, "name", None)
    if isinstance(name, str) and name and not (name.startswith("<") and name.endswith(">")):
        return os.path.basename(name)
    return None


def _multipartEntries(value: Any) -> list[tuple[str, Any]]:
    if value is None: return []
    return list(value.items()) if hasattr(value, "items") else list(value)


def encode_multipart(data: Mapping[str, Any] | Sequence[tuple[str, Any]] | None,
                     files: Mapping[str, Any] | Sequence[tuple[str, Any]] | None,
                     boundary: str | None = None) -> tuple[bytes, str]:
    """Encode multipart/form-data like requests+urllib3: file tuple len 2..4,
    mimetype guessed from filename, quoted CR/LF/quote in names, Chrome-style boundary,
    CRLF, fields before files, order preserved."""
    boundary = boundary or "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    parts: list[bytes] = []

    def part(name: str, filename: str | None, content: str | bytes | bytearray,
             contentType: str | None = None, extraHeaders: Mapping[str, str] | None = None) -> None:
        disposition = f'form-data; {_quotePartValue("name", name)}'
        if filename is not None:
            disposition += f'; {_quotePartValue("filename", filename)}'
        partHeaders = {"Content-Disposition": disposition}
        if filename is not None:
            partHeaders["Content-Type"] = contentType if contentType is not None else _guessMimetype(filename)
        elif contentType is not None:
            partHeaders["Content-Type"] = contentType
        if extraHeaders: partHeaders.update(extraHeaders)
        head = f"--{boundary}\r\n" + "".join(f"{key}: {value}\r\n" for key, value in partHeaders.items()) + "\r\n"
        parts.append(head.encode())
        parts.append(content.encode() if isinstance(content, str) else bytes(content))
        parts.append(b"\r\n")

    # fields: scalar/list values, None items skipped, bytes sent raw
    for name, value in _multipartEntries(data):
        if isinstance(value, (list, tuple)):
            items: list[Any] = list(value)
        elif isinstance(value, (str, bytes, bytearray)) or not hasattr(value, "__iter__"):
            items = [value]
        else:
            items = list(value)
        for item in items:
            if item is None: continue
            part(name, None, item if isinstance(item, (bytes, bytearray)) else str(item))

    # files: bare file objects/bytes/str or (filename, content[, content type[, extra headers]])
    for name, spec in _multipartEntries(files):
        filename: str | None
        contentType: str | None = None
        extraHeaders: Mapping[str, str] | None = None
        if isinstance(spec, (tuple, list)):
            if len(spec) == 2:
                filename, content = spec
            elif len(spec) == 3:
                filename, content, contentType = spec
            elif len(spec) == 4:
                filename, content, contentType, extraHeaders = spec
            else:
                raise ValueError(f"file spec must be (filename, content[, content type[, headers]]), got {len(spec)} items")
        else:
            content = spec
            filename = _guessFilename(spec) or name
        if content is None: continue
        if hasattr(content, "read"): content = content.read()
        if filename is not None and contentType is None:
            contentType = _guessMimetype(filename)
        part(name, filename, content, contentType, extraHeaders)

    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class Headers(dict):
    """Case-insensitive ordered header mapping: update()/[] replace in place, keeping wire order."""
    def _resolve(self, key: str) -> str | None:
        lowered = key.lower()
        return next((existing for existing in self if existing.lower() == lowered), None)
    def __setitem__(self, key: str, value: str) -> None:
        existing = self._resolve(key)
        dict.__setitem__(self, existing if existing is not None else key, value)
    def setdefault(self, key: str, default: Any = None) -> Any:
        existing = self._resolve(key)
        if existing is not None: return self[existing]
        dict.__setitem__(self, key, default); return default
    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        for mapping in args:
            items = mapping.items() if hasattr(mapping, "items") else mapping
            for key, value in items: self[key] = value
        for key, value in kwargs.items(): self[key] = value
    def set(self, key: str, value: str) -> None: self[key] = value


@dataclass(slots=True)
class Response:
    status_code: int
    headers: dict[str, list[str]]
    cookies: dict[str, str]
    content: bytes
    url: str
    used_protocol: str = ""
    history: list["Response"] = field(default_factory=list)
    elapsed: float = 0.0
    encoding: str = "utf-8"

    @property
    def status(self) -> int: return self.status_code
    @property
    def text(self) -> str:
        charset = self.encoding
        for key, values in self.headers.items():
            if key.lower() == "content-type" and values:
                for piece in values[0].split(";")[1:]:
                    if piece.strip().lower().startswith("charset="): charset = piece.split("=", 1)[1].strip(' "')
        try: return self.content.decode(charset, errors="replace")
        except LookupError: return self.content.decode("utf-8", errors="replace")
    @property
    def http_version(self) -> str:
        protocol = self.used_protocol.lower()
        if "3" in protocol or "quic" in protocol: return "3"
        if "2" in protocol: return "2"
        return "1.1" if protocol else ""
    @property
    def ok(self) -> bool: return 200 <= self.status_code < 400
    def json(self) -> Any: return json.loads(self.text)
    def raise_for_status(self) -> None:
        if not self.ok: raise RequestError(f"HTTP {self.status_code} for {self.url}")
    def __getitem__(self, key: str) -> str:
        vals = next((v for k, v in self.headers.items() if k.lower() == key.lower()), None)
        if vals is None: raise KeyError(key)
        return ", ".join(vals)
    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] {self.elapsed*1000:.0f}ms>"


# ---------------------------------------------------------------------------
# shared engine: one implementation, two frontends (sync / async)
# ---------------------------------------------------------------------------

def _applyJarDump(jar: CookieJar, jarDump: Mapping[str, Any] | None) -> None:
    """Merge every cookie the Go jar reported back into the Python jar."""
    if not jarDump: return
    for _host, pairs in jarDump.items():
        if not isinstance(pairs, list): continue
        for pair in pairs:
            if not isinstance(pair, dict) or not pair.get("name"): continue
            expires = pair.get("expires")
            jar.set(pair["name"], str(pair.get("value", "")), domain=pair.get("domain") or "",
                    path=pair.get("path") or "/", expires=float(expires) if expires else None,
                    secure=bool(pair.get("secure")), http_only=bool(pair.get("httpOnly")))


def _validateTransport(*, http_version: str, force_http1: bool, disable_http3: bool,
                       proxy: str | None, client_identifier: str) -> dict[str, bool]:
    httpVer = _version(http_version)
    forceHttp1 = force_http1 or httpVer == "1.1"
    racing = httpVer == "3"
    if forceHttp1 and racing: raise SessionConfigurationError("http_version=3 cannot be combined with force_http1")
    if disable_http3 and racing: raise SessionConfigurationError("http_version=3 conflicts with disable_http3")
    if racing and proxy and not proxy.lower().startswith("socks5://"):
        raise SessionConfigurationError("HTTP/3 racing with a proxy requires socks5:// to tunnel UDP")
    if racing and client_identifier in {"chrome_152", "chrome_152_PSK", "chrome_150", "chrome_150_PSK"}:
        warnings.warn("this profile has no browser-specific HTTP/3 settings; using library defaults", UserWarning, stacklevel=4)
    if httpVer == "2" and client_identifier.startswith("chrome_133"):
        warnings.warn("HTTP/2-only selection may alter this profile's ALPN fingerprint", UserWarning, stacklevel=4)
    return {"forceHttp1": forceHttp1, "disableHttp3": disable_http3 or httpVer == "2", "withProtocolRacing": racing}


def _encodeBody(*, data: Any, jsonBody: Any, files: Any, headers: dict[str, str]) -> tuple[str | None, bool]:
    """Returns (body, isByteRequest); mutates headers to add a matching Content-Type."""
    if files is not None:
        bodyBytes, contentType = encode_multipart(data if isinstance(data, (dict, list, tuple)) else None, files)
        headers.setdefault("Content-Type", contentType)
        return base64.b64encode(bodyBytes).decode("ascii"), True
    if jsonBody is not None:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(jsonBody, separators=(",", ":")), False
    if data is not None:
        if isinstance(data, bytes):
            headers.setdefault("Content-Type", "application/octet-stream")
            return base64.b64encode(data).decode(), True
        if isinstance(data, (dict, list, tuple)):
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return urlencode(data, doseq=True), False
        return str(data), False
    return None, False


def _buildPayload(sessionId: str, *, method: str, url: str, params: Any, headers: dict[str, str],
                  header_order: Sequence[str] | None, body: str | None, byteRequest: bool,
                  cookies: dict[str, str], flags: dict[str, bool], timeout: float,
                  proxy: str | None, allow_redirects: bool, host_override: str | None,
                  identifier: str, random_tls_extension_order: bool, verify: bool,
                  disable_session_tickets: bool, server_name_overwrite: str | None,
                  local_address: str | None, custom: dict[str, Any] | None,
                  request_header_order: Sequence[str] | None) -> dict[str, Any]:
    requestUrl = url
    if params:
        query = urlencode(params, doseq=True)
        requestUrl += ("&" if "?" in requestUrl else "?") + query
    order = list(request_header_order) if request_header_order is not None else (list(header_order) if header_order is not None else list(headers))
    payload: dict[str, Any] = {"requestMethod": method.upper(), "requestUrl": requestUrl,
        "tlsClientIdentifier": identifier, "sessionId": sessionId, "headers": headers,
        "headerOrder": order, "requestBody": body,
        "requestCookies": [{"name": key, "value": value} for key, value in cookies.items()],
        "timeoutMilliseconds": int(timeout * 1000), "followRedirects": allow_redirects,
        "insecureSkipVerify": not verify, "isByteRequest": byteRequest, "isByteResponse": True,
        "withCustomCookieJar": True, "withRandomTLSExtensionOrder": random_tls_extension_order,
        "forceHttp1": flags["forceHttp1"], "disableHttp3": flags["disableHttp3"],
        "withProtocolRacing": flags["withProtocolRacing"], "disableSessionTickets": disable_session_tickets}
    if proxy is not None: payload["proxyUrl"] = proxy
    if host_override is not None: payload["requestHostOverride"] = host_override
    if server_name_overwrite is not None: payload["serverNameOverwrite"] = server_name_overwrite
    if local_address is not None: payload["localAddress"] = local_address
    if custom is not None: payload["customTlsClient"] = custom
    return payload


def _parseResponse(result: dict[str, Any], requestUrl: str, elapsed: float) -> Response:
    encoded = result.get("body", "")
    if encoded.startswith("data:") and ";base64," in encoded: encoded = encoded.split(";base64,", 1)[1]
    return Response(int(result.get("status", 0)), result.get("headers") or {},
                    result.get("cookies") or {}, base64.b64decode(encoded),
                    result.get("target", requestUrl), result.get("usedProtocol", ""), [], elapsed)


class _Core:
    """Transport + cookie state shared by Session and AsyncSession."""
    def __init__(self, *, client_identifier: str | None = None, client_os: ClientOs | str | None = None,
                 random_tls_extension_order: bool = True, http_version: Any = "auto",
                 proxy: str | None = None, timeout: float = 30, header_order: Sequence[str] | None = None,
                 headers: Mapping[str, str] | None = None, cookies: Any = None, verify: bool = True,
                 force_http1: bool = False, disable_http3: bool = False, disable_session_tickets: bool = False,
                 server_name_overwrite: str | None = None, local_address: str | None = None,
                 ja3_string: str | None = None, supported_signature_algorithms: Sequence[str] | None = None,
                 key_share_curves: Sequence[str] | None = None, supported_versions: Sequence[str] | None = None,
                 alpn_protocols: Sequence[str] | None = None, alps_protocols: Sequence[str] | None = None,
                 cert_compression_algos: Sequence[str] | None = None, trust_anchors_payload: str | None = None,
                 h2_settings: Mapping[str, int] | None = None, h2_settings_order: Sequence[str] | None = None,
                 connection_flow: int = 0, pseudo_header_order: Sequence[str] | None = None,
                 priority_frames: Sequence[Mapping[str, Any]] | None = None,
                 header_priority: Mapping[str, Any] | None = None,
                 fill_custom_with_chrome_defaults: bool = True) -> None:
        try:
            self.client_identifier = validate(client_identifier)
            self.client_os = validate_os(client_os, self.client_identifier)
        except ValueError as exc: raise SessionConfigurationError(str(exc)) from exc
        self.random_tls_extension_order = random_tls_extension_order
        self.http_version = _version(http_version)
        self.proxy, self.timeout, self.verify = proxy, timeout, verify
        self.force_http1, self.disable_http3, self.disable_session_tickets = force_http1, disable_http3, disable_session_tickets
        self.server_name_overwrite, self.local_address = server_name_overwrite, local_address
        # session.headers starts as the profile+OS default set; dict(=) keeps insertion order,
        # which is exactly the wire header order when no explicit header_order is given
        self.headers = Headers(default_headers(self.client_identifier, self.client_os))
        if headers: self.headers.update(headers)
        self.header_order: list[str] | None = list(header_order) if header_order else None
        self.cookies = cookies if isinstance(cookies, CookieJar) else CookieJar(cookies)
        self.custom: dict[str, Any] | None = None
        customData = {"ja3String": ja3_string, "supportedSignatureAlgorithms": supported_signature_algorithms,
            "keyShareCurves": key_share_curves, "supportedVersions": supported_versions,
            "alpnProtocols": alpn_protocols, "alpsProtocols": alps_protocols,
            "certCompressionAlgos": cert_compression_algos, "trustAnchorsPayload": trust_anchors_payload,
            "h2Settings": h2_settings, "h2SettingsOrder": h2_settings_order, "connectionFlow": connection_flow,
            "pseudoHeaderOrder": pseudo_header_order, "priorityFrames": priority_frames, "headerPriority": header_priority}
        customData = {key: value for key, value in customData.items() if value is not None and value != 0}
        if ja3_string:
            if client_identifier is not None: raise SessionConfigurationError("ja3_string cannot be combined with client_identifier")
            if fill_custom_with_chrome_defaults: customData["fillCustomWithChromeDefaults"] = True
            self.client_identifier = ""
            self.custom = customData
        elif any(value is not None for key, value in customData.items() if key != "connectionFlow"):
            raise SessionConfigurationError("custom TLS options require ja3_string")
        self._sessionId = str(uuid.uuid4())
        self._closed = False
        self._configMark = self._transportMark()

    # -- transport identity -------------------------------------------------
    def _transportMark(self) -> tuple[Any, ...]:
        return (self.client_identifier, self.random_tls_extension_order, self.http_version, self.proxy,
                self.timeout, self.verify, self.force_http1, self.disable_http3, self.disable_session_tickets,
                self.server_name_overwrite, self.local_address, json.dumps(self.custom, sort_keys=True))

    def _markIfChanged(self) -> str | None:
        mark = self._transportMark()
        if mark != self._configMark:
            self._configMark = mark
            oldId, self._sessionId = self._sessionId, str(uuid.uuid4())
            return oldId
        return None

    def _checkOpen(self) -> None:
        if self._closed: raise SessionConfigurationError("session is closed")

    # -- one request, blocking --------------------------------------------
    def _request(self, method: str, url: str, *, params: Any = None, data: Any = None, json: Any = None,
                 files: Any = None, headers: Mapping[str, str] | None = None, cookies: Any = None,
                 timeout: float | None = None, proxy: str | None = None, allow_redirects: bool = True,
                 header_order: Sequence[str] | None = None, host_override: str | None = None) -> Response:
        self._checkOpen()
        merged = Headers(self.headers)
        if headers: merged.update(headers)
        body, byteRequest = _encodeBody(data=data, jsonBody=json, files=files, headers=merged)
        cookieData = dict(self.cookies.to_dict(domain=urlsplit(url).hostname or ""))
        if cookies:
            if isinstance(cookies, Mapping): extra = dict(cookies)
            elif isinstance(cookies, CookieJar): extra = cookies.to_dict()
            else: extra = {c["name"]: c["value"] for c in cookies}
            cookieData.update(extra)
        flags = _validateTransport(http_version=self.http_version, force_http1=self.force_http1,
                                   disable_http3=self.disable_http3, proxy=proxy if proxy is not None else self.proxy,
                                   client_identifier=self.client_identifier)
        payload = _buildPayload(self._sessionId, method=method, url=url, params=params, headers=merged,
                                header_order=self.header_order, body=body, byteRequest=byteRequest,
                                cookies=cookieData, flags=flags,
                                timeout=timeout if timeout is not None else self.timeout,
                                proxy=proxy if proxy is not None else self.proxy, allow_redirects=allow_redirects,
                                host_override=host_override, identifier=self.client_identifier,
                                random_tls_extension_order=self.random_tls_extension_order, verify=self.verify,
                                disable_session_tickets=self.disable_session_tickets,
                                server_name_overwrite=self.server_name_overwrite, local_address=self.local_address,
                                custom=self.custom, request_header_order=header_order)
        start = time.perf_counter()
        result = _call(payload)
        elapsed = time.perf_counter() - start
        # per-request cookies are transient: keep them out of the session jar unless
        # the server itself set/updated that name via a Set-Cookie header
        setCookieHeaders = [value for key, values in (result.get("headers") or {}).items() if key.lower() == "set-cookie" for value in values]
        responseNames = {header.split("=", 1)[0].strip() for header in setCookieHeaders if "=" in header}
        requestNames = set(cookieData) if cookies else set()
        jarDump = result.get("jarDump") or {}
        filtered = {hostKey: [pair for pair in (pairs or []) if not (pair.get("name") in requestNames and pair.get("name") not in responseNames)]
                    for hostKey, pairs in jarDump.items()}
        _applyJarDump(self.cookies, filtered)
        return _parseResponse(result, url, elapsed)

    def _syncRequest(self, method: str, url: str, **kwargs: Any) -> Response:
        oldId = self._markIfChanged()
        if oldId: _closeNative(oldId)
        return self._request(method, url, **kwargs)

    def close(self) -> None:
        if self._closed: return
        self._closed = True
        _closeNative(self._sessionId)


class Session:
    """Blocking requests-style TLS session (cookies + default headers per profile)."""
    def __init__(self, **kwargs: Any) -> None:
        self._core = _Core(**kwargs)

    def __enter__(self) -> "Session": self._core._checkOpen(); return self
    def __exit__(self, *_: Any) -> None: self.close()

    @property
    def client_identifier(self) -> str: return self._core.client_identifier
    @property
    def client_os(self) -> str: return self._core.client_os
    @property
    def cookies(self) -> CookieJar: return self._core.cookies
    @property
    def headers(self) -> dict[str, str]: return self._core.headers
    @headers.setter
    def headers(self, value: Mapping[str, str]) -> None: self._core.headers = Headers(value)

    def reset_connection(self) -> None:
        """Force a fresh Go session (new TLS connection) on the next request."""
        oldId = self._core._markIfChanged()
        if not oldId: oldId, self._core._sessionId = self._core._sessionId, str(uuid.uuid4())
        _closeNative(oldId)

    def close(self) -> None: self._core.close()

    def request(self, method: str, url: str, **kwargs: Any) -> Response: return self._core._syncRequest(method, url, **kwargs)
    def get(self, url: str, **kwargs: Any) -> Response: return self.request("GET", url, **kwargs)
    def head(self, url: str, **kwargs: Any) -> Response: return self.request("HEAD", url, **kwargs)
    def post(self, url: str, **kwargs: Any) -> Response: return self.request("POST", url, **kwargs)
    def put(self, url: str, **kwargs: Any) -> Response: return self.request("PUT", url, **kwargs)
    def patch(self, url: str, **kwargs: Any) -> Response: return self.request("PATCH", url, **kwargs)
    def delete(self, url: str, **kwargs: Any) -> Response: return self.request("DELETE", url, **kwargs)
    def options(self, url: str, **kwargs: Any) -> Response: return self.request("OPTIONS", url, **kwargs)


class AsyncSession:
    """Async facade: same engine, every method awaitable, shared executor pool."""
    def __init__(self, **kwargs: Any) -> None:
        self._core = _Core(**kwargs)
        self._lock = asyncio.Lock()
        self._active: set[asyncio.Task[Any]] = set()

    async def __aenter__(self) -> "AsyncSession":
        self._core._checkOpen(); return self
    async def __aexit__(self, *_: Any) -> None: await self.close()

    @property
    def client_identifier(self) -> str: return self._core.client_identifier
    @property
    def client_os(self) -> str: return self._core.client_os
    @property
    def cookies(self) -> CookieJar: return self._core.cookies
    @property
    def headers(self) -> dict[str, str]: return self._core.headers
    @headers.setter
    def headers(self, value: Mapping[str, str]) -> None: self._core.headers = Headers(value)

    @classmethod
    def configure_executor(cls, workers: int = 64) -> None:
        global _executor
        if workers < 1: raise ValueError("workers must be positive")
        with _poolLock:
            oldPool = _executor
            if getattr(oldPool, "_threads", set()): raise SessionConfigurationError("configure executor before starting requests")
            _executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="yumeclient")
            oldPool.shutdown(wait=False)

    async def _run(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        task = asyncio.current_task()
        async with self._lock:
            self._core._checkOpen()
            if task: self._active.add(task)
            oldId = self._core._markIfChanged()
        try:
            loop = asyncio.get_running_loop()
            if oldId: await loop.run_in_executor(_executor, _closeNative, oldId)
            future = loop.run_in_executor(_executor, lambda: fn(*args, **kwargs))
            try: return await asyncio.shield(future)
            except asyncio.CancelledError:
                try: await asyncio.shield(future)
                finally: raise
        finally:
            if task:
                async with self._lock: self._active.discard(task)

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        core = self._core
        return await self._run(core._request, method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> Response: return await self.request("GET", url, **kwargs)
    async def head(self, url: str, **kwargs: Any) -> Response: return await self.request("HEAD", url, **kwargs)
    async def post(self, url: str, **kwargs: Any) -> Response: return await self.request("POST", url, **kwargs)
    async def put(self, url: str, **kwargs: Any) -> Response: return await self.request("PUT", url, **kwargs)
    async def patch(self, url: str, **kwargs: Any) -> Response: return await self.request("PATCH", url, **kwargs)
    async def delete(self, url: str, **kwargs: Any) -> Response: return await self.request("DELETE", url, **kwargs)
    async def options(self, url: str, **kwargs: Any) -> Response: return await self.request("OPTIONS", url, **kwargs)

    async def reset_connection(self) -> None:
        oldId = self._core._markIfChanged()
        if not oldId: oldId, self._core._sessionId = self._core._sessionId, str(uuid.uuid4())
        await asyncio.get_running_loop().run_in_executor(_executor, _closeNative, oldId)

    async def close(self) -> None:
        if self._core._closed: return
        self._core._closed = True
        active = tuple(task for task in self._active if task is not asyncio.current_task())
        sessionId = self._core._sessionId
        if active: await asyncio.gather(*(asyncio.shield(task) for task in active), return_exceptions=True)
        try: await asyncio.get_running_loop().run_in_executor(_executor, _closeNative, sessionId)
        except TLSClientError: pass


async def close_runtime() -> None:
    """Shut the shared executor down (optional; call after all sessions closed)."""
    global _executor
    with _poolLock: pool = _executor
    await asyncio.get_running_loop().run_in_executor(None, lambda: pool.shutdown(wait=True, cancel_futures=False))


# ---------------------------------------------------------------------------
# module-level one-shot API (requests-style): yumeclient.get(...), yumeclient.aget(...)
# ---------------------------------------------------------------------------

_SESSION_KEYS = frozenset(inspect.signature(_Core.__init__).parameters) - {"self"}

def _splitKwargs(kwargs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    session_kwargs = {key: kwargs.pop(key) for key in list(kwargs) if key in _SESSION_KEYS}
    return session_kwargs, kwargs

def request(method: str, url: str, **kwargs: Any) -> Response:
    """One-shot blocking request; session kwargs (client_identifier, client_os, proxy, ...) accepted too."""
    session_kwargs, request_kwargs = _splitKwargs(kwargs)
    with Session(**session_kwargs) as session:
        return session.request(method, url, **request_kwargs)

def get(url: str, **kwargs: Any) -> Response: return request("GET", url, **kwargs)
def head(url: str, **kwargs: Any) -> Response: return request("HEAD", url, **kwargs)
def post(url: str, **kwargs: Any) -> Response: return request("POST", url, **kwargs)
def put(url: str, **kwargs: Any) -> Response: return request("PUT", url, **kwargs)
def patch(url: str, **kwargs: Any) -> Response: return request("PATCH", url, **kwargs)
def delete(url: str, **kwargs: Any) -> Response: return request("DELETE", url, **kwargs)
def options(url: str, **kwargs: Any) -> Response: return request("OPTIONS", url, **kwargs)

async def arequest(method: str, url: str, **kwargs: Any) -> Response:
    """One-shot awaitable request; same kwargs as :func:`request`."""
    session_kwargs, request_kwargs = _splitKwargs(kwargs)
    async with AsyncSession(**session_kwargs) as session:
        return await session.request(method, url, **request_kwargs)

async def aget(url: str, **kwargs: Any) -> Response: return await arequest("GET", url, **kwargs)
async def ahead(url: str, **kwargs: Any) -> Response: return await arequest("HEAD", url, **kwargs)
async def apost(url: str, **kwargs: Any) -> Response: return await arequest("POST", url, **kwargs)
async def aput(url: str, **kwargs: Any) -> Response: return await arequest("PUT", url, **kwargs)
async def apatch(url: str, **kwargs: Any) -> Response: return await arequest("PATCH", url, **kwargs)
async def adelete(url: str, **kwargs: Any) -> Response: return await arequest("DELETE", url, **kwargs)
async def aoptions(url: str, **kwargs: Any) -> Response: return await arequest("OPTIONS", url, **kwargs)

__all__ += ["request", "get", "head", "post", "put", "patch", "delete", "options",
            "arequest", "aget", "ahead", "apost", "aput", "apatch", "adelete", "aoptions"]
