"""yumeclient — requests-style sync/async TLS client over bogdanfinn/tls-client v1.16.0.

The Python layer never swaps in another TLS implementation: every request goes
through the Go cffi adapter (native/) which drives the upstream client and its
uTLS fingerprints. ``session.cookies`` is the single source of truth: each call
sends a snapshot, the native per-request jar selects cookies per redirect hop
(RFC 6265) and only the changes (``jarDelta``) come back.
"""
from __future__ import annotations

import asyncio
import base64
import ctypes
import functools
import hashlib
import inspect
import json
import mimetypes
import os
import platform
import re
import threading
import time
import uuid
import warnings
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, Mapping, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit

from .cookies import CookieJar
from .multipart import choose_boundary, encode_multipart
from .profiles import (ALL_CLIENT_OS, ALL_HEADER_STYLES, ALL_IDENTIFIERS, ClientIdentifier, ClientOs,
                       HeaderStyle, Profiles, default_headers, find, resolve_header_style,
                       validate, validate_os)

__all__ = ["Session", "AsyncSession", "Response", "CookieJar", "Headers", "Profiles",
           "ALL_IDENTIFIERS", "ALL_CLIENT_OS", "ALL_HEADER_STYLES", "ClientIdentifier", "ClientOs", "HeaderStyle",
           "find", "default_headers", "TLSClientError", "RequestError",
           "SessionConfigurationError", "close_runtime", "encode_multipart", "choose_boundary",
           "TimeoutConfig", "InvalidRequestError", "RequestCancelled", "ConnectError", "ProxyError", "TLSError",
           "ConnectionClosed", "Timeout", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "ResponseTooLarge",
           "StreamClosed", "HTTPStatusError"]


class TLSClientError(RuntimeError): pass


class RequestError(TLSClientError):
    """A request failed. ``kind`` names the failure class and ``stage`` where it happened
    (connect / write / read / body / request); the subclasses below map one-to-one onto kinds.

    Attributes: ``kind``, ``stage``, ``method``, ``url`` (credentials removed), ``elapsed``,
    ``request_id``, ``retryable``, ``detail`` (native message, redacted) and ``response``
    (only for :class:`HTTPStatusError`).
    """
    def __init__(self, message: str = "", *, kind: str = "request", stage: str | None = None,
                 method: str | None = None, url: str | None = None, elapsed: float | None = None,
                 request_id: str | None = None, retryable: bool = False, detail: str | None = None,
                 response: "Response | None" = None) -> None:
        super().__init__(message)
        self.kind, self.stage, self.method, self.url = kind, stage, method, url
        self.elapsed, self.request_id, self.retryable = elapsed, request_id, retryable
        self.detail = message if detail is None else detail
        self.response = response


class SessionConfigurationError(TLSClientError, ValueError): pass
class InvalidRequestError(RequestError, ValueError):
    """The request or its transport configuration was rejected before any network I/O."""
class RequestCancelled(RequestError):
    """The native request was cancelled (task cancellation, session close)."""
class ConnectError(RequestError, ConnectionError):
    """DNS resolution, TCP connect, proxy negotiation or the TLS handshake failed."""
class ProxyError(ConnectError):
    """The proxy leg failed: connecting to the proxy, CONNECT / SOCKS negotiation, proxy auth."""
class TLSError(ConnectError):
    """TLS handshake or certificate verification failed."""
class ConnectionClosed(RequestError, ConnectionError):
    """The connection was closed or reset after it had been established."""
class Timeout(RequestError, TimeoutError):
    """Base class of every timeout; raised itself when the total deadline expires."""
class ConnectTimeout(Timeout, ConnectError):
    """DNS + proxy + TCP + TLS of one hop took longer than ``TimeoutConfig.connect``."""
class ReadTimeout(Timeout):
    """No response headers, or no body bytes, within ``TimeoutConfig.read``."""
class WriteTimeout(Timeout):
    """Sending the request took longer than ``TimeoutConfig.write``."""
class ResponseTooLarge(RequestError):
    """The response body exceeded ``max_content_size``."""
class StreamClosed(RequestError):
    """The streamed response body was already closed."""
class HTTPStatusError(RequestError):
    """Raised by :meth:`Response.raise_for_status`; the response is in ``.response``."""


_ERROR_KINDS: dict[str, type[RequestError]] = {
    "timeout": Timeout, "connect_timeout": ConnectTimeout, "read_timeout": ReadTimeout,
    "write_timeout": WriteTimeout, "connect": ConnectError, "dns": ConnectError, "proxy": ProxyError,
    "tls": TLSError, "connection_closed": ConnectionClosed, "cancelled": RequestCancelled,
    "body_too_large": ResponseTooLarge, "invalid_request": InvalidRequestError,
    "configuration": InvalidRequestError, "stream_closed": StreamClosed}
_RETRYABLE = frozenset({"timeout", "connect_timeout", "read_timeout", "write_timeout", "connect", "dns",
                        "proxy", "connection_closed"})
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@")
_AUTH_VALUE = re.compile(r"(?i)\b(basic|bearer)\s+[a-z0-9._~+/=-]+")


def _redact(text: str) -> str:
    """Drop credentials from URLs (scheme://user:pass@) and Basic/Bearer tokens."""
    return _AUTH_VALUE.sub(r"\1 ***", _USERINFO.sub(r"\1***@", text))


def _safeUrl(url: str | None) -> str | None:
    if not url: return url
    try:
        parts = urlsplit(url)
        if parts.username is None and parts.password is None: return url
        host = parts.hostname or ""
        if ":" in host: host = f"[{host}]"
        if parts.port is not None: host += f":{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    except ValueError:
        return _redact(url)


class _NativeError(Exception):
    """Native (Go) error text, attached as ``__cause__`` of the public exception."""


def _errorFromResult(result: Mapping[str, Any], method: str | None = None, url: str | None = None) -> RequestError:
    kind = str(result.get("errorKind") or "request")
    detail = _redact(str(result.get("body") or "request failed"))
    cls = _ERROR_KINDS.get(kind, RequestError)
    safe = _safeUrl(url)
    message = f"{detail} [{method} {safe}]" if method and safe else detail
    error = cls(message, kind=kind, stage=result.get("errorStage"), method=method, url=safe,
                elapsed=result.get("elapsed"), request_id=result.get("requestId"),
                retryable=kind in _RETRYABLE, detail=detail)
    error.__cause__ = _NativeError(detail)
    return error


@dataclass(frozen=True)
class TimeoutConfig:
    """Split timeouts in seconds (``None`` = no limit for that stage).

    * ``connect`` - DNS + proxy + TCP + TLS handshake of every hop (redirects included);
    * ``write`` - sending the request headers and body once a connection is available;
    * ``read`` - waiting for the response headers, and the longest pause between body chunks;
    * ``total`` - the whole exchange. With ``stream=True`` it ends when the headers arrive; the
      body is then bounded by ``read`` (``total`` serves as the read limit when ``read`` is None).

    ``timeout=`` accepts a number (= ``total``), a ``(connect, read)`` tuple, a ``TimeoutConfig``
    or ``None`` (no limits). Stage limits are not enforced on HTTP/3 hops of protocol-racing
    sessions (quic-go reports no stages); ``total`` and the body ``read`` limit are.
    """
    total: float | None = None
    connect: float | None = None
    read: float | None = None
    write: float | None = None

    def __post_init__(self) -> None:
        for name in ("total", "connect", "read", "write"):
            value = getattr(self, name)
            if value is None: continue
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
                raise SessionConfigurationError(f"timeout {name} must be a positive number or None, got {value!r}")


def _timeoutConfig(value: Any) -> TimeoutConfig:
    if value is None: return TimeoutConfig()
    if isinstance(value, TimeoutConfig): return value
    if isinstance(value, (tuple, list)):
        if len(value) != 2: raise SessionConfigurationError("timeout tuple must be (connect, read)")
        return TimeoutConfig(connect=value[0], read=value[1])
    return TimeoutConfig(total=value)


def _ms(seconds: float | None) -> int:
    return 0 if seconds is None else max(1, int(round(seconds * 1000)))


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
            lib.yumeclient_cancel.argtypes = [ctypes.c_char_p]; lib.yumeclient_cancel.restype = ctypes.c_int
            lib.yumeclient_stream_read.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
            lib.yumeclient_stream_read.restype = ctypes.c_void_p
            lib.yumeclient_stream_close.argtypes = [ctypes.c_char_p]; lib.yumeclient_stream_close.restype = None
            _library = lib
        return _library


def _decodeNative(lib: ctypes.CDLL, pointer: int | None) -> dict[str, Any]:
    if not pointer: raise RequestError("native client returned a null response")
    try: return json.loads(ctypes.string_at(pointer).decode("utf-8"))
    finally: lib.yumeclient_free(pointer)


def _call(payload: dict[str, Any]) -> dict[str, Any]:
    lib = _native()
    result = _decodeNative(lib, lib.yumeclient_call(json.dumps(payload, separators=(",", ":")).encode()))
    if not result.get("status"):
        raise _errorFromResult(result, payload.get("requestMethod"), payload.get("requestUrl"))
    return result


def _closeNative(sessionId: str) -> None:
    _native().yumeclient_close(sessionId.encode())


def _cancelNative(requestId: str) -> None:
    """Cancel an in-flight native request (or one that has not started yet); never blocks."""
    _native().yumeclient_cancel(requestId.encode())


def _debugStats() -> dict[str, int]:
    """Native bookkeeping (in-flight requests, open streams, goroutines) - for leak tests."""
    lib = _native()
    lib.yumeclient_debug_stats.restype = ctypes.c_void_p
    return _decodeNative(lib, lib.yumeclient_debug_stats())


def _closeStreamNative(streamId: str) -> None:
    try: _native().yumeclient_stream_close(streamId.encode())
    except Exception: pass  # interpreter shutdown / library already gone


def _version(value: Any) -> str:
    if value is None or str(value).lower() == "auto": return "auto"
    if value in (1, "1", "1.1", "h1"): return "1.1"
    if value in (2, "2", "h2"): return "2"
    if value in (3, "3", "h3", "quic"): return "3"
    raise SessionConfigurationError(f"invalid http_version: {value!r}")


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


class _NativeStream:
    """Native body handle of a ``stream=True`` response; closed exactly once (also on GC)."""
    __slots__ = ("stream_id", "request_id", "eof", "_finalizer", "__weakref__")

    def __init__(self, streamId: str, requestId: str | None) -> None:
        self.stream_id, self.request_id, self.eof = streamId, requestId, False
        self._finalizer = weakref.finalize(self, _closeStreamNative, streamId)

    @property
    def closed(self) -> bool: return not self._finalizer.alive

    def read(self, size: int, method: str | None, url: str | None) -> bytes:
        """Blocking read of up to ``size`` bytes; b"" at end of body."""
        if self.eof: return b""
        if self.closed:
            raise StreamClosed("response stream is closed", kind="stream_closed", method=method, url=_safeUrl(url))
        lib = _native()
        buffer = ctypes.create_string_buffer(size)
        result = _decodeNative(lib, lib.yumeclient_stream_read(self.stream_id.encode(), buffer, size))
        if not result.get("status"):
            self.close()
            raise _errorFromResult(result, method, url)
        n = int(result.get("n") or 0)
        data = ctypes.string_at(buffer, n) if n else b""
        if result.get("eof"):
            self.eof = True
            self.close()
        return data

    def cancel(self) -> None:
        """Abort a read in progress (it fails with RequestCancelled); never blocks."""
        if self.request_id and not self.closed: _cancelNative(self.request_id)

    def close(self) -> None: self._finalizer()


class Response:
    """HTTP response.

    With ``stream=True`` the body stays in the native layer until it is consumed with
    :meth:`iter_bytes` / :meth:`read` (sync) or :meth:`aiter_bytes` / :meth:`aread` (async).
    Close an unconsumed stream with :meth:`close` / :meth:`aclose` or a ``with`` block;
    an abandoned stream is also released when the response is garbage-collected.
    """
    __slots__ = ("status_code", "headers", "cookies", "_content", "url", "used_protocol", "history",
                 "elapsed", "encoding", "fingerprint", "connection_info", "request_id", "_stream", "_async",
                 "_owner", "_method", "__weakref__")

    def __init__(self, status_code: int, headers: dict[str, list[str]], cookies: dict[str, str],
                 content: bytes = b"", url: str = "", used_protocol: str = "",
                 history: list["Response"] | None = None, elapsed: float = 0.0, encoding: str = "utf-8",
                 fingerprint: dict[str, Any] | None = None) -> None:
        self.status_code, self.headers, self.cookies, self._content = status_code, headers, cookies, content
        self.url, self.used_protocol, self.history, self.elapsed = url, used_protocol, history or [], elapsed
        self.encoding, self.fingerprint = encoding, fingerprint
        self.connection_info: dict[str, Any] | None = None
        self.request_id: str | None = None
        self._stream: _NativeStream | None = None
        self._async = False
        self._owner: Any = None
        self._method: str | None = None

    # -- body ---------------------------------------------------------------
    @property
    def content(self) -> bytes:
        if self._stream is not None:
            if self._async and not self._stream.closed:
                raise StreamClosed("streamed body not read yet: use `await response.aread()`",
                                   kind="stream_not_read", method=self._method, url=_safeUrl(self.url))
            self.read()
        return self._content
    @content.setter
    def content(self, value: bytes) -> None:
        self._content = value

    @property
    def is_stream_consumed(self) -> bool:
        """True once a streamed body was read to the end or closed."""
        return self._stream is None or self._stream.closed
    @property
    def status(self) -> int: return self.status_code
    @property
    def text(self) -> str:
        content = self.content
        charset = self._charset()
        try: return content.decode(charset, errors="replace")
        except LookupError: return content.decode("utf-8", errors="replace")
    def _charset(self) -> str:
        charset = self.encoding
        for key, values in self.headers.items():
            if key.lower() == "content-type" and values:
                for piece in values[0].split(";")[1:]:
                    if piece.strip().lower().startswith("charset="): charset = piece.split("=", 1)[1].strip(' "')
        return charset
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
        if not self.ok:
            raise HTTPStatusError(f"HTTP {self.status_code} for {_safeUrl(self.url)}", kind="http_status",
                                  method=self._method, url=_safeUrl(self.url), request_id=self.request_id,
                                  response=self)
    def __getitem__(self, key: str) -> str:
        vals = next((v for k, v in self.headers.items() if k.lower() == key.lower()), None)
        if vals is None: raise KeyError(key)
        return ", ".join(vals)
    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] {self.elapsed*1000:.0f}ms>"

    # -- streaming (sync) ----------------------------------------------------
    def iter_bytes(self, chunk_size: int = 65536) -> Iterator[bytes]:
        """Yield the body in chunks of at most ``chunk_size`` bytes (bounded memory for streams).
        Leaving the loop early closes the stream."""
        if chunk_size < 1: raise ValueError("chunk_size must be positive")
        stream = self._stream
        if stream is None:
            data = self._content
            for start in range(0, len(data), chunk_size): yield data[start:start + chunk_size]
            return
        try:
            while not stream.eof:
                chunk = stream.read(chunk_size, self._method, self.url)
                if chunk: yield chunk
        finally:
            self.close()

    def iter_content(self, chunk_size: int | None = 65536, decode_unicode: bool = False) -> Iterator[Any]:
        """requests-compatible alias of :meth:`iter_bytes` (``decode_unicode`` yields str)."""
        chunks = self.iter_bytes(chunk_size or 65536)
        if not decode_unicode:
            yield from chunks
            return
        import codecs
        try: decoder = codecs.getincrementaldecoder(self._charset())(errors="replace")
        except LookupError: decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        for chunk in chunks:
            text = decoder.decode(chunk)
            if text: yield text
        tail = decoder.decode(b"", final=True)
        if tail: yield tail

    def read(self) -> bytes:
        """Read the rest of a streamed body into :attr:`content` (no-op for buffered responses)."""
        stream = self._stream
        if stream is not None:
            if stream.closed:
                raise StreamClosed("response body was already consumed or closed", kind="stream_closed",
                                   method=self._method, url=_safeUrl(self.url))
            parts: list[bytes] = []
            try:
                while not stream.eof: parts.append(stream.read(1 << 20, self._method, self.url))
            finally:
                self.close()
            self._content, self._stream = b"".join(parts), None
        return self._content

    def close(self) -> None:
        """Release the native stream (and the one-shot session that produced it)."""
        if self._stream is not None: self._stream.close()
        owner, self._owner = self._owner, None
        if owner is not None: owner.close()

    def __enter__(self) -> "Response": return self
    def __exit__(self, *_: Any) -> None: self.close()

    # -- streaming (async) ---------------------------------------------------
    async def aiter_bytes(self, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        """Async :meth:`iter_bytes`: each native read runs in the executor; cancelling the
        consuming task aborts the read in progress."""
        if chunk_size < 1: raise ValueError("chunk_size must be positive")
        stream = self._stream
        if stream is None:
            data = self._content
            for start in range(0, len(data), chunk_size): yield data[start:start + chunk_size]
            return
        loop = asyncio.get_running_loop()
        try:
            while not stream.eof:
                future = loop.run_in_executor(_executor, stream.read, chunk_size, self._method, self.url)
                try: chunk = await asyncio.shield(future)
                except asyncio.CancelledError:
                    stream.cancel()
                    raise
                if chunk: yield chunk
        finally:
            self._closeInBackground()

    async def aread(self) -> bytes:
        """Async :meth:`read`."""
        if self._stream is not None:
            if self._stream.closed:
                raise StreamClosed("response body was already consumed or closed", kind="stream_closed",
                                   method=self._method, url=_safeUrl(self.url))
            parts = [chunk async for chunk in self.aiter_bytes(1 << 20)]
            self._content, self._stream = b"".join(parts), None
        return self._content

    async def aclose(self) -> None:
        self._closeInBackground()

    def _closeInBackground(self) -> None:
        # closing waits for a native read that is being aborted: keep that off the event loop
        stream, owner = self._stream, self._owner
        self._owner = None
        if (stream is None or stream.closed) and owner is None: return
        def closer() -> None:
            if stream is not None: stream.close()
            if owner is not None: owner.close()
        try: _executor.submit(closer)
        except RuntimeError: closer()  # executor shut down

    async def __aenter__(self) -> "Response": return self
    async def __aexit__(self, *_: Any) -> None: await self.aclose()


# ---------------------------------------------------------------------------
# shared engine: one implementation, two frontends (sync / async)
# ---------------------------------------------------------------------------

def _applyJarDelta(jar: CookieJar, delta: Any) -> None:
    """Merge what the server set / deleted during one request (every redirect hop) into the jar."""
    if not isinstance(delta, list): return
    for item in delta:
        if not isinstance(item, dict) or not item.get("name"): continue
        domain, path = item.get("domain") or "", item.get("path") or "/"
        if item.get("deleted"):
            jar.remove(item["name"], domain=domain, path=path)
            continue
        expires = item.get("expires")
        jar.set(item["name"], str(item.get("value", "")), domain=domain, path=path,
                expires=float(expires) if expires else None, secure=bool(item.get("secure")),
                http_only=bool(item.get("httpOnly")), same_site=item.get("sameSite"),
                host_only=bool(item.get("hostOnly")))


def _validateTransport(*, http_version: str, force_http1: bool, disable_http3: bool,
                       proxy: str | None, client_identifier: str, keep_alpn: bool = False,
                       udp_proxy: str | None = None) -> dict[str, bool]:
    httpVer = _version(http_version)
    forceHttp1 = force_http1 or httpVer == "1.1"
    racing = httpVer == "3"
    if keep_alpn and not forceHttp1:
        raise SessionConfigurationError("keep_alpn=True needs http_version='1.1' (or force_http1=True); "
                                        "with http_version='auto' the profile's ALPN is already sent unchanged")
    if keep_alpn and udp_proxy: raise SessionConfigurationError("keep_alpn cannot be combined with udp_proxy")
    if forceHttp1 and racing: raise SessionConfigurationError("http_version=3 cannot be combined with force_http1")
    if disable_http3 and racing: raise SessionConfigurationError("http_version=3 conflicts with disable_http3")
    if racing and proxy and not proxy.lower().startswith("socks5://"):
        raise SessionConfigurationError("HTTP/3 racing with a proxy requires socks5:// to tunnel UDP")
    if racing and client_identifier in {"chrome_152", "chrome_152_PSK", "chrome_150", "chrome_150_PSK"}:
        warnings.warn("this profile has no browser-specific HTTP/3 settings; using library defaults", UserWarning, stacklevel=4)
    if httpVer == "2" and client_identifier.startswith("chrome_133"):
        warnings.warn("HTTP/2-only selection may alter this profile's ALPN fingerprint", UserWarning, stacklevel=4)
    return {"forceHttp1": forceHttp1, "disableHttp3": disable_http3 or httpVer == "2", "withProtocolRacing": racing}


def _encodeBody(*, data: Any, jsonBody: Any, files: Any, headers: dict[str, str],
                okhttp: bool = False) -> tuple[str | None, bool]:
    """Returns (body, isByteRequest); mutates headers to add a matching Content-Type.

    okhttp style: raw bytes get no implicit Content-Type (an okhttp RequestBody
    without a MediaType sends none); pass Content-Type to match the app."""
    if files is not None:
        bodyBytes, contentType = encode_multipart(data if isinstance(data, (dict, list, tuple)) else None, files)
        headers.setdefault("Content-Type", contentType)
        return base64.b64encode(bodyBytes).decode("ascii"), True
    if jsonBody is not None:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(jsonBody, separators=(",", ":")), False
    if data is not None:
        if isinstance(data, bytes):
            if not okhttp: headers.setdefault("Content-Type", "application/octet-stream")
            return base64.b64encode(data).decode(), True
        if isinstance(data, (dict, list, tuple)):
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return urlencode(data, doseq=True), False
        return str(data), False
    return None, False


def _buildPayload(sessionId: str, *, method: str, url: str, params: Any, headers: dict[str, str],
                  header_order: Sequence[str] | None, body: str | None, byteRequest: bool,
                  cookies: dict[str, str], flags: dict[str, bool], timeouts: TimeoutConfig,
                  proxy: str | None, allow_redirects: bool, host_override: str | None,
                  identifier: str, random_tls_extension_order: bool, verify: bool,
                  disable_session_tickets: bool, server_name_overwrite: str | None,
                  local_address: str | None, custom: dict[str, Any] | None,
                  request_header_order: Sequence[str] | None, udp_proxy: str | None = None,
                  want_fingerprint: bool = False, header_style: str = "raw",
                  keep_alpn: bool = False) -> dict[str, Any]:
    requestUrl = url
    if params:
        query = urlencode(params, doseq=True)
        requestUrl += ("&" if "?" in requestUrl else "?") + query
    order = list(request_header_order) if request_header_order is not None else (list(header_order) if header_order is not None else list(headers))
    payload: dict[str, Any] = {"requestMethod": method.upper(), "requestUrl": requestUrl,
        "tlsClientIdentifier": identifier, "sessionId": sessionId, "headers": headers,
        "headerOrder": order, "requestBody": body,
        "requestCookies": [{"name": key, "value": value} for key, value in cookies.items()],
        # timeoutMilliseconds only caps the session's dialers (fixed when the Go session is
        # built); the per-request limits below are enforced through the request context
        "timeoutMilliseconds": max(30000, _ms(timeouts.connect)),
        "totalTimeoutMilliseconds": _ms(timeouts.total), "connectTimeoutMilliseconds": _ms(timeouts.connect),
        "readTimeoutMilliseconds": _ms(timeouts.read), "writeTimeoutMilliseconds": _ms(timeouts.write),
        "followRedirects": allow_redirects,
        "insecureSkipVerify": not verify, "isByteRequest": byteRequest, "isByteResponse": True,
        "withCustomCookieJar": True, "withRandomTLSExtensionOrder": random_tls_extension_order,
        "forceHttp1": flags["forceHttp1"], "disableHttp3": flags["disableHttp3"],
        "withProtocolRacing": flags["withProtocolRacing"], "disableSessionTickets": disable_session_tickets}
    if header_style == "okhttp": payload["headerStyle"] = "okhttp"
    if keep_alpn: payload["keepAlpn"] = True
    if proxy is not None: payload["proxyUrl"] = proxy
    if udp_proxy is not None: payload["udpProxyUrl"] = udp_proxy
    if want_fingerprint: payload["withFingerprint"] = True
    if host_override is not None: payload["requestHostOverride"] = host_override
    if server_name_overwrite is not None: payload["serverNameOverwrite"] = server_name_overwrite
    if local_address is not None: payload["localAddress"] = local_address
    if custom is not None: payload["customTlsClient"] = custom
    return payload


def _parseResponse(result: dict[str, Any], requestUrl: str, elapsed: float) -> Response:
    encoded = result.get("body") or ""
    if encoded.startswith("data:") and ";base64," in encoded: encoded = encoded.split(";base64,", 1)[1]
    return Response(int(result.get("status", 0)), result.get("headers") or {},
                    result.get("cookies") or {}, base64.b64decode(encoded),
                    result.get("target", requestUrl), result.get("usedProtocol", ""), [], elapsed)


# numeric curve ids -> upstream mapper names (mapper.go curves map)
_CURVE_NAMES = {29: "X25519", 23: "P256", 24: "P384", 31: "P521", 4588: "X25519MLKEM768",
    10794: "X25519MLKEM768", 4587: "X25519Kyber768", 4586: "X25519Kyber512D",
    25497: "X25519MLKEM768", 0x0A0A: "GREASE"}
# numeric TLS versions -> upstream mapper names
_VERSION_NAMES = {772: "1.3", 771: "1.2", 770: "1.1", 769: "1.0", 0x0A0A: "GREASE"}

def _normalizeCurveName(value):
    if isinstance(value, str): return value
    if not isinstance(value, int): return str(value)
    if value in _CURVE_NAMES: return _CURVE_NAMES[value]
    return "%x" % value

def _normalizeVersionName(value):
    if isinstance(value, str): return value
    if not isinstance(value, int): return str(value)
    if value in _VERSION_NAMES: return _VERSION_NAMES[value]
    return "%x" % value

def _normalizeHexU16(value):
    # upstream ja3.go: strconv.ParseUint(s, 16, 16) — hex WITHOUT 0x prefix.
    # decimal ja3 strings ("1027") vs hex strings ("0403") are disambiguated:
    # leading zero or hex letters -> hex as-is; all digits without leading zero
    # -> decimal converted to hex ("1027" -> "403").
    if isinstance(value, int): return "%x" % value
    if not isinstance(value, str): return str(value)
    stripped = value[2:] if value.lower().startswith("0x") else value
    if stripped.isdigit() and len(stripped) < 5 and stripped[0] != "0":
        return "%x" % int(stripped)
    return value


class _RequestHandle:
    """One native request: its id (for yumeclient_cancel) and the cancel/complete race."""
    __slots__ = ("id", "_lock", "cancelled", "done")

    def __init__(self) -> None:
        self.id = uuid.uuid4().hex
        self._lock = threading.Lock()
        self.cancelled = self.done = False

    def cancel(self) -> bool:
        """Cancel natively; False when the result was already accepted."""
        with self._lock:
            if self.done: return False
            self.cancelled = True
        _cancelNative(self.id)
        return True

    def complete(self) -> bool:
        """Accept the native result; False when the request was cancelled meanwhile."""
        with self._lock:
            if self.cancelled: return False
            self.done = True
            return True


def _discardLate(future: Any) -> None:
    """Done-callback for a request whose awaiting task was cancelled: release a late stream."""
    if future.cancelled(): return
    if future.exception() is None:
        result = future.result()
        if isinstance(result, Response): result.close()


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
                 fill_custom_with_chrome_defaults: bool = True,
                 tls_extension_order: Sequence[int] | None = None,
                 ech_config_list: bytes | None = None,
                 grease: bool | None = None,
                 psk_mode: str | None = None,
                 udp_proxy: str | None = None,
                 key_share_data: Mapping[int, bytes] | None = None,
                 header_style: HeaderStyle | str | None = None,
                 keep_alpn: bool = False,
                 max_content_size: int | None = None) -> None:
        try:
            self.client_identifier = validate(client_identifier)
            self.client_os = validate_os(client_os, self.client_identifier)
            # ja3 sessions have no profile: raw unless header_style says otherwise
            self.header_style = resolve_header_style("" if ja3_string else self.client_identifier, header_style)
        except ValueError as exc: raise SessionConfigurationError(str(exc)) from exc
        self.keep_alpn = bool(keep_alpn)
        if self.keep_alpn and not (force_http1 or _version(http_version) == "1.1"):
            raise SessionConfigurationError("keep_alpn=True needs http_version='1.1' (or force_http1=True); "
                                            "with http_version='auto' the profile's ALPN is already sent unchanged")
        if self.keep_alpn and udp_proxy is not None:
            raise SessionConfigurationError("keep_alpn cannot be combined with udp_proxy")
        self.random_tls_extension_order = random_tls_extension_order
        self.http_version = _version(http_version)
        self.proxy, self.verify = proxy, verify
        self.timeout = _timeoutConfig(timeout)
        if max_content_size is not None and (isinstance(max_content_size, bool) or not isinstance(max_content_size, int) or max_content_size < 1):
            raise SessionConfigurationError("max_content_size must be a positive int (bytes) or None")
        self.max_content_size = max_content_size
        self.force_http1, self.disable_http3, self.disable_session_tickets = force_http1, disable_http3, disable_session_tickets
        self.server_name_overwrite, self.local_address = server_name_overwrite, local_address
        # advanced ClientHello controls (iOS CFNetwork-class fingerprints)
        if tls_extension_order is not None:
            if ja3_string is None: raise SessionConfigurationError("tls_extension_order requires ja3_string")
            if not all(isinstance(x, int) and 0 <= x <= 65535 for x in tls_extension_order):
                raise SessionConfigurationError("tls_extension_order must be ints 0..65535")
        if ech_config_list is not None and ja3_string is None:
            raise SessionConfigurationError("ech_config_list requires ja3_string")
        if grease is not None and ja3_string is None:
            raise SessionConfigurationError("grease requires ja3_string")
        if psk_mode is not None:
            if psk_mode not in ("psk", "no_psk"):
                raise SessionConfigurationError("psk_mode must be 'psk' or 'no_psk'")
            if ja3_string is None: raise SessionConfigurationError("psk_mode requires ja3_string")
        if udp_proxy is not None and not str(udp_proxy).lower().startswith(("socks5://", "udp://")):
            raise SessionConfigurationError("udp_proxy must be socks5:// or udp:// (for HTTP/3 racing)")
        self.tls_extension_order = list(tls_extension_order) if tls_extension_order else None
        self.ech_config_list = ech_config_list
        self.grease = grease
        self.psk_mode = psk_mode
        self.udp_proxy = udp_proxy
        # mimic path: pre-captured key share bytes per curve id (int group -> raw bytes)
        if key_share_data is not None:
            if ja3_string is None: raise SessionConfigurationError("key_share_data requires ja3_string")
            self.key_share_data = {int(group): bytes(data) for group, data in key_share_data.items()}
        else:
            self.key_share_data = None
        self.last_fingerprint: dict[str, Any] | None = None
        # session.headers starts as the profile+OS default set; dict(=) keeps insertion order,
        # which is exactly the wire header order when no explicit header_order is given
        self.headers = Headers(default_headers(self.client_identifier, self.client_os, self.header_style))
        if headers: self.headers.update(headers)
        self.header_order: list[str] | None = list(header_order) if header_order else None
        self.cookies = cookies if isinstance(cookies, CookieJar) else CookieJar(cookies)
        self.custom: dict[str, Any] | None = None
        # upstream's ja3 mapper expects named/hex strings; accept ints and
        # decimal/hex numbers from curl_cffi-style calls and normalize them
        keyShareCurves = [_normalizeCurveName(v) for v in key_share_curves] if key_share_curves is not None else None
        supportedVersions = [_normalizeVersionName(v) for v in supported_versions] if supported_versions is not None else None
        sigAlgs = [_normalizeHexU16(v) for v in supported_signature_algorithms] if supported_signature_algorithms is not None else None
        customData = {"ja3String": ja3_string, "supportedSignatureAlgorithms": sigAlgs,
            "keyShareCurves": keyShareCurves, "supportedVersions": supportedVersions,
            "alpnProtocols": alpn_protocols, "alpsProtocols": alps_protocols,
            "certCompressionAlgos": cert_compression_algos, "trustAnchorsPayload": trust_anchors_payload,
            "h2Settings": h2_settings, "h2SettingsOrder": h2_settings_order, "connectionFlow": connection_flow,
            "pseudoHeaderOrder": pseudo_header_order, "priorityFrames": priority_frames, "headerPriority": header_priority}
        customData = {key: value for key, value in customData.items() if value is not None and value != 0}
        if ja3_string:
            if client_identifier is not None: raise SessionConfigurationError("ja3_string cannot be combined with client_identifier")
            # only add Chrome-default filler when explicitly asked; False = raw ja3 as-is
            if fill_custom_with_chrome_defaults: customData["fillCustomWithChromeDefaults"] = True
            if self.tls_extension_order: customData["tlsExtensionOrder"] = self.tls_extension_order
            if self.ech_config_list is not None:
                customData["echConfigList"] = base64.b64encode(self.ech_config_list).decode("ascii")
            if self.grease is not None: customData["grease"] = self.grease
            if self.psk_mode is not None: customData["pskMode"] = self.psk_mode
            if self.key_share_data:
                customData["keyShareData"] = {str(group): base64.b64encode(data).decode("ascii")
                                              for group, data in self.key_share_data.items()}
            self.client_identifier = ""
            self.custom = customData
        elif any(value is not None for key, value in customData.items() if key != "connectionFlow"):
            raise SessionConfigurationError("custom TLS options require ja3_string")
        self._sessionId = str(uuid.uuid4())
        self._closed = False
        self._configMark = self._transportMark()
        self._state = threading.Condition()
        self._inflight: dict[str, _RequestHandle] = {}
        self._streams: "weakref.WeakSet[_NativeStream]" = weakref.WeakSet()
        self._proxySessions: set[str] = set()

    # -- transport identity -------------------------------------------------
    def _transportMark(self) -> tuple[Any, ...]:
        return (self.client_identifier, self.random_tls_extension_order, self.http_version, self.proxy,
                self.verify, self.force_http1, self.disable_http3, self.disable_session_tickets,
                self.server_name_overwrite, self.local_address, self.grease, self.psk_mode,
                tuple(self.tls_extension_order or ()), self.ech_config_list, self.udp_proxy,
                self.header_style, self.keep_alpn, json.dumps(self.custom, sort_keys=True))

    def _markIfChanged(self) -> str | None:
        mark = self._transportMark()
        if mark != self._configMark:
            self._configMark = mark
            oldId, self._sessionId = self._sessionId, str(uuid.uuid4())
            return oldId
        return None

    def _retire(self, force: bool = False) -> list[str]:
        """Native session ids to close: the old main id after a transport change (or always
        with force=True) plus every per-request-proxy session derived from it."""
        oldId = self._markIfChanged()
        if oldId is None and force: oldId, self._sessionId = self._sessionId, str(uuid.uuid4())
        if oldId is None: return []
        with self._state:
            derived, self._proxySessions = list(self._proxySessions), set()
        return [oldId, *derived]

    def _sessionIdFor(self, proxy: str | None) -> str:
        # a Go session keeps the proxy it was built with: a per-request proxy override gets its
        # own native session instead of silently reusing the session's proxy (or direct route)
        if proxy == self.proxy: return self._sessionId
        derived = f"{self._sessionId}~{hashlib.sha256(str(proxy).encode()).hexdigest()[:16]}"
        with self._state: self._proxySessions.add(derived)
        return derived

    def _checkOpen(self) -> None:
        if self._closed: raise SessionConfigurationError("session is closed")

    # -- one request, blocking --------------------------------------------
    def _request(self, method: str, url: str, *, params: Any = None, data: Any = None, json: Any = None,
                 files: Any = None, headers: Mapping[str, str] | None = None, cookies: Any = None,
                 timeout: Any = None, proxy: str | None = None, allow_redirects: bool = True,
                 header_order: Sequence[str] | None = None, host_override: str | None = None,
                 stream: bool = False, max_content_size: int | None = None,
                 _handle: _RequestHandle | None = None) -> Response:
        self._checkOpen()
        handle = _handle or _RequestHandle()
        timeouts = _timeoutConfig(timeout) if timeout is not None else self.timeout
        limit = max_content_size if max_content_size is not None else self.max_content_size
        requestProxy = proxy if proxy is not None else self.proxy
        merged = Headers(self.headers)
        if headers: merged.update(headers)
        body, byteRequest = _encodeBody(data=data, jsonBody=json, files=files, headers=merged,
                                        okhttp=self.header_style == "okhttp")
        # explicit per-request cookies: sent to this URL in place of same-name jar cookies,
        # never stored unless the server sets them (jar cookies are selected natively per hop)
        explicitCookies: dict[str, str] = {}
        if cookies:
            if isinstance(cookies, Mapping): explicitCookies = {str(k): str(v) for k, v in cookies.items()}
            elif isinstance(cookies, CookieJar): explicitCookies = cookies.to_dict(url=url)
            else: explicitCookies = {c["name"]: c["value"] for c in cookies}
        flags = _validateTransport(http_version=self.http_version, force_http1=self.force_http1,
                                   disable_http3=self.disable_http3, proxy=requestProxy,
                                   client_identifier=self.client_identifier, keep_alpn=self.keep_alpn,
                                   udp_proxy=self.udp_proxy)
        payload = _buildPayload(self._sessionIdFor(requestProxy), method=method, url=url, params=params, headers=merged,
                                header_order=self.header_order, body=body, byteRequest=byteRequest,
                                cookies=explicitCookies, flags=flags,
                                timeouts=timeouts, proxy=requestProxy, allow_redirects=allow_redirects,
                                host_override=host_override, identifier=self.client_identifier,
                                random_tls_extension_order=self.random_tls_extension_order, verify=self.verify,
                                disable_session_tickets=self.disable_session_tickets,
                                server_name_overwrite=self.server_name_overwrite, local_address=self.local_address,
                                custom=self.custom, request_header_order=header_order,
                                udp_proxy=self.udp_proxy, want_fingerprint=True,
                                header_style=self.header_style, keep_alpn=self.keep_alpn)
        payload["requestId"] = handle.id
        payload["jar"] = self.cookies._snapshot()
        if stream: payload["stream"] = True
        if limit is not None: payload["maxBodyBytes"] = int(limit)
        with self._state: self._inflight[handle.id] = handle
        try:
            start = time.perf_counter()
            result = _call(payload)
            elapsed = time.perf_counter() - start
        finally:
            with self._state:
                self._inflight.pop(handle.id, None)
                self._state.notify_all()
        streamId = result.get("streamId")
        nativeStream = _NativeStream(streamId, handle.id) if streamId else None
        if not handle.complete():
            # cancelled while the result was on its way: a late response must not touch
            # the session (cookie jar, fingerprint) - drop it
            if nativeStream is not None: nativeStream.close()
            raise RequestCancelled("request cancelled", kind="cancelled", method=method.upper(),
                                   url=_safeUrl(url), request_id=handle.id)
        _applyJarDelta(self.cookies, result.get("jarDelta"))
        if result.get("fingerprint"):
            self.last_fingerprint = result["fingerprint"]
        response = _parseResponse(result, url, elapsed)
        response.fingerprint = result.get("fingerprint")
        response.connection_info = result.get("connectionInfo")
        response.request_id = handle.id
        response._method = method.upper()
        if nativeStream is not None:
            response._stream = nativeStream
            self._streams.add(nativeStream)
        return response

    def _syncRequest(self, method: str, url: str, **kwargs: Any) -> Response:
        for oldId in self._retire(): _closeNative(oldId)
        return self._request(method, url, **kwargs)

    def _cancelInflight(self, grace: float | None) -> None:
        """Let in-flight requests (other threads) finish for ``grace`` seconds, then cancel them."""
        deadline = None if grace is None else time.monotonic() + max(0.0, grace)
        with self._state:
            while self._inflight:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0: break
                self._state.wait(remaining)
            pending = list(self._inflight.values())
        for handle in pending: handle.cancel()

    def _closeStreams(self) -> None:
        for stream in list(self._streams): stream.close()

    def _nativeIds(self) -> list[str]:
        with self._state: return [self._sessionId, *self._proxySessions]

    def close(self, grace: float | None = 5.0) -> None:
        if self._closed: return
        self._closed = True
        self._cancelInflight(grace)
        self._closeStreams()
        for sessionId in self._nativeIds():
            try: _closeNative(sessionId)
            except TLSClientError: pass


class Session:
    """Blocking requests-style TLS session (cookies + default headers per profile)."""
    def __init__(self, **kwargs: Any) -> None:
        self._core = _Core(**kwargs)

    def __enter__(self) -> "Session": self._core._checkOpen(); return self
    def __exit__(self, *_: Any) -> None: self.close()

    @property
    def client_identifier(self) -> str: return self._core.client_identifier
    @property
    def header_style(self) -> str: return self._core.header_style
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
        for oldId in self._core._retire(force=True): _closeNative(oldId)

    def close(self, grace: float | None = 5.0) -> None:
        """Close the session: requests still running in other threads get ``grace`` seconds
        (None = wait for them), then they are cancelled; open response streams are closed."""
        self._core.close(grace)

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
    def header_style(self) -> str: return self._core.header_style
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
            oldIds = self._core._retire()
        if self._core._closed:  # closed between check and execution
            raise SessionConfigurationError("session is closed")
        handle = _RequestHandle()
        try:
            loop = asyncio.get_running_loop()
            for oldId in oldIds: await loop.run_in_executor(_executor, _closeNative, oldId)
            future = loop.run_in_executor(_executor, functools.partial(fn, *args, _handle=handle, **kwargs))
            try: return await asyncio.shield(future)
            except asyncio.CancelledError:
                # abort the native request (connect, TLS, headers or body) instead of waiting
                # for it; a result that still arrives is dropped by _request / _discardLate
                handle.cancel()
                future.add_done_callback(_discardLate)
                raise
        finally:
            if task:
                async with self._lock: self._active.discard(task)

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        core = self._core
        response = await self._run(core._request, method, url, **kwargs)
        response._async = True
        return response

    async def get(self, url: str, **kwargs: Any) -> Response: return await self.request("GET", url, **kwargs)
    async def head(self, url: str, **kwargs: Any) -> Response: return await self.request("HEAD", url, **kwargs)
    async def post(self, url: str, **kwargs: Any) -> Response: return await self.request("POST", url, **kwargs)
    async def put(self, url: str, **kwargs: Any) -> Response: return await self.request("PUT", url, **kwargs)
    async def patch(self, url: str, **kwargs: Any) -> Response: return await self.request("PATCH", url, **kwargs)
    async def delete(self, url: str, **kwargs: Any) -> Response: return await self.request("DELETE", url, **kwargs)
    async def options(self, url: str, **kwargs: Any) -> Response: return await self.request("OPTIONS", url, **kwargs)

    async def reset_connection(self) -> None:
        loop = asyncio.get_running_loop()
        for oldId in self._core._retire(force=True): await loop.run_in_executor(_executor, _closeNative, oldId)

    async def close(self, grace: float | None = 5.0) -> None:
        """Close the session: in-flight requests get ``grace`` seconds (None = wait for them),
        then they are cancelled natively; open response streams are closed."""
        core = self._core
        if core._closed: return
        core._closed = True  # sync flag: even a forgotten await blocks further requests
        active = tuple(task for task in self._active if task is not asyncio.current_task())
        if active:
            _, pending = await asyncio.wait(active, timeout=grace)
            if pending:
                with core._state: handles = list(core._inflight.values())
                for handle in handles: handle.cancel()
                await asyncio.wait(pending, timeout=5.0)
        core._closeStreams()
        loop = asyncio.get_running_loop()
        for sessionId in core._nativeIds():
            try: await loop.run_in_executor(_executor, _closeNative, sessionId)
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
    if not request_kwargs.get("stream"):
        with Session(**session_kwargs) as session:
            return session.request(method, url, **request_kwargs)
    session = Session(**session_kwargs)
    try: response = session.request(method, url, **request_kwargs)
    except BaseException:
        session.close(); raise
    response._owner = session._core  # closed together with the stream
    return response

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
    if not request_kwargs.get("stream"):
        async with AsyncSession(**session_kwargs) as session:
            return await session.request(method, url, **request_kwargs)
    session = AsyncSession(**session_kwargs)
    try: response = await session.request(method, url, **request_kwargs)
    except BaseException:
        await session.close(); raise
    response._owner = session._core  # closed together with the stream
    return response

async def aget(url: str, **kwargs: Any) -> Response: return await arequest("GET", url, **kwargs)
async def ahead(url: str, **kwargs: Any) -> Response: return await arequest("HEAD", url, **kwargs)
async def apost(url: str, **kwargs: Any) -> Response: return await arequest("POST", url, **kwargs)
async def aput(url: str, **kwargs: Any) -> Response: return await arequest("PUT", url, **kwargs)
async def apatch(url: str, **kwargs: Any) -> Response: return await arequest("PATCH", url, **kwargs)
async def adelete(url: str, **kwargs: Any) -> Response: return await arequest("DELETE", url, **kwargs)
async def aoptions(url: str, **kwargs: Any) -> Response: return await arequest("OPTIONS", url, **kwargs)

__all__ += ["request", "get", "head", "post", "put", "patch", "delete", "options",
            "arequest", "aget", "ahead", "apost", "aput", "apatch", "adelete", "aoptions"]
