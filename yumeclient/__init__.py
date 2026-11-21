"""yumeclient — requests-style sync/async HTTP client with browser and app fingerprints.

Every request goes through the native library (native/, Go, loaded with ctypes): it
builds the profile's TLS ClientHello with uTLS, speaks HTTP/1.1, HTTP/2 and HTTP/3
(QUIC) the way the profile's client does, and follows redirects. Its network stack is
bogdanfinn/tls-client with patched upstream modules (native/third_party).
``session.cookies`` is the single source of truth: each call sends a snapshot, the native
per-request jar selects cookies per redirect hop (RFC 6265) and only the changes
(``jarDelta``) come back.

Documentation: https://github.com/october2823/yumeclient/tree/main/docs
"""
from __future__ import annotations

import asyncio
import base64
import contextvars
import ctypes
import functools
import hashlib
import inspect
import json
import mimetypes
import os
import platform
import re
import sys
import threading
import time
import uuid
import warnings
import weakref
from concurrent.futures import ThreadPoolExecutor, wait as _waitFutures
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, Mapping, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit

from ._headers import Headers
from .cookies import CookieJar
from .multipart import choose_boundary, encode_multipart
from .profiles import (ALL_CLIENT_OS, ALL_HEADER_STYLES, ALL_IDENTIFIERS, FIREFOX_H2_EXTRA, HTTP3_FINGERPRINTS, NO_HTTP3,
                       ClientIdentifier, ClientOs, HeaderStyle, Profiles, default_headers, find,
                       resolve_header_style, validate, validate_os)

__all__ = ["Session", "AsyncSession", "Response", "CookieJar", "Headers", "Profiles",
           "ALL_IDENTIFIERS", "ALL_CLIENT_OS", "ALL_HEADER_STYLES", "ClientIdentifier", "ClientOs", "HeaderStyle",
           "find", "default_headers", "TLSClientError", "RequestError",
           "SessionConfigurationError", "close_runtime", "encode_multipart", "choose_boundary",
           "TimeoutConfig", "InvalidRequestError", "RequestCancelled", "ConnectError", "ProxyError", "TLSError",
           "ConnectionClosed", "Timeout", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "ResponseTooLarge",
           "StreamClosed", "HTTPStatusError", "ProtocolError", "TooManyRedirects", "fingerprint_diff",
           "__version__"]

__version__ = "0.8.1"


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
class ProtocolError(ConnectError):
    """The server negotiated an HTTP version the session does not allow (``http_version='2'``
    got HTTP/1.1 or does not speak h2c on http://; ``keep_alpn=True`` got h2). The connection
    is closed before the request is written."""
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
class TooManyRedirects(RequestError):
    """The request was redirected more than 20 times (the Fetch standard's limit)."""


_ERROR_KINDS: dict[str, type[RequestError]] = {
    "timeout": Timeout, "connect_timeout": ConnectTimeout, "read_timeout": ReadTimeout,
    "write_timeout": WriteTimeout, "connect": ConnectError, "dns": ConnectError, "proxy": ProxyError,
    "tls": TLSError, "connection_closed": ConnectionClosed, "cancelled": RequestCancelled,
    "body_too_large": ResponseTooLarge, "invalid_request": InvalidRequestError,
    "configuration": InvalidRequestError, "stream_closed": StreamClosed, "protocol": ProtocolError,
    "too_many_redirects": TooManyRedirects}
_RETRYABLE = frozenset({"timeout", "connect_timeout", "read_timeout", "write_timeout", "connect", "dns",
                        "proxy", "connection_closed"})
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@")
_AUTH_VALUE = re.compile(r"(?i)\b(basic|bearer)\s+[a-z0-9._~+/=-]+")


def _redact(text: str) -> str:
    """Drop credentials from URLs (scheme://user:pass@) and Basic/Bearer tokens."""
    return _AUTH_VALUE.sub(r"\1 ***", _USERINFO.sub(r"\1***@", text))


_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks4a")


def _proxyUrl(value: Any, option: str = "proxy") -> str | None:
    """A proxy URL checked before any request: before 0.8.1 a typo surfaced only at the
    first request, as InvalidRequestError "client creation failed: ...". "" means no
    proxy (per request: a direct connection even when the session has a proxy)."""
    if value is None or value == "": return value
    if not isinstance(value, str): raise SessionConfigurationError(f"{option} must be a URL string, got {type(value).__name__}")
    shown = _safeUrl(value) if "@" in value else value
    if "://" not in value:
        raise SessionConfigurationError(f"{option} {shown!r} has no scheme; write it as http://host:port "
                                        f"(or {', '.join(s + '://' for s in _PROXY_SCHEMES[1:])})")
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in _PROXY_SCHEMES:
        raise SessionConfigurationError(f"{option} {shown!r}: unsupported scheme {parts.scheme!r}; "
                                        f"use one of {', '.join(s + '://' for s in _PROXY_SCHEMES)}")
    try: port = parts.port
    except ValueError: raise SessionConfigurationError(f"{option} {shown!r}: invalid port") from None
    if not parts.hostname: raise SessionConfigurationError(f"{option} {shown!r}: no host")
    if port is None and scheme.startswith("socks"):
        raise SessionConfigurationError(f"{option} {shown!r}: a SOCKS proxy needs a port (usually 1080)")
    return value


def _urlProblem(url: Any) -> str | None:
    """Why a request URL cannot be sent, or None. Checked before the native call: such
    URLs used to fail as a retryable ConnectError (kind "connect")."""
    if not isinstance(url, str): return f"URL must be a str, not {type(url).__name__}"
    if any(ch in url for ch in "\r\n\x00"): return "URL contains control characters"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        return f"invalid URL: {exc}"
    scheme = parts.scheme.lower()
    if not scheme: return "URL has no scheme; use http:// or https://"
    if scheme not in ("http", "https"): return f"unsupported URL scheme {parts.scheme!r}; use http:// or https://"
    if not parts.hostname: return "URL has no host"
    if port == 0: return "invalid URL port 0"
    return None


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
    or ``None`` (no limits). The stages are the same for HTTP/1.1, HTTP/2 and HTTP/3 (where
    ``connect`` is the QUIC handshake).
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


def _closeForgotten(ids: dict[str, Any]) -> None:
    """weakref.finalize callback of a session that was never closed: release its native
    sessions (connections, pools). No lock and no library loading: it can run from the
    garbage collector in any thread, and a library that was never loaded has nothing open."""
    lib = _library
    if lib is None: return
    for sessionId in [ids["main"], *list(ids["proxies"])]:
        try: lib.yumeclient_close(sessionId.encode())
        except Exception: pass


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


_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


def _warn(message: str, category: type[Warning] = UserWarning) -> None:
    """warnings.warn attributed to the first caller outside this package."""
    frame, level = sys._getframe(0), 1
    while frame is not None and os.path.dirname(os.path.abspath(frame.f_code.co_filename)) == _PACKAGE_DIR:
        frame, level = frame.f_back, level + 1
    warnings.warn(message, category, stacklevel=level)


_mainPool: ThreadPoolExecutor | None = None


def _interruptible(call: Any, abort: Any) -> Any:
    """Run a blocking native call so that Ctrl+C reaches the main thread.

    A ctypes call keeps the main thread in C until it returns, so SIGINT used to be handled
    only after the whole response had arrived. On the main thread the call runs on a helper
    thread and is awaited in short slices; on KeyboardInterrupt ``abort()`` cancels it natively
    and the interrupt is re-raised once the native call has returned. Other threads call directly.
    """
    global _mainPool
    if threading.current_thread() is not threading.main_thread(): return call()
    with _poolLock:
        # main-thread calls are sequential; spare workers cover calls whose cancel is still unwinding
        if _mainPool is None: _mainPool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="yumeclient-main")
        pool = _mainPool
    try: future = pool.submit(contextvars.copy_context().run, call)  # caller's contextvars (and 3.14 warning filters)
    except RuntimeError: return call()  # interpreter shutdown (atexit handlers): plain blocking call
    try:
        # short waits return to the interpreter, which runs pending signal handlers (SIGINT).
        # Not future.result(timeout=): yumeclient.Timeout is a TimeoutError too
        while not _waitFutures((future,), timeout=0.05)[0]: pass
    except BaseException:  # KeyboardInterrupt, or whatever a custom signal handler raised
        abort()
        try: late = future.result(timeout=5)
        except BaseException: late = None
        if isinstance(late, Response): late.close()
        raise
    return future.result()


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

    def read_sync(self, size: int, method: str | None, url: str | None) -> bytes:
        return _interruptible(functools.partial(self.read, size, method, url), self.cancel)

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
                 "_owner", "_method", "_request", "__weakref__")

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
        self._request: dict[str, Any] | None = None

    def trace(self, *, redact: Any = (), values: bool = True, redact_query: bool = True) -> dict[str, Any]:
        """Redacted, JSON-safe description of this request (see :func:`yumeclient.diagnostics.request_trace`):
        header order, ALPN, protocol, TLS fingerprint, timings and body hashes; credentials redacted."""
        from .diagnostics import request_trace
        return request_trace(self, redact=redact, values=values, redact_query=redact_query)

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
    @property
    def is_redirect(self) -> bool:
        """A 3xx with a Location header (followed ones are in :attr:`history`)."""
        return 300 <= self.status_code < 400 and any(k.lower() == "location" for k in self.headers)
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
                chunk = stream.read_sync(chunk_size, self._method, self.url)
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
                while not stream.eof: parts.append(stream.read_sync(1 << 20, self._method, self.url))
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
        try:
            while not stream.eof:
                future = _executor.submit(stream.read, chunk_size, self._method, self.url)
                try: chunk = await asyncio.wrap_future(future)
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


def _checkProtocol(*, http_version: str, force_http1: bool, disable_http3: bool, keep_alpn: bool,
                   udp_proxy: str | None, proxy: str | None, alpn: Sequence[str] | None) -> None:
    """Conflicting protocol options: rejected before any network I/O (constructor and
    every request, since session attributes may be reassigned)."""
    httpVer = _version(http_version)
    forced = force_http1 or httpVer == "1.1"
    if force_http1 and httpVer in ("2", "3"):
        raise SessionConfigurationError(f"force_http1=True conflicts with http_version={httpVer!r}")
    if disable_http3 and httpVer == "3": raise SessionConfigurationError("http_version='3' conflicts with disable_http3=True")
    if keep_alpn and not forced:
        raise SessionConfigurationError("keep_alpn=True needs http_version='1.1' (or force_http1=True); "
                                        "with http_version='auto' the profile's ALPN is already sent unchanged")
    if keep_alpn and udp_proxy: raise SessionConfigurationError("keep_alpn cannot be combined with udp_proxy")
    if httpVer == "3" and proxy and not proxy.lower().startswith(("socks5://", "socks5h://")) and not udp_proxy:
        raise SessionConfigurationError(f"HTTP/3 with a {proxy.split(':', 1)[0]}:// proxy: QUIC needs UDP, which only "
                                        "SOCKS5 tunnels. Use a socks5:// proxy, add udp_proxy='socks5://...' for "
                                        "QUIC, or disable HTTP/3")
    if alpn is None: return
    offer = list(alpn)
    if not offer or not all(isinstance(p, str) and p for p in offer):
        raise SessionConfigurationError("alpn_protocols must be a non-empty list of protocol names")
    if forced and not keep_alpn and offer != ["http/1.1"]:
        raise SessionConfigurationError(
            f"alpn_protocols={offer!r} conflicts with forced HTTP/1.1: the ClientHello would offer "
            "['http/1.1'] instead. Pass alpn_protocols=['http/1.1'], or keep_alpn=True to offer this "
            "list and still speak HTTP/1.1")
    if keep_alpn and "http/1.1" not in offer:
        raise SessionConfigurationError(f"keep_alpn=True with alpn_protocols={offer!r}: the server cannot select http/1.1")
    if httpVer == "2" and "h2" not in offer:
        raise SessionConfigurationError(f"http_version='2' with alpn_protocols={offer!r}: h2 is not offered")


# profiles whose QUIC handshake and HTTP/3 layer come from captures of the real client
# (profiles.HTTP3_FINGERPRINTS); "*chrome" = custom JA3 filled with Chrome defaults,
# which takes that Chrome's.
_HTTP3_PROFILES = HTTP3_FINGERPRINTS | {"*chrome"}


# Chromium 124+ sends "priority: u=0, i" (RFC 9218) with a navigation over HTTP/2 and
# HTTP/3, not over HTTP/1.1 (captures of Chrome 99-157, Opera 89-91, 2026-11-20); HTTP/3
# adds it from the profile's captured fingerprint, HTTP/2 from the request (native
# h2Headers). Unless the request sets its own.
_H2_PRIORITY_PROFILES = frozenset({
    "chrome_124", "chrome_130_PSK", "chrome_131", "chrome_131_PSK", "chrome_133", "chrome_133_PSK",
    "chrome_144", "chrome_144_PSK", "chrome_146", "chrome_146_PSK", "chrome_150", "chrome_150_PSK",
    "chrome_152", "chrome_152_PSK", "brave_146", "brave_146_PSK", "edge_131", "edge_latest", "*chrome"})


def _checkHttp3Client(httpVer: str, client_identifier: str) -> None:
    if httpVer == "3" and client_identifier in NO_HTTP3:
        raise SessionConfigurationError(f"http_version='3' with client_identifier={client_identifier!r}: "
                                        f"{NO_HTTP3[client_identifier]}; this client never sends HTTP/3")


def _validateTransport(*, http_version: str, force_http1: bool, disable_http3: bool,
                       proxy: str | None, client_identifier: str, keep_alpn: bool = False,
                       udp_proxy: str | None = None, alpn: Sequence[str] | None = None) -> dict[str, bool]:
    httpVer = _version(http_version)
    _checkProtocol(http_version=httpVer, force_http1=force_http1, disable_http3=disable_http3, keep_alpn=keep_alpn,
                   udp_proxy=udp_proxy, proxy=proxy, alpn=alpn)
    racing = httpVer == "3"
    _checkHttp3Client(httpVer, client_identifier)
    if racing and client_identifier not in _HTTP3_PROFILES:
        _warn("no captured HTTP/3 fingerprint for this profile: the QUIC handshake and HTTP/3 "
              "settings are the library's defaults, not this client's")
    if httpVer == "2" and client_identifier.startswith("chrome_133"):
        _warn("HTTP/2-only selection may alter this profile's ALPN fingerprint")
    return {"forceHttp1": force_http1 or httpVer == "1.1", "disableHttp3": disable_http3 or httpVer == "2",
            "withProtocolRacing": racing}


_NEVER_OMITTED = frozenset({"host", "content-length", "transfer-encoding", "cookie"})
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")  # RFC 9110 field name
_BAD_FIELD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")  # control characters (HTAB allowed)


def _encodeBody(*, data: Any, jsonBody: Any, files: Any, headers: dict[str, str],
                okhttp: bool = False, rawType: bool = True) -> tuple[str | None, bool]:
    """Returns (body, isByteRequest); mutates headers to add a matching Content-Type.

    okhttp style: raw bytes get no implicit Content-Type (an okhttp RequestBody
    without a MediaType sends none); pass Content-Type to match the app. rawType=False
    (Content-Type: None) drops the octet-stream default, which requests never adds."""
    if files is not None:
        bodyBytes, contentType = encode_multipart(data if isinstance(data, (dict, list, tuple)) else None, files)
        headers.setdefault("Content-Type", contentType)
        return base64.b64encode(bodyBytes).decode("ascii"), True
    if jsonBody is not None:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(jsonBody, separators=(",", ":")), False
    if data is not None:
        if isinstance(data, bytes):
            if not okhttp and rawType: headers.setdefault("Content-Type", "application/octet-stream")
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
    # HTTP/1.1: Host first, as every browser and client sends it (the transport put it
    # last when the order did not name it); HTTP/2 and HTTP/3 carry it as :authority
    if header_style != "okhttp":
        named = [k for k in order if isinstance(k, str) and k.lower() == "host"]
        if not named:
            order.insert(0, "Host")
        elif request_header_order is None and header_order is None:
            # a Host header set by the user, without an order naming it: still first
            order = named[:1] + [k for k in order if k not in named]
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
    history = [_historyResponse(item) for item in result.get("history") or ()]
    return Response(int(result.get("status", 0)), result.get("headers") or {},
                    result.get("cookies") or {}, base64.b64decode(encoded),
                    result.get("target", requestUrl), result.get("usedProtocol", ""), history, elapsed)


def _historyResponse(item: dict[str, Any]) -> Response:
    """One followed redirect: status, headers, its Set-Cookie values and body (``b""``
    when the body was larger than 64 KiB)."""
    body = item.get("body")
    response = Response(int(item.get("status", 0)), item.get("headers") or {}, item.get("cookies") or {},
                        base64.b64decode(body) if body else b"", item.get("url", ""),
                        item.get("usedProtocol", ""), [], float(item.get("elapsed") or 0.0))
    response._method = item.get("method")
    return response


# IANA ids -> upstream mapper names (tls-client mapper.go; utls u_common.go for the
# Kyber drafts). The mapper silently skips names it does not know, so unknown values
# are rejected here instead of disappearing from the hello.
_CURVE_NAMES = {23: "P256", 24: "P384", 25: "P521", 29: "X25519", 4588: "X25519MLKEM768",
    0x6399: "X25519Kyber768", 0xFE30: "X25519Kyber512D", 0xFE31: "X25519Kyber768Old",
    0xFE32: "P256Kyber768"}
_VERSION_NAMES = {772: "1.3", 771: "1.2", 770: "1.1", 769: "1.0"}
_CERT_COMPRESSION_NAMES = {1: "zlib", 2: "brotli", 3: "zstd"}  # RFC 8879


def _isGrease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF  # RFC 8701


def _mapperName(option: str, value: Any, names: dict[int, str]) -> str:
    """One value of a custom-JA3 list option as the upstream mapper name: the name
    itself, or the numeric id (int, decimal or 0x-hex string); GREASE values -> GREASE."""
    known = set(names.values())
    if option != "cert_compression_algos": known.add("GREASE")
    number = None
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str):
        if value in known: return value
        text = value.strip()
        try: number = int(text, 16) if text.lower().startswith("0x") else int(text) if text.isdigit() else None
        except ValueError: number = None
    if number is not None:
        if option != "cert_compression_algos" and 0 <= number <= 0xFFFF and _isGrease(number): return "GREASE"
        if number in names: return names[number]
    raise SessionConfigurationError(
        f"{option}: unsupported value {value!r}; use one of {', '.join(sorted(known))} or its numeric id")


def _normalizeCurveName(value):
    return _mapperName("key_share_curves", value, _CURVE_NAMES)


def _normalizeVersionName(value):
    return _mapperName("supported_versions", value, _VERSION_NAMES)

_H2_SETTING_IDS = {"HEADER_TABLE_SIZE": 1, "ENABLE_PUSH": 2, "MAX_CONCURRENT_STREAMS": 3,
                   "INITIAL_WINDOW_SIZE": 4, "MAX_FRAME_SIZE": 5, "MAX_HEADER_LIST_SIZE": 6,
                   "ENABLE_CONNECT_PROTOCOL": 8, "NO_RFC7540_PRIORITIES": 9}


_CUSTOM_OPTION_NAMES = {"supportedSignatureAlgorithms": "supported_signature_algorithms",
                        "keyShareCurves": "key_share_curves", "supportedVersions": "supported_versions",
                        "alpnProtocols": "alpn_protocols", "alpsProtocols": "alps_protocols",
                        "certCompressionAlgos": "cert_compression_algos",
                        "trustAnchorsPayload": "trust_anchors_payload", "h2Settings": "h2_settings",
                        "h2SettingsOrder": "h2_settings_order", "connectionFlow": "connection_flow",
                        "pseudoHeaderOrder": "pseudo_header_order", "priorityFrames": "priority_frames",
                        "headerPriority": "header_priority"}


def _h2SettingName(value: Any) -> str:
    """An HTTP/2 setting as the native layer reads it: a name (RFC 9113, upstream's
    UNKNOWN_SETTING_<id>) or the numeric id. Unknown names used to be dropped silently."""
    if isinstance(value, bool): raise SessionConfigurationError(f"h2 setting {value!r}: expected a name or an id")
    if isinstance(value, int): number = value
    else:
        text = str(value).strip()
        if text.upper() in _H2_SETTING_IDS: return text.upper()
        digits = text.upper().removeprefix("UNKNOWN_SETTING_")
        try: number = int(digits, 0)
        except ValueError:
            raise SessionConfigurationError(f"unknown HTTP/2 setting {value!r}; use one of "
                                            f"{', '.join(_H2_SETTING_IDS)} or a numeric id") from None
    if not 0 < number <= 0xFFFF: raise SessionConfigurationError(f"HTTP/2 setting id {value!r} out of range 1..65535")
    return str(number)


def _h2Settings(settings: Mapping[Any, int] | None, order: Sequence[Any] | None) -> tuple[dict[str, int] | None, list[str] | None]:
    resolved = None
    if settings is not None:
        resolved = {}
        for key, value in settings.items():
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
                raise SessionConfigurationError(f"HTTP/2 setting {key!r}: value must be an int 0..2**32-1")
            resolved[_h2SettingName(key)] = value
    if order is None:
        # the native side keeps settings in a map: without an explicit order the frame
        # order was random; the dict order is what the caller wrote
        return resolved, list(resolved) if resolved else None
    return resolved, [_h2SettingName(key) for key in order]


def _trustAnchorsHex(value: Any, ja3: str | None) -> str | None:
    """trust_anchors_payload (bytes or hex) -> hex of the trust_anchors extension (0xca34) data."""
    if value is None: return None
    if isinstance(value, (bytes, bytearray)): data = bytes(value)
    elif isinstance(value, str):
        try: data = bytes.fromhex(value.replace(":", "").replace(" ", ""))
        except ValueError: raise SessionConfigurationError("trust_anchors_payload must be bytes or a hex string") from None
    else: raise SessionConfigurationError("trust_anchors_payload must be bytes or a hex string")
    if len(data) < 2 or int.from_bytes(data[:2], "big") != len(data) - 2:
        raise SessionConfigurationError("trust_anchors_payload must be a TrustAnchorIdentifier list: "
                                        "a 2-byte length followed by that many bytes")
    extensions = ja3.split(",")[2].split("-") if ja3 and ja3.count(",") >= 2 else []
    if ja3 and "51764" not in extensions:
        raise SessionConfigurationError("trust_anchors_payload needs extension 51764 (trust_anchors) in ja3_string")
    return data.hex()


def _normalizeHexU16(value):
    # upstream ja3.go: strconv.ParseUint(s, 16, 16) — hex WITHOUT 0x prefix.
    # decimal ja3 strings ("1027") vs hex strings ("0403") are disambiguated:
    # leading zero or hex letters -> hex as-is; all digits without leading zero
    # -> decimal converted to hex ("1027" -> "403").
    if isinstance(value, int): return "%x" % value
    if not isinstance(value, str): return str(value)
    if value.lower().startswith("0x"): return value[2:]  # upstream parses hex without the prefix
    stripped = value
    if stripped.isdigit() and len(stripped) < 5 and stripped[0] != "0":
        return "%x" % int(stripped)
    return value


_PSEUDO = {":method": ":method", ":authority": ":authority", ":scheme": ":scheme", ":path": ":path"}
_PSEUDO.update({name[1:]: name for name in list(_PSEUDO)})
_PSEUDO.update({name[1]: name for name in list(_PSEUDO.values())})


def _pseudoOrder(order: Sequence[str] | None) -> list[str] | None:
    """The four request pseudo-headers in the wire order (":method", "method" or "m").
    A partial or misspelled list used to drop the missing ones from the request."""
    if order is None: return None
    resolved = [_PSEUDO.get(str(name).strip().lower()) for name in order]
    if None in resolved or sorted(set(resolved)) != sorted(set(_PSEUDO.values())) or len(resolved) != 4:
        raise SessionConfigurationError(f"pseudo_header_order {list(order)!r}: list all four of "
                                        f":method, :authority, :scheme, :path once")
    return resolved


_SIGALG_NAMES = frozenset({"PKCS1WithSHA256", "PKCS1WithSHA384", "PKCS1WithSHA512", "PSSWithSHA256", "PSSWithSHA384",
                           "PSSWithSHA512", "ECDSAWithP256AndSHA256", "ECDSAWithP384AndSHA384",
                           "ECDSAWithP521AndSHA512", "PKCS1WithSHA1", "ECDSAWithSHA1", "Ed25519", "SHA224_RSA",
                           "SHA224_ECDSA"})


def _sigAlg(value: Any) -> str:
    """A signature scheme: upstream name, int id, hex string ("0403", "0x0403") or decimal."""
    normalized = _normalizeHexU16(value)
    if normalized in _SIGALG_NAMES: return normalized
    try: number = int(normalized, 16)
    except ValueError: number = -1
    if not 0 <= number <= 0xFFFF:
        raise SessionConfigurationError(f"unknown signature algorithm {value!r}; use a name "
                                        f"({', '.join(sorted(_SIGALG_NAMES))}) or the IANA id")
    return normalized


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
                 cert_compression_algos: Sequence[str] | None = None, trust_anchors_payload: bytes | str | None = None,
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
        # explicit options as passed (Session.export_profile)
        self._options = {name: value for name, value in locals().items()
                         if name != "self" and value is not _CORE_DEFAULTS.get(name, _MISSING)
                         and value != _CORE_DEFAULTS.get(name, _MISSING)}
        try:
            self.client_identifier = validate(client_identifier)
            self.client_os = validate_os(client_os, self.client_identifier)
            # ja3 sessions have no profile: raw unless header_style says otherwise
            self.header_style = resolve_header_style("" if ja3_string else self.client_identifier, header_style)
        except ValueError as exc: raise SessionConfigurationError(str(exc)) from exc
        self.keep_alpn = bool(keep_alpn)
        proxy = _proxyUrl(proxy) or None
        udp_proxy = _proxyUrl(udp_proxy, "udp_proxy") or None
        if isinstance(alpn_protocols, str): alpn_protocols = [alpn_protocols]
        _checkProtocol(http_version=_version(http_version), force_http1=force_http1, disable_http3=disable_http3,
                       keep_alpn=self.keep_alpn, udp_proxy=udp_proxy, proxy=proxy,
                       alpn=list(alpn_protocols) if alpn_protocols is not None else None)
        if ja3_string is None: _checkHttp3Client(_version(http_version), self.client_identifier)
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
        if ech_config_list is not None:
            if ja3_string is None: raise SessionConfigurationError("ech_config_list requires ja3_string")
            ech_config_list = bytes(ech_config_list)
            # ECHConfigList: 2-byte length, then the configs (draft-ietf-tls-esni)
            if len(ech_config_list) < 2 or int.from_bytes(ech_config_list[:2], "big") != len(ech_config_list) - 2:
                raise SessionConfigurationError("ech_config_list must be a serialized ECHConfigList (2-byte length prefix)")
            ja3Parts = ja3_string.split(",")
            if len(ja3Parts) < 3 or "65037" not in ja3Parts[2].split("-"):
                raise SessionConfigurationError("ech_config_list needs extension 65037 (encrypted_client_hello) in ja3_string")
            if _version(http_version) == "3":
                raise SessionConfigurationError("ech_config_list works over TCP only (HTTP/1.1, HTTP/2), not with http_version='3'")
        if grease is not None and ja3_string is None:
            raise SessionConfigurationError("grease requires ja3_string")
        if psk_mode is not None:
            if psk_mode not in ("psk", "no_psk"):
                raise SessionConfigurationError("psk_mode must be 'psk' or 'no_psk'")
            if ja3_string is None: raise SessionConfigurationError("psk_mode requires ja3_string")
        if udp_proxy is not None and not udp_proxy.lower().startswith(("socks5://", "socks5h://")):
            raise SessionConfigurationError("udp_proxy must be a socks5:// proxy (QUIC goes through its UDP ASSOCIATE)")
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
        sigAlgs = [_sigAlg(v) for v in supported_signature_algorithms] if supported_signature_algorithms is not None else None
        h2Resolved, h2OrderResolved = _h2Settings(h2_settings, h2_settings_order)
        customData = {"ja3String": ja3_string, "supportedSignatureAlgorithms": sigAlgs,
            "keyShareCurves": keyShareCurves, "supportedVersions": supportedVersions,
            "alpnProtocols": alpn_protocols, "alpsProtocols": alps_protocols,
            "certCompressionAlgos": [_mapperName("cert_compression_algos", v, _CERT_COMPRESSION_NAMES)
                                     for v in cert_compression_algos] if cert_compression_algos is not None else None,
            "trustAnchorsPayload": _trustAnchorsHex(trust_anchors_payload, ja3_string),
            "h2Settings": h2Resolved, "h2SettingsOrder": h2OrderResolved, "connectionFlow": connection_flow,
            "pseudoHeaderOrder": _pseudoOrder(pseudo_header_order), "priorityFrames": priority_frames,
            "headerPriority": header_priority}
        customData = {key: value for key, value in customData.items() if value is not None and value != 0}
        if ja3_string:
            if client_identifier is not None: raise SessionConfigurationError("ja3_string cannot be combined with client_identifier")
            # what the ja3 and the explicit options leave open (extension contents, HTTP/2,
            # HTTP/3) comes from this Chrome profile; False = generic values only
            if fill_custom_with_chrome_defaults: customData["chromeDefaultsProfile"] = Profiles.LATEST_CHROME
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
        elif customData:  # connection_flow included: without ja3_string it was silently ignored
            raise SessionConfigurationError(f"{', '.join(_CUSTOM_OPTION_NAMES.get(k, k) for k in customData)} "
                                            "require ja3_string")
        self._sessionId = str(uuid.uuid4())
        self._closed = False
        self._configMark = self._transportMark()
        self._state = threading.Condition()
        self._inflight: dict[str, _RequestHandle] = {}
        self._streams: "weakref.WeakSet[_NativeStream]" = weakref.WeakSet()
        self._proxySessions: set[str] = set()
        # a session dropped without close() releases its native connections when collected
        self._liveIds: dict[str, Any] = {"main": self._sessionId, "proxies": self._proxySessions}
        self._forgotten = weakref.finalize(self, _closeForgotten, self._liveIds)
        self._forgotten.atexit = False  # the process is ending anyway

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
            self._liveIds["main"] = self._sessionId
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
            self._liveIds.update(main=self._sessionId, proxies=self._proxySessions)
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
                 _handle: _RequestHandle | None = None, _flags: dict[str, bool] | None = None) -> Response:
        self._checkOpen()
        problem = _urlProblem(url)
        if problem:
            raise InvalidRequestError(problem, kind="invalid_request", stage="request", method=str(method).upper(),
                                      url=_safeUrl(url) if isinstance(url, str) else None)
        handle = _handle or _RequestHandle()
        timeouts = _timeoutConfig(timeout) if timeout is not None else self.timeout
        limit = max_content_size if max_content_size is not None else self.max_content_size
        requestProxy = _proxyUrl(proxy) if proxy is not None else self.proxy
        merged = Headers(self.headers)
        if headers: merged.update(headers)
        # None removes a header (requests semantics), also one the transport would add
        removed = [key.lower() for key, value in merged.items() if value is None]
        for key in removed: del merged[key]
        for key, value in merged.items():
            # rejected here rather than by the transport: a failed request would cost the
            # session its connections and send a replayable request out again
            if (isinstance(key, str) and not _TOKEN.fullmatch(key)) or (isinstance(value, str) and _BAD_FIELD_VALUE.search(value)):
                raise InvalidRequestError(f"invalid header {key!r}: field names must be tokens "
                                          "and values must not contain control characters",
                                          kind="invalid_request", method=method.upper(), url=_safeUrl(url))
        body, byteRequest = _encodeBody(data=data, jsonBody=json, files=files, headers=merged,
                                        okhttp=self.header_style == "okhttp",
                                        rawType="content-type" not in removed)
        # as in requests, the body still sets its Content-Type, the jar its cookies, and
        # Host / Content-Length are always sent; invalid names were never sent anyway
        omitted = [key for key in removed if key not in merged and key not in _NEVER_OMITTED and _TOKEN.fullmatch(key)]
        # explicit per-request cookies: sent to this URL in place of same-name jar cookies,
        # never stored unless the server sets them (jar cookies are selected natively per hop)
        explicitCookies: dict[str, str] = {}
        if cookies:
            if isinstance(cookies, Mapping): explicitCookies = {str(k): str(v) for k, v in cookies.items()}
            elif isinstance(cookies, CookieJar): explicitCookies = cookies.to_dict(url=url)
            else: explicitCookies = {c["name"]: c["value"] for c in cookies}
        flags = _flags if _flags is not None else self._flags(requestProxy)
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
        if _version(self.http_version) == "2": payload["requireProtocol"] = "h2"
        h2Extra = []
        if self.header_style != "okhttp":
            if self._h3Identity() in _H2_PRIORITY_PROFILES and "priority" not in omitted:
                h2Extra.append(["priority", "u=0, i"])
            if self.client_identifier.startswith("firefox_") and self.custom is None:
                h2Extra += [[k, v] for k, v in FIREFOX_H2_EXTRA if k not in omitted and k not in merged]
        if h2Extra: payload["h2Headers"] = h2Extra
        if omitted: payload["omitHeaders"] = omitted
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
        response._request = {"method": method.upper(), "url": payload.get("requestUrl"),
                             "headers": list(merged.items()), "body": _requestBody(body, byteRequest)}
        if nativeStream is not None:
            response._stream = nativeStream
            self._streams.add(nativeStream)
        return response

    def _flags(self, proxy: str | None) -> dict[str, bool]:
        """Per-request protocol check and flags. Called in the caller's thread (before the
        request moves to a worker) so that errors and warnings point at the caller."""
        return _validateTransport(http_version=self.http_version, force_http1=self.force_http1,
                                  disable_http3=self.disable_http3, proxy=self.proxy if proxy is None else _proxyUrl(proxy),
                                  client_identifier=self._h3Identity(), keep_alpn=self.keep_alpn,
                                  udp_proxy=self.udp_proxy, alpn=(self.custom or {}).get("alpnProtocols"))

    def _h3Identity(self) -> str:
        if self.custom is None: return self.client_identifier
        return "*chrome" if self.custom.get("chromeDefaultsProfile") else ""

    def _syncRequest(self, method: str, url: str, **kwargs: Any) -> Response:
        kwargs["_flags"] = self._flags(kwargs.get("proxy"))
        for oldId in self._retire(): _closeNative(oldId)
        handle = _RequestHandle()
        return _interruptible(functools.partial(self._request, method, url, _handle=handle, **kwargs), handle.cancel)

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
        self._forgotten.detach()
        self._cancelInflight(grace)
        self._closeStreams()
        for sessionId in self._nativeIds():
            try: _closeNative(sessionId)
            except TLSClientError: pass


_MISSING = object()
_CORE_DEFAULTS = {name: param.default for name, param in inspect.signature(_Core.__init__).parameters.items()
                  if param.default is not inspect.Parameter.empty}


# Transport options pick the native session (profile, protocol, proxy, TLS); they are fixed for
# the lifetime of a Session. Assigning one on the facade used to be accepted and ignored.
_FIXED_OPTIONS = frozenset(inspect.signature(_Core.__init__).parameters) - {"self", "headers", "cookies"}


class _FixedTransport:
    __slots__ = ()

    @classmethod
    def from_profile(cls, profile: Mapping[str, Any], **overrides: Any) -> Any:
        """New session from :meth:`export_profile` output; ``overrides`` (e.g. ``proxy=``,
        ``timeout=``) are passed to the constructor. The exported default headers replace the
        profile defaults exactly (order and removals included) unless ``headers=`` is given.
        Credential headers are not exported (see ``omitted_headers``): set them again."""
        from .diagnostics import profile_options
        kwargs, headers = profile_options(profile)
        kwargs.update(overrides)
        session = cls(**kwargs)
        if headers is not None and "headers" not in overrides: session._core.headers = Headers(headers)
        return session

    def export_profile(self, *, include_fingerprint: bool = True, include_secrets: bool = False) -> dict[str, Any]:
        """Versioned, JSON-safe snapshot of this session's TLS/HTTP identity (profile, OS,
        header style, protocol and ClientHello options, default headers in order, last observed
        fingerprint). Proxy, timeouts, cookies and certificate settings are not included;
        credential-like default headers (Authorization, Cookie, *token*, *key*, ...) only with
        ``include_secrets=True`` - otherwise their names are listed in ``omitted_headers``."""
        from .diagnostics import export_profile
        return export_profile(self, include_fingerprint=include_fingerprint, include_secrets=include_secrets)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _FIXED_OPTIONS:
            raise AttributeError(f"{name!r} is fixed for the lifetime of a session: create a new session. "
                                 "Per request you can pass proxy=, timeout=, headers=, cookies=, header_order=, "
                                 "allow_redirects=, stream=, max_content_size=")
        object.__setattr__(self, name, value)


class Session(_FixedTransport):
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


class AsyncSession(_FixedTransport):
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
            # wrap_future, not shield(run_in_executor): a shielded inner future that fails after
            # the outer one was cancelled is reported to the loop's exception handler (3.14)
            future = _executor.submit(contextvars.copy_context().run, functools.partial(fn, *args, _handle=handle, **kwargs))
            try: return await asyncio.wrap_future(future)
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
        kwargs["_flags"] = core._flags(kwargs.get("proxy"))
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


from .diagnostics import _requestBody, fingerprint_diff  # noqa: E402  (needs the classes above)
