"""multipart/form-data encoding, requests-compatible.

Laid out the way requests and urllib3 lay them out: fields first, then files,
CRLF-terminated parts, percent-escaped CR/LF/quote in names, Chrome-style
boundary. File specs accept bare file objects/bytes/str or tuples of
(filename, content[, content type[, extra part headers]]).

This module is intentionally standalone: tweak it without touching the core.
"""
from __future__ import annotations

import mimetypes
import os
import uuid
from typing import Any, Mapping, Sequence

__all__ = ["encode_multipart", "choose_boundary"]


def choose_boundary() -> str:
    """Chrome-style boundary: ----WebKitFormBoundary + 16 hex chars."""
    return "----WebKitFormBoundary" + uuid.uuid4().hex[:16]


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
    boundary = boundary or choose_boundary()
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
