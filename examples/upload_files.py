"""File uploads: multipart/form-data with files and form fields, the way requests takes them.

    python examples/upload_files.py
"""
import io
import os

from yumeclient import Session, encode_multipart

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")

with Session(timeout=30) as s:
    files = {
        # (file name, content, content type); content: bytes, str or a binary file object
        "avatar": ("me.png", b"\x89PNG\r\n\x1a\nnot really a png", "image/png"),
        "notes": ("notes.txt", io.BytesIO(b"line 1\nline 2\n")),
        "raw": b"just bytes",  # no file name: sent as a file part named after the field
    }
    r = s.post(f"{BASE}/post", data={"title": "upload", "public": "1"}, files=files)
    body = r.json()
    print("form fields:", body["form"])
    print("files:", {name: len(content) for name, content in body["files"].items()})
    print("content type:", body["headers"]["Content-Type"][:30], "...")

# The same encoder is available directly, e.g. for a body you send yourself.
payload, content_type = encode_multipart({"field": "value"}, {"doc": ("a.txt", b"hello")})
print(len(payload), "bytes,", content_type)
