"""Streaming: download to a file chunk by chunk, cap the response size, read a stream in
asyncio.

    python examples/streaming_download.py
"""
import asyncio
import hashlib
import os
import tempfile
from pathlib import Path

from yumeclient import AsyncSession, ResponseTooLarge, Session

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")
target = Path(tempfile.gettempdir()) / "yumeclient-download.bin"

with Session(timeout=30) as s:
    # stream=True returns as soon as the headers arrive; the body is read as you iterate.
    with s.get(f"{BASE}/stream-bytes/102400", stream=True) as r:
        r.raise_for_status()
        digest, size = hashlib.sha256(), 0
        with target.open("wb") as f:
            for chunk in r.iter_bytes(16384):
                f.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    print(f"downloaded {size} bytes to {target}, sha256 {digest.hexdigest()[:16]}...")
    target.unlink()

    # max_content_size: refuse bodies larger than the limit (after decompression).
    try:
        s.get(f"{BASE}/bytes/50000", max_content_size=10000)
    except ResponseTooLarge as e:
        print("too large:", e.kind)

    # A stream you don't read to the end: leaving the with-block closes it and frees the
    # connection.
    with s.get(f"{BASE}/stream-bytes/102400", stream=True) as r:
        first = next(r.iter_bytes(1024))
        print("read only", len(first), "bytes of the stream")


async def main() -> None:
    async with AsyncSession(timeout=30) as s:
        async with await s.get(f"{BASE}/stream-bytes/65536", stream=True) as r:
            total = 0
            async for chunk in r.aiter_bytes(8192):
                total += len(chunk)
        print("async stream:", total, "bytes")

        # Or read the whole streamed body at once.
        r = await s.get(f"{BASE}/bytes/2048", stream=True)
        body = await r.aread()
        print("aread:", len(body), "bytes")


asyncio.run(main())
