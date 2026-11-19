#!/usr/bin/env python3
"""Smoke test for an *installed* yumeclient wheel (CI: run from outside the source tree).

Checks: the package imports from site-packages, the bundled native library loads
through ctypes, and sync + async requests against a local HTTP server work,
including prompt async cancellation. No external network access.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yumeclient


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path.startswith("/slow"):
            time.sleep(2)
        body = b"smoke-ok"
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "smoke=1; Path=/")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *_: object) -> None:
        pass


async def _async_checks(base: str) -> None:
    async with yumeclient.AsyncSession(timeout=10) as session:
        response = await session.get(base + "/a")
        assert response.status_code == 200 and response.content == b"smoke-ok", response
        started = time.monotonic()
        try:
            await asyncio.wait_for(session.get(base + "/slow"), timeout=0.2)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("slow request was not cancelled")
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, f"cancellation took {elapsed:.2f}s"


def main() -> int:
    package = Path(yumeclient.__file__).resolve().parent
    library = yumeclient._libraryPath()
    print(f"python {sys.version.split()[0]} | package {package} | native {library.name}")
    assert "site-packages" in str(package) or "dist-packages" in str(package), "not testing the installed wheel"
    assert library.is_file(), library
    yumeclient._native()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with yumeclient.Session(timeout=10) as session:
            response = session.get(base + "/s")
            assert response.status_code == 200 and response.text == "smoke-ok", response
            assert session.cookies.get("smoke") == "1", session.cookies.export()
            with session.get(base + "/s", stream=True) as streamed:
                assert b"".join(streamed.iter_bytes(3)) == b"smoke-ok"
            assert yumeclient._debugStats()["streams"] == 0
        asyncio.run(_async_checks(base))
    finally:
        server.shutdown()
        server.server_close()
    print("smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
