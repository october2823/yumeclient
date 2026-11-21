"""A local stand-in for the part of httpbin.org the examples use, so they run offline in
the tests (``HTTPBIN=http://127.0.0.1:<port> python examples/<name>.py``).

Endpoints: /get /post /put /patch /delete /anything (request echo), /headers, /ip,
/user-agent, /cookies, /cookies/set, /cookies/delete, /status/<code>, /redirect/<n>,
/delay/<seconds>, /gzip, /json, /bytes/<n>, /stream-bytes/<n>.

    python tests/httpbin_local.py [port]
"""
from __future__ import annotations

import gzip
import json
import sys
import threading
import time
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def _multipart(content_type: str, body: bytes) -> tuple[dict, dict]:
    message = BytesParser(policy=HTTP).parsebytes(f"Content-Type: {content_type}\r\n\r\n".encode() + body)
    form, files = {}, {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if part.get_filename() is not None:
            files[name] = payload.decode("utf-8", "replace")
        else:
            form[name] = payload.decode("utf-8", "replace")
    return form, files


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "httpbin-local"

    def log_message(self, *args):
        pass

    def _send(self, status=200, body=b"", content_type="application/json", headers=()):
        self.send_response(status)
        if body or status not in (204, 304):
            self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, value, status=200, headers=()):
        self._send(status, json.dumps(value, indent=2).encode() + b"\n", headers=headers)

    def _cookies(self) -> dict:
        jar = {}
        for header in self.headers.get_all("Cookie") or []:
            for pair in header.split(";"):
                name, _, value = pair.strip().partition("=")
                if name:
                    jar[name] = value
        return jar

    def _echo(self, body: bytes = b""):
        url = urlsplit(self.path)
        args = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(url.query).items()}
        content_type = self.headers.get("Content-Type", "")
        form, files, data, parsed = {}, {}, "", None
        if content_type.startswith("application/x-www-form-urlencoded"):
            form = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(body.decode()).items()}
        elif content_type.startswith("multipart/form-data"):
            form, files = _multipart(content_type, body)
        else:
            data = body.decode("utf-8", "replace")
            if content_type.startswith("application/json"):
                parsed = json.loads(body or b"null")
        self._json({
            "args": args, "data": data, "files": files, "form": form, "json": parsed,
            "headers": {k: v for k, v in self.headers.items()}, "method": self.command,
            "origin": self.client_address[0], "url": f"http://{self.headers.get('Host')}{self.path}",
        })

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query, keep_blank_values=True)
        if path in ("/get", "/anything") or path.startswith("/anything/"):
            return self._echo()
        if path == "/headers":
            return self._json({"headers": dict(self.headers.items())})
        if path == "/ip":
            return self._json({"origin": self.client_address[0]})
        if path == "/user-agent":
            return self._json({"user-agent": self.headers.get("User-Agent")})
        if path == "/cookies":
            return self._json({"cookies": self._cookies()})
        if path == "/cookies/set":
            headers = [("Set-Cookie", f"{k}={v[0]}; Path=/") for k, v in query.items()] + [("Location", "/cookies")]
            return self._send(302, headers=headers)
        if path == "/cookies/delete":
            headers = [("Set-Cookie", f"{k}=; Max-Age=0; Path=/") for k in query] + [("Location", "/cookies")]
            return self._send(302, headers=headers)
        if path.startswith("/status/"):
            return self._send(int(path.rsplit("/", 1)[1]))
        if path.startswith("/redirect/"):
            n = int(path.rsplit("/", 1)[1])
            return self._send(302, headers=[("Location", f"/redirect/{n - 1}" if n > 1 else "/get")])
        if path.startswith("/delay/"):
            time.sleep(min(float(path.rsplit("/", 1)[1]), 10))
            return self._echo()
        if path == "/gzip":
            body = gzip.compress(json.dumps({"gzipped": True, "headers": dict(self.headers.items())}).encode())
            return self._send(body=body, headers=[("Content-Encoding", "gzip")])
        if path == "/json":
            return self._json({"slideshow": {"title": "Sample Slide Show", "slides": []}})
        if path.startswith("/bytes/"):
            return self._send(body=bytes(i % 256 for i in range(int(path.rsplit("/", 1)[1]))),
                              content_type="application/octet-stream")
        if path.startswith("/stream-bytes/"):
            n = int(path.rsplit("/", 1)[1])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for start in range(0, n, 10240):
                chunk = bytes(i % 256 for i in range(start, min(n, start + 10240)))
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.write(b"0\r\n\r\n")
            return None
        return self._send(404, b'{"error": "not found"}\n')

    def do_HEAD(self):
        return self.do_GET()

    def do_POST(self):
        body = self._body()
        path = urlsplit(self.path).path
        if path.startswith("/status/"):
            return self._send(int(path.rsplit("/", 1)[1]))
        if path.startswith("/redirect-to"):
            return self._send(302, headers=[("Location", "/get")])
        return self._echo(body)

    do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_POST


class _Server(ThreadingHTTPServer):
    request_queue_size = 128  # the examples open many connections at once
    daemon_threads = True


class HTTPBin:
    def __init__(self, port: int = 0):
        self.httpd = _Server(("127.0.0.1", port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    srv = HTTPBin(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
    print(f"httpbin-local on {srv.url}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.close()
