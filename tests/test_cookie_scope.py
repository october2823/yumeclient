"""Cookie scoping (RFC 6265): domain / host-only, path, Secure, expiry, deletion, redirects,
per-request overrides and concurrent requests. A local forward proxy stands in for any
hostname, so http://www.example.test/... reaches the echo handler without DNS."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from yumeclient import AsyncSession, CookieJar, Session


class _Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)          # absolute URI: we are the forward proxy
        query = parse_qs(parts.query)
        headers = [("Set-Cookie", value) for value in query.get("set", [])]
        if parts.path == "/redir":
            status, body = 302, b""
            headers.append(("Location", query["to"][0]))
        else:
            if "sleep" in query:
                time.sleep(float(query["sleep"][0]))
            status = 200
            body = json.dumps({"host": parts.hostname, "path": parts.path,
                               "cookie": self.headers.get("Cookie", "")}).encode()
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def proxy():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def url(host: str, path: str = "/echo", **query: object) -> str:
    q = urlencode(query, doseq=True)
    return f"http://{host}{path}" + (f"?{q}" if q else "")


def sent(response) -> list[str]:
    raw = response.json()["cookie"]
    return [part.strip() for part in raw.split(";") if part.strip()]


@pytest.fixture
def session(proxy):
    with Session(proxy=proxy, timeout=10) as s:
        yield s


def test_host_only_vs_domain_cookie(session):
    session.get(url("www.example.test", set=["h=1; Path=/", "d=2; Domain=example.test; Path=/"]))
    assert sorted(sent(session.get(url("www.example.test")))) == ["d=2", "h=1"]
    assert sent(session.get(url("api.example.test"))) == ["d=2"]          # host-only h stays on www
    assert sent(session.get(url("unrelated.test"))) == []
    host_only = next(c for c in session.cookies if c.name == "h")
    assert host_only.host_only and host_only.domain == "www.example.test"
    assert "h" not in session.cookies.to_dict(domain="sub.www.example.test")


def test_server_cannot_set_cookie_for_unrelated_domain(session):
    session.get(url("www.example.test", set=["evil=1; Domain=other.test; Path=/"]))
    assert "evil" not in session.cookies
    assert sent(session.get(url("other.test"))) == []


def test_public_suffix_domain_is_rejected(session):
    # Domain=co.uk / github.io would reach every site under the suffix (RFC 6265 5.3 step 5)
    session.get(url("shop.example.co.uk", set=["ps=1; Domain=co.uk; Path=/", "ok=2; Domain=example.co.uk; Path=/"]))
    session.get(url("alice.github.io", set=["gh=3; Domain=github.io; Path=/"]))
    assert sent(session.get(url("victim.co.uk"))) == []
    assert sent(session.get(url("bob.github.io"))) == []
    assert sent(session.get(url("www.example.co.uk"))) == ["ok=2"]
    assert sorted(c.name for c in session.cookies) == ["ok"]


def test_public_suffix_host_keeps_its_own_cookie_host_only(session):
    session.get(url("github.io", set=["own=1; Domain=github.io; Path=/"]))
    assert sent(session.get(url("github.io"))) == ["own=1"]
    assert sent(session.get(url("alice.github.io"))) == []
    cookie = next(iter(session.cookies))
    assert cookie.host_only and cookie.domain == "github.io"


def test_ip_host_domain_cookie_is_host_only(session):
    session.get(url("10.1.2.3", set=["ip=1; Domain=10.1.2.3; Path=/"]))
    cookie = next(iter(session.cookies))
    assert cookie.host_only and cookie.domain == "10.1.2.3"


def test_path_scope_and_order(session):
    jar = session.cookies
    jar.set("p", "admin", domain="example.test", path="/admin")
    jar.set("n", "root", domain="example.test", path="/")
    jar.set("n", "deep", domain="example.test", path="/admin/x")
    assert sent(session.get(url("example.test", "/public"))) == ["n=root"]
    assert sent(session.get(url("example.test", "/administrator"))) == ["n=root"]
    assert sent(session.get(url("example.test", "/admin/x/y"))) == ["n=deep", "p=admin", "n=root"]


def test_default_path_from_response(session):
    session.get(url("example.test", "/a/b/page", set=["dp=1"]))    # no Path: default-path /a/b
    assert sent(session.get(url("example.test", "/a/b/other"))) == ["dp=1"]
    assert sent(session.get(url("example.test", "/a"))) == []


def test_secure_cookie_never_sent_over_http(session):
    session.cookies.set("sec", "1", domain="example.test", secure=True)
    session.cookies.set("plain", "1", domain="example.test")
    assert sent(session.get(url("example.test"))) == ["plain=1"]
    assert session.cookies.to_dict(url="http://example.test/") == {"plain": "1"}
    assert session.cookies.to_dict(url="https://example.test/") == {"sec": "1", "plain": "1"}


def test_expired_cookie_not_sent(session):
    session.cookies.set("old", "1", domain="example.test", expires=time.time() - 10)
    session.cookies.set("new", "1", domain="example.test", expires=time.time() + 3600)
    assert sent(session.get(url("example.test"))) == ["new=1"]


def test_server_deletion_removes_from_python_jar(session):
    session.get(url("example.test", set=["gone=1; Path=/"]))
    assert session.cookies.get("gone") == "1"
    session.get(url("example.test", set=["gone=; Max-Age=0; Path=/"]))
    assert "gone" not in session.cookies
    assert sent(session.get(url("example.test"))) == []


def test_python_side_removal_is_honoured(session):
    session.get(url("example.test", set=["sid=1; Path=/"]))
    assert sent(session.get(url("example.test"))) == ["sid=1"]
    session.cookies.remove("sid")
    # 0.4.x kept it in the Go session jar, sent it and copied it back into Python
    assert sent(session.get(url("example.test"))) == []
    assert "sid" not in session.cookies


def test_redirect_hop_cookies(session):
    same = session.get(url("www.example.test", "/redir", set="r=1; Path=/", to="http://www.example.test/echo"))
    assert sent(same) == ["r=1"]
    other = session.get(url("www.example.test", "/redir", set="x=1; Path=/", to="http://other.test/echo"))
    assert sent(other) == []                                            # host-only x stays on www
    assert session.cookies.get("x") == "1" and session.cookies.get("r") == "1"


def test_per_request_cookies_override_and_are_transient(session):
    session.cookies.set("n", "jar", domain="example.test")
    assert sorted(sent(session.get(url("example.test"), cookies={"n": "req", "t": "1"}))) == ["n=req", "t=1"]
    assert session.cookies.get("n") == "jar" and "t" not in session.cookies
    session.get(url("example.test", set="t=server; Path=/"), cookies={"t": "1"})
    assert session.cookies.get("t") == "server"                         # kept: the server set it


def test_domainless_cookie_is_global_but_does_not_shadow_scoped(session):
    session.cookies["g"] = "any"                                        # requests semantics
    assert sent(session.get(url("a.test"))) == ["g=any"]
    session.cookies.set("g", "scoped", domain="b.test")                 # a separate, scoped entry
    assert sent(session.get(url("b.test"))) == ["g=scoped"]


def test_concurrent_requests_keep_both_cookies(proxy):
    async def main() -> dict[str, str]:
        async with AsyncSession(proxy=proxy, timeout=10) as s:
            await asyncio.gather(s.get(url("example.test", set="a=1; Path=/", sleep=0.3)),
                                 s.get(url("example.test", set="b=1; Path=/", sleep=0.1)))
            return s.cookies.to_dict(url="http://example.test/")
    assert asyncio.run(main()) == {"a": "1", "b": "1"}


def test_for_url_matches_python_selection():
    jar = CookieJar()
    jar.set("a", "1", domain="example.test", path="/x", host_only=True)
    jar.set("b", "2", domain="example.test", path="/")
    assert [c.name for c in jar.for_url("http://example.test/x/y")] == ["a", "b"]
    assert [c.name for c in jar.for_url("http://sub.example.test/x")] == ["b"]
    exported = jar.export()
    assert CookieJar(exported).export() == exported
