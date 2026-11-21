from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, replace
from http.cookiejar import Cookie
from time import time
from typing import Any, Iterator
from urllib.parse import urlsplit

def _normalize_domain(domain: str) -> str:
    return domain.lstrip(".").lower().split(":", 1)[0]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_match(host: str, domain: str) -> bool:
    """RFC 6265 5.1.3 (an IP address only matches itself)."""
    return host == domain or (not _is_ip(host) and host.endswith("." + domain))


def _path_match(request_path: str, cookie_path: str) -> bool:
    """RFC 6265 5.1.4."""
    request_path = request_path or "/"
    if request_path == cookie_path: return True
    if request_path.startswith(cookie_path):
        return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"
    return False


@dataclass
class JarCookie:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    expires: float | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    # host-only (no Domain attribute): sent to exactly ``domain``, not to its subdomains
    host_only: bool = False

    def matches(self, host: str) -> bool:
        if not self.domain: return True  # set without a domain: every host (requests semantics)
        return host == self.domain if self.host_only else _domain_match(host, self.domain)


class CookieJar:
    """Small browser-export-compatible cookie store with (name, domain, path) identity.

    It is the single source of truth for a session: every request sends a snapshot to the
    native layer, which selects cookies per hop with RFC 6265 rules (domain / host-only,
    path, Secure, expiry) and reports back what the server set or deleted. A cookie set
    without a domain (``jar["sid"] = "x"``) is sent to every host, like in requests, unless a
    host- or domain-scoped cookie of the same name applies.
    """
    def __init__(self, initial: Any = None) -> None:
        self._items: list[JarCookie] = []
        # requests running in parallel (threads, AsyncSession workers) update the jar at the
        # same time; without the lock concurrent set() calls lost each other's cookies
        self._lock = threading.RLock()
        if isinstance(initial, dict): self.update(initial)
        elif isinstance(initial, list):
            for item in initial:
                if isinstance(item, dict): self.set(item.get("name", ""), item.get("value", ""), domain=item.get("domain", ""), path=item.get("path", "/"), expires=item.get("expirationDate", item.get("expires")), secure=item.get("secure", False), http_only=item.get("httpOnly", item.get("http_only", False)), same_site=item.get("sameSite"), host_only=item.get("hostOnly", item.get("host_only", False)))

    def __getstate__(self) -> dict[str, Any]:
        with self._lock: return {"_items": [replace(c) for c in self._items]}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self._items = list(state.get("_items", []))
        self._lock = threading.RLock()

    def set(self, name: str, value: str, *, domain: str = "", path: str = "/", expires: float | None = None, secure: bool = False, http_only: bool = False, same_site: str | None = None, host_only: bool = False) -> None:
        with self._lock: self._set(name, value, domain, path, expires, secure, http_only, same_site, host_only)

    def _set(self, name: str, value: str, domain: str, path: str, expires: float | None, secure: bool,
             http_only: bool, same_site: str | None, host_only: bool) -> None:
        if not domain:
            # update the most specific existing same-name cookie in place instead of
            # shadowing it with a domainless duplicate (jar["sid"] = "x" semantics)
            candidates = [c for c in self._items if c.name == name and c.path == path]
            if candidates:
                target = max(candidates, key=lambda c: len(c.domain))
                target.value = str(value)
                if expires is not None: target.expires = expires
                return
        domain = _normalize_domain(domain)
        self._items = [c for c in self._items if not (c.name == name and c.domain == domain and c.path == path)]
        self._items.append(JarCookie(str(name), str(value), domain, path or "/", expires, secure, http_only, same_site, bool(host_only and domain)))

    def update(self, values: Any, *, domain: str = "") -> None:
        with self._lock: self._update(values, domain)

    def _update(self, values: Any, domain: str) -> None:
        if hasattr(values, "items"):
            for name, value in values.items(): self.set(name, value, domain=domain)
        else:
            for item in values: self.set(item.get("name", ""), item.get("value", ""), domain=item.get("domain", domain), path=item.get("path", "/"), expires=item.get("expirationDate", item.get("expires")), secure=item.get("secure", False), http_only=item.get("httpOnly", False), same_site=item.get("sameSite"), host_only=item.get("hostOnly", False))

    def load(self, header: str, *, domain: str = "") -> None:
        for pair in header.split(";"):
            name, sep, value = pair.strip().partition("=")
            if sep and name: self.set(name, value, domain=domain)

    def get_cookie(self, name: str) -> Cookie | None:
        with self._lock: found = [c for c in self._items if c.name == name]
        if not found: return None
        c = max(found, key=lambda x: len(x.domain))
        return Cookie(0, c.name, c.value, None, False, c.domain, bool(c.domain), c.path, True, c.expires, c.expires is not None, None, None, {"HttpOnly": c.http_only}, False, None)

    def get(self, name: str, default: Any = None) -> Any:
        item = self.get_cookie(name)
        return item.value if item else default

    def remove(self, name: str, *, domain: str | None = None, path: str | None = None) -> None:
        with self._lock: self._items = [c for c in self._items if not (c.name == name and (domain is None or c.domain == _normalize_domain(domain)) and (path is None or c.path == path))]

    def clear_domain(self, domain: str) -> None:
        domain = domain.lstrip(".").lower()
        with self._lock: self._items = [c for c in self._items if c.domain != domain]

    def to_dict(self, *, domain: str | None = None, url: str | None = None) -> dict[str, str]:
        """name -> value. ``url=`` applies full RFC 6265 selection (see :meth:`for_url`, the
        first cookie per name wins); ``domain=`` filters by host only (host-only cookies match
        exactly that host)."""
        if url is not None:
            selected: dict[str, str] = {}
            for c in self.for_url(url): selected.setdefault(c.name, c.value)
            return selected
        host = _normalize_domain(domain) if domain else ""
        chosen: dict[str, JarCookie] = {}
        for c in self._copy():
            if host and not c.matches(host): continue
            if c.expires is not None and c.expires < time(): continue
            if c.name not in chosen or len(c.domain) > len(chosen[c.name].domain): chosen[c.name] = c
        return {name: item.value for name, item in chosen.items()}

    def for_url(self, url: str) -> list[JarCookie]:
        """Cookies a request to ``url`` sends, in RFC 6265 order (longer path first, then older):
        domain / host-only match, path match, Secure only over https, not expired."""
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        path = parts.path or "/"
        secure = parts.scheme.lower() in ("https", "wss")
        now = time()
        chosen: list[tuple[int, JarCookie]] = []
        for index, c in enumerate(self._copy()):
            if c.expires is not None and c.expires <= now: continue
            if c.secure and not secure: continue
            if not c.matches(host) or not _path_match(path, c.path or "/"): continue
            chosen.append((index, c))
        scoped = {c.name for _, c in chosen if c.domain}
        chosen = [(i, c) for i, c in chosen if c.domain or c.name not in scoped]
        chosen.sort(key=lambda item: (-len(item[1].path or "/"), item[0]))
        return [c for _, c in chosen]

    def _snapshot(self) -> list[dict[str, Any]]:
        """Wire form for the native per-request jar (expired cookies left out)."""
        now = time()
        return [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path or "/",
                 "expires": c.expires or 0, "secure": c.secure, "httpOnly": c.http_only,
                 "hostOnly": c.host_only, "sameSite": c.same_site or ""}
                for c in self._copy() if c.name and not (c.expires is not None and c.expires <= now)]

    def export(self) -> list[dict[str, Any]]:
        return [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "expirationDate": c.expires, "secure": c.secure, "httpOnly": c.http_only, "sameSite": c.same_site, "hostOnly": c.host_only} for c in self._copy()]

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None: raise KeyError(name)
        return value
    def __setitem__(self, name: str, value: str) -> None: self.set(name, value)
    def __contains__(self, name: object) -> bool: return isinstance(name, str) and self.get(name) is not None
    def __iter__(self) -> Iterator[JarCookie]: return iter(self._copy())
    def __len__(self) -> int: return len(self._items)

    def _copy(self) -> list[JarCookie]:
        with self._lock: return list(self._items)
