from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import Cookie
from time import time
from typing import Any, Iterator

def _normalize_domain(domain: str) -> str:
    return domain.lstrip(".").lower().split(":", 1)[0]


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

class CookieJar:
    """Small browser-export-compatible cookie store with (name, domain, path) identity."""
    def __init__(self, initial: Any = None) -> None:
        self._items: list[JarCookie] = []
        if isinstance(initial, dict): self.update(initial)
        elif isinstance(initial, list):
            for item in initial:
                if isinstance(item, dict): self.set(item.get("name", ""), item.get("value", ""), domain=item.get("domain", ""), path=item.get("path", "/"), expires=item.get("expirationDate", item.get("expires")), secure=item.get("secure", False), http_only=item.get("httpOnly", item.get("http_only", False)), same_site=item.get("sameSite"))

    def set(self, name: str, value: str, *, domain: str = "", path: str = "/", expires: float | None = None, secure: bool = False, http_only: bool = False, same_site: str | None = None) -> None:
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
        self._items.append(JarCookie(str(name), str(value), domain, path or "/", expires, secure, http_only, same_site))

    def update(self, values: Any, *, domain: str = "") -> None:
        if hasattr(values, "items"):
            for name, value in values.items(): self.set(name, value, domain=domain)
        else:
            for item in values: self.set(item.get("name", ""), item.get("value", ""), domain=item.get("domain", domain), path=item.get("path", "/"), expires=item.get("expirationDate", item.get("expires")), secure=item.get("secure", False), http_only=item.get("httpOnly", False), same_site=item.get("sameSite"))

    def load(self, header: str, *, domain: str = "") -> None:
        for pair in header.split(";"):
            name, sep, value = pair.strip().partition("=")
            if sep and name: self.set(name, value, domain=domain)

    def get_cookie(self, name: str) -> Cookie | None:
        found = [c for c in self._items if c.name == name]
        if not found: return None
        c = max(found, key=lambda x: len(x.domain))
        return Cookie(0, c.name, c.value, None, False, c.domain, bool(c.domain), c.path, True, c.expires, c.expires is not None, None, None, {"HttpOnly": c.http_only}, False, None)

    def get(self, name: str, default: Any = None) -> Any:
        item = self.get_cookie(name)
        return item.value if item else default

    def remove(self, name: str, *, domain: str | None = None, path: str | None = None) -> None:
        self._items = [c for c in self._items if not (c.name == name and (domain is None or c.domain == _normalize_domain(domain)) and (path is None or c.path == path))]

    def clear_domain(self, domain: str) -> None:
        domain = domain.lstrip(".").lower()
        self._items = [c for c in self._items if c.domain != domain]

    def to_dict(self, *, domain: str | None = None) -> dict[str, str]:
        chosen: dict[str, JarCookie] = {}
        for c in self._items:
            if domain and c.domain and domain.lower() != c.domain and not domain.lower().endswith("." + c.domain): continue
            if c.expires is not None and c.expires < time(): continue
            if c.name not in chosen or len(c.domain) > len(chosen[c.name].domain): chosen[c.name] = c
        return {name: item.value for name, item in chosen.items()}

    def export(self) -> list[dict[str, Any]]:
        return [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "expirationDate": c.expires, "secure": c.secure, "httpOnly": c.http_only, "sameSite": c.same_site} for c in self._items]

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None: raise KeyError(name)
        return value
    def __setitem__(self, name: str, value: str) -> None: self.set(name, value)
    def __contains__(self, name: object) -> bool: return isinstance(name, str) and self.get(name) is not None
    def __iter__(self) -> Iterator[JarCookie]: return iter(self._items)
    def __len__(self) -> int: return len(self._items)
