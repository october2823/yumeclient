"""Case-insensitive header mapping (shared by the session and the profile baselines)."""
from __future__ import annotations

from typing import Any, Mapping


class Headers(dict):
    """Case-insensitive ordered header mapping: update()/[] replace in place, keeping wire order
    and the first spelling of the name. Lookup, ``in``, ``del``, ``get`` and ``pop`` ignore case."""
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.update(*args, **kwargs)
    def _resolve(self, key: Any) -> Any:
        if not isinstance(key, str): return None
        if dict.__contains__(self, key): return key
        lowered = key.lower()
        return next((existing for existing in self if isinstance(existing, str) and existing.lower() == lowered), None)
    def __getitem__(self, key: Any) -> Any:
        existing = self._resolve(key)
        return dict.__getitem__(self, key if existing is None else existing)
    def __contains__(self, key: Any) -> bool: return self._resolve(key) is not None
    def __delitem__(self, key: Any) -> None:
        existing = self._resolve(key)
        dict.__delitem__(self, key if existing is None else existing)
    def get(self, key: Any, default: Any = None) -> Any:
        existing = self._resolve(key)
        return default if existing is None else dict.__getitem__(self, existing)
    def pop(self, key: Any, *default: Any) -> Any:
        existing = self._resolve(key)
        if existing is None:
            if default: return default[0]
            raise KeyError(key)
        return dict.pop(self, existing)
    def copy(self) -> "Headers": return Headers(self)
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
    def __ior__(self, other: Any) -> "Headers":
        self.update(other); return self
    def __or__(self, other: Any) -> "Headers":
        if not isinstance(other, Mapping): return NotImplemented
        merged = Headers(self); merged.update(other); return merged
    def __ror__(self, other: Any) -> "Headers":
        if not isinstance(other, Mapping): return NotImplemented
        merged = Headers(other); merged.update(self); return merged
