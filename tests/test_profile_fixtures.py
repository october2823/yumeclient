"""Every supported profile against its recorded fingerprint (0.6.0), fully offline.

tests/fixtures/profiles.json holds, per identifier, what the ClientHello looked like on the
wire (JA3 / JA4 / JA4_r, ALPN offer, extension order), the HTTP/2 fingerprint and the default
request header order. A tls-client upgrade or a profile change that alters any of these fails
here with a fingerprint_diff; if the change is intended, regenerate the fixtures:

    python scripts/profile_fixtures.py --update
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import pytest

import yumeclient
from yumeclient import Session, fingerprint_diff

from test_wire import Sniffer, parse_hello

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "profiles.json"
FORMAT = "yumeclient.profile-fixtures"
_GREASE = lambda v: v & 0x0F0F == 0x0A0A and v >> 8 == v & 0xFF  # noqa: E731


def capture(sniffer: Sniffer, identifier: str) -> dict[str, Any]:
    """One fresh connection with ``identifier`` through the sniffing relay."""
    start = len(sniffer.hellos)
    response, outcome = None, "ok"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            with Session(client_identifier=identifier, verify=False, timeout=10) as s:
                response = s.get(f"https://localhost:{sniffer.port}/x")
        except yumeclient.RequestError as exc:
            outcome = exc.kind
    assert len(sniffer.hellos) > start, f"{identifier}: no ClientHello captured"
    hello = parse_hello(sniffer.hellos[start])
    entry: dict[str, Any] = {
        "ja3": hello["ja3"], "ja4": hello["ja4"], "ja4_r": hello["ja4_r"], "alpn_offered": hello["alpn_list"],
        "tls_extensions": [t for t in hello["order"] if not _GREASE(t)], "handshake": outcome}
    if response is not None:
        fp = response.fingerprint or {}
        assert fp.get("source") == "wire" and fp.get("ja4") == hello["ja4"], identifier  # report == wire
        entry["akamai_fingerprint"] = fp.get("akamai_fingerprint")
        entry["header_order"] = [name.lower() for name, _ in fp.get("request_headers", [])]
    return entry


def generate(sniffer: Sniffer, rounds: int = 3) -> dict[str, Any]:
    profiles: dict[str, Any] = {}
    for identifier in yumeclient.ALL_IDENTIFIERS:
        runs = [capture(sniffer, identifier) for _ in range(rounds)]
        entry = runs[0]
        # randomized extension order (Chrome family): only the set is stable
        entry["shuffled"] = any(run["tls_extensions"] != entry["tls_extensions"] for run in runs[1:])
        for run in runs[1:]:
            unstable = [d for d in fingerprint_diff(entry, run) if not (entry["shuffled"] and d["kind"] == "order")]
            assert not unstable, (identifier, unstable)
        profiles[identifier] = entry
    return {"format": FORMAT, "version": 1, "tls_server": "Python ssl (OpenSSL), ALPN http/1.1, SNI localhost",
            "regenerate": "python scripts/profile_fixtures.py --update", "profiles": profiles}


@pytest.fixture(scope="module")
def sniffer():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    s = Sniffer()
    yield s
    s.close()


def _fixtures() -> dict[str, Any]:
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    assert data["format"] == FORMAT
    return data["profiles"]


def test_every_profile_has_a_fixture():
    assert sorted(_fixtures()) == sorted(yumeclient.ALL_IDENTIFIERS), "run: python scripts/profile_fixtures.py --update"


@pytest.mark.parametrize("identifier", yumeclient.ALL_IDENTIFIERS)
def test_profile_matches_fixture(sniffer, identifier):
    expected = _fixtures().get(identifier)
    if expected is None:
        pytest.fail("no fixture: run python scripts/profile_fixtures.py --update")
    actual = capture(sniffer, identifier)
    # completes against the local OpenSSL server or not (cloudscraper: CBC-SHA1 only, refused);
    # checked first: without a handshake the HTTP-level fields are missing from the diff below
    assert (actual["handshake"] == "ok") == (expected["handshake"] == "ok"), actual["handshake"]
    diff = [d for d in fingerprint_diff(expected, actual)
            if not (expected["shuffled"] and d["kind"] == "order" and d["field"] in ("tls_extensions", "ja3.extensions"))]
    assert diff == [], json.dumps(diff, indent=1)
