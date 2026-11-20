"""Default request headers against captures of the real browsers (tests/fixtures/
browser_headers.json): a navigation in a fresh profile, over HTTP/2 and HTTP/1.1."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import yumeclient
from yumeclient import Session
from yumeclient.profiles import sec_ch_ua

from test_okhttp import H1Server
from test_protocol import H2Server

DATA = json.loads((Path(__file__).parent / "fixtures" / "browser_headers.json").read_text(encoding="utf-8"))

# profile -> capture; the comparison skips what a test build cannot show (Chromium
# test builds send "Chromium" without "Google Chrome", headless ones a HeadlessChrome UA)
CHROME = {f"chrome_{v}": f"chrome_{v}" for v in (103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 117, 120,
                                                  124, 131, 133, 144, 146, 150, 152)}
CHROME.update({"chrome_116_PSK": "chrome_116", "chrome_130_PSK": "chrome_130"})
CHROME = {k: v for k, v in CHROME.items() if k in yumeclient.ALL_IDENTIFIERS}
FIREFOX = {f"firefox_{v}": f"firefox_{v}.0" for v in (102, 104, 105, 106, 110, 117, 120, 123, 132, 133, 135, 147, 148)}
FIREFOX.update({"firefox_146_PSK": "firefox_146.0", "firefox_147_PSK": "firefox_147.0"})
OPERA = {"opera_89": "opera_89.0.4447.83", "opera_90": "opera_90.0.4480.84", "opera_91": "opera_91.0.4516.77"}


@pytest.fixture(scope="module")
def native():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")


def test_sec_ch_ua_follows_chromium():
    # two brands: Chromium test builds; 104 is left out (its release builds shipped the
    # older permuted list, which the profile follows: see the Opera 90 case below)
    for name, headers in DATA["http2"].items():
        if name.startswith("chrome_") and name != "chrome_104":
            assert sec_ch_ua(int(name.split("_")[1]), None) == dict(headers)["sec-ch-ua"], name
    # three brands: Google Chrome 157.0.8103.79 (2026-11-20)
    assert sec_ch_ua(157) == '"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"'
    # Opera 90 = Chromium 104, seeded with 90: the older algorithm, as Chrome 104 shipped
    assert dict(DATA["http2"]["opera_90.0.4480.84"])["sec-ch-ua"] == '" Not A;Brand";v="99", "Chromium";v="104", "Opera";v="90"'
    assert sec_ch_ua(104) == '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"'


def _h2_headers(identifier: str) -> list[tuple[str, str]]:
    srv = H2Server()
    try:
        with Session(client_identifier=identifier, verify=False, timeout=5) as s:
            r = s.get(f"https://127.0.0.1:{srv.port}/")
        assert r.used_protocol == "HTTP/2.0"
        return [(k.lower(), v) for k, v in r.fingerprint["request_headers"] if not k.startswith(":")]
    finally:
        srv.close()


def _compare(ours: list, real: list, skip: set[str]) -> None:
    assert [k for k, _ in ours] == [k for k, _ in real]
    for (k, v), (_, want) in zip(ours, real):
        if k not in skip:
            assert v == want, k


@pytest.mark.parametrize("identifier", sorted(CHROME))
def test_chrome_http2_headers(native, identifier):
    _compare(_h2_headers(identifier), DATA["http2"][CHROME[identifier]], {"user-agent", "sec-ch-ua"})


@pytest.mark.parametrize("identifier", sorted(FIREFOX) + sorted(OPERA))
def test_firefox_and_opera_http2_headers(native, identifier):
    _compare(_h2_headers(identifier), DATA["http2"][{**FIREFOX, **OPERA}[identifier]], set())


def test_tor_http2_headers_are_firefox_128s(native):
    real = [(k, v) for k, v in DATA["http2"]["firefox_128.0"] if k != "te"]  # Tor's baseline has no te
    _compare(_h2_headers("tor_145"), real, {"user-agent"})


@pytest.mark.parametrize("identifier,capture", [("chrome_110", "chrome_110"), ("chrome_120", "chrome_120"),
                                                ("chrome_133", "chrome_133"), ("chrome_152", "chrome_152"),
                                                ("firefox_102", "firefox_102.0"), ("firefox_123", "firefox_123.0"),
                                                ("firefox_133", "firefox_133.0"), ("firefox_147", "firefox_147.0"),
                                                ("tor_145", "firefox_128.0")])
def test_http1_headers(native, identifier, capture):
    # Host first, Connection: keep-alive, names spelled as the browser does
    # (lowercase client hints in Chromium); before: lowercase names and Host last
    srv = H1Server()
    try:
        with Session(client_identifier=identifier, verify=False, timeout=5) as s:
            s.get(f"https://127.0.0.1:{srv.port}/")
    finally:
        srv.close()
    lines = srv.requests[0].split(b"\r\n\r\n")[0].decode().split("\r\n")[1:]
    ours = [tuple(line.split(": ", 1)) for line in lines]
    real = [tuple(pair) for pair in DATA["http1"][capture]]
    _compare(ours, real, {"Host", "User-Agent", "sec-ch-ua"})
