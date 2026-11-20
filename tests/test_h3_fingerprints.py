"""Every profile with HTTP/3 data (native/h3profiles.json, captured from the real
browsers by scripts/h3_browsers.py) sends that browser's QUIC and HTTP/3 handshake:
the QUIC ClientHello (JA4, extensions), transport parameters, connection ID lengths,
Initial packet size and layout, SETTINGS, control stream, priorities and QPACK
streams. A local aioquic server records what arrives (scripts/h3_capture.py)."""
from __future__ import annotations

import json
import re
import sys
import warnings
from pathlib import Path

import pytest

pytest.importorskip("aioquic")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import h3_capture  # noqa: E402

import yumeclient  # noqa: E402

DATA = json.loads((ROOT / "native" / "h3profiles.json").read_text(encoding="utf-8"))
PROFILES = sorted(DATA["profiles"])


@pytest.fixture(scope="module")
def server():
    try:
        yumeclient.Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    srv = h3_capture.CaptureServer()
    yield srv
    srv.close()


def _capture(server, profile: str, decoder: bool = False) -> dict:
    with server.recorder.lock:
        server.recorder.conns.clear()
        server.recorder.by_addr.clear()
    url = f"https://localhost:{server.port}/"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with yumeclient.Session(client_identifier=profile, verify=False, timeout=8, http_version="3") as s:
            for path in ("", "favicon.ico"):  # a second request: QPACK decoder stream, PRIORITY_UPDATE
                r = s.get(url + path)
                assert r.used_protocol == "HTTP/3.0"
    for _ in range(50):  # the last frames are still on their way
        results = server.recorder.results()
        if results and len(results[0]["h3"]["requests"]) >= 2 and (
                not decoder or any(u["type"] == "qpack_decoder" for u in results[0]["h3"]["uni_streams"])):
            break
        import time
        time.sleep(0.02)
    assert len(results) == 1, "one QUIC connection"
    return results[0]


def _tp_name(tid: int) -> str:
    return h3_capture.TP_NAMES.get(tid, f"0x{tid:x}")


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_sends_the_captured_browser_handshake(server, profile):
    entry = DATA["captures"][DATA["profiles"][profile]["capture"]]
    q, h3 = entry["quic"], entry["h3"]
    conn = _capture(server, profile, decoder=bool(h3["qpack"]))
    expected = h3_capture.parse_client_hello(bytes.fromhex(q["client_hello"]))
    got = conn["tls"]

    # QUIC ClientHello: same JA4, cipher suites, extensions and their contents
    assert got["ja4"] == expected["ja4"] == q["ja4"]
    for key in ("ciphers", "groups", "signature_algorithms", "versions", "alpn"):
        assert got[key] == expected[key], key
    assert sorted(map(str, got["extensions"])) == sorted(map(str, expected["extensions"]))
    if not q["shuffle_extensions"]:
        assert got["extensions"] == expected["extensions"]
    stable = lambda d: {k: v for k, v in d.items() if k != "65037"}  # noqa: E731  GREASE ECH is random
    assert stable(got["extension_data"]) == stable(expected["extension_data"])
    assert [g for g, _ in got["key_share"]] == [g for g, _ in expected["key_share"]]

    # transport parameters: the same set and values (the first connection to a
    # server announces no google_initial_rtt)
    tps = conn["transport_parameters"]
    want = [t for t in q["transport_parameters"] if t["kind"] != "initial_rtt"]
    assert sorted(t["name"] for t in tps) == sorted("grease" if t["kind"] == "grease" else _tp_name(t["id"]) for t in want)
    values = {t["name"]: t.get("value") for t in tps}
    for t in want:
        if t["kind"] == "varint":
            assert values[_tp_name(t["id"])] == t["value"], _tp_name(t["id"])
        elif t["kind"] == "bytes":
            assert (values[_tp_name(t["id"])] or "") == t["hex"], _tp_name(t["id"])
        elif t["kind"] == "version_information":
            v = values[_tp_name(t["id"])]
            words = [w[2:] for w in v] if isinstance(v, list) else [v[i:i + 8] for i in range(0, len(v), 8)]
            words = [w if int(w, 16) & 0x0F0F0F0F != 0x0A0A0A0A else "0a0a0a0a" for w in words]
            assert words[0] + "".join(sorted(words[1:])) == t["hex"]

    # packets: connection ID lengths, datagram size, first packet number
    quic = conn["quic"]
    assert quic["scid_len"] == q["scid_len"]
    if q["dcid_len"]:
        assert quic["dcid_len"] == q["dcid_len"]
    else:  # random
        assert 8 <= quic["dcid_len"] <= 20
    assert set(quic["initial_datagrams"]) == {q["initial_packet_size"]}
    packets = [p for p in quic["initial_packets"] if "CRYPTO" in " ".join(p["frames"])]
    if q["first_packet_number"] >= 0:
        assert packets[0]["pn"] == q["first_packet_number"]
    else:  # random, never 0
        assert 1 <= packets[0]["pn"] <= 1024
    # zero bytes after the Initial packet, or PADDING frames inside it
    assert (packets[0]["len"] < quic["initial_datagrams"][0]) == q["pad_with_zeros"]
    _check_first_flight(packets, q["chaos"], got["hs_len"] + 4)

    # HTTP/3: SETTINGS, control stream, priorities, QPACK streams, pseudo-headers
    control = next(u for u in conn["h3"]["uni_streams"] if u["type"] == "control")
    frames = control["frames"]
    settings = next(f["settings"] for f in frames if f["type"] == "SETTINGS")
    assert [["GREASE"] if s[0] == "GREASE" else [_setting_id(s[0]), s[1]] for s in settings] == h3["settings"]
    kinds = [f["type"] for f in frames]
    assert kinds[0] == "SETTINGS"
    assert (kinds[1:2] == ["GREASE"]) == h3["grease_frame"]
    updates = [f for f in frames if f["type"] == "PRIORITY_UPDATE"]
    if h3["priority_updates"]:
        assert [(f["element"], f["value"]) for f in updates] == [(0, h3["priority"]), (4, h3["priority"])]
    else:
        assert not updates
    req = conn["h3"]["requests"][0]["headers"]
    assert [k for k, _ in req if k.startswith(":")] == h3["pseudo_header_order"]
    assert dict(req).get("priority") == (h3["priority"] if h3["priority_header"] else dict(req).get("priority"))
    if h3["qpack"]:
        ids = {u["type"]: u["stream"] for u in conn["h3"]["uni_streams"]}
        assert "qpack_decoder" in ids  # the server used its dynamic table: acknowledged
        if "qpack_encoder" in ids:
            assert (ids["qpack_decoder"] < ids["qpack_encoder"]) == h3["qpack"]["decoder_first"]


def _setting_id(name: str) -> int:
    ids = {v: k for k, v in h3_capture.H3_SETTING_NAMES.items()}
    return ids[name] if name in ids else int(name, 16)


def _check_first_flight(packets: list[dict], chaos: str, length: int) -> None:
    """The ClientHello arrives whole, once, in the browser's layout."""
    covered = []
    per_packet = []
    for p in packets:
        crypto = [tuple(map(int, re.findall(r"\d+", f))) for f in p["frames"] if f.startswith("CRYPTO")]
        per_packet.append(crypto)
        covered += crypto
        assert {f.split("(")[0] for f in p["frames"]} <= {"CRYPTO", "PING", "PADDING"}
        if sum(n for _, n in covered) >= length:
            break  # later packets are retransmissions (the local server is slow at times)
    covered.sort()
    end = 0
    for off, n in covered:
        assert off == end, "CRYPTO frames neither overlap nor leave gaps"
        end = off + n
    assert end == length
    if chaos == "off":
        assert all(len(c) == 1 for c in per_packet)
    elif chaos == "last_packet" and len(per_packet) > 1:
        assert per_packet[0] == [(0, per_packet[0][0][1])]  # the first packet is in order
    elif chaos == "sni_slice":
        first = per_packet[0]
        assert len(first) == 2 and first[1][0] == 0 and first[0][0] > 0  # after the SNI cut first
    elif chaos == "multi_packet" and len(per_packet) > 1:
        first = per_packet[0]
        assert any(off == 0 for off, _ in first) and any(off + n == length for off, n in first)
