"""Build native/h3profiles.json — the HTTP/3 and QUIC fingerprints of real browsers —
from captures made with scripts/h3_browsers.py (scripts/h3_capture.py).

  python scripts/h3_profiles.py CAPTURE_DIR [--out native/h3profiles.json]

Every entry records the build it was captured from. Only the stable parts of a
capture are kept; what varies per connection (extension and transport parameter
order, GREASE values, connection IDs, chaos layout) is described, not copied.
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from h3_capture import H3_SETTING_NAMES, TP_NAMES  # noqa: E402

SETTING_IDS = {v: k for k, v in H3_SETTING_NAMES.items()}
TP_IDS = {v: k for k, v in TP_NAMES.items()}
VARINT_TPS = {0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0E, 0x20, 0x3127, 0xFF04DE1B}

# yumeclient profile -> capture, and how the capture relates to it
PROFILE_SOURCES: dict[str, tuple[str, str]] = {}
for v in (103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 116, 117, 120, 124, 130, 131, 133, 144, 146, 150, 152):
    PROFILE_SOURCES[f"chrome_{v}"] = (f"chrome_{v}", "captured")
for name in ("chrome_116_PSK", "chrome_130_PSK", "chrome_131_PSK", "chrome_133_PSK",
             "chrome_144_PSK", "chrome_146_PSK", "chrome_150_PSK", "chrome_152_PSK"):
    PROFILE_SOURCES[name] = (name.split("_PSK")[0], "captured (the PSK variant differs in TCP resumption only)")
# Chrome 116 with the PostQuantumKyber field trial: X25519Kyber768 over QUIC as well
PROFILE_SOURCES["chrome_116_PSK_PQ"] = ("chrome_116_pq", "captured with --enable-features=PostQuantumKyber")
for name, base in (("edge_99", "chrome_99"), ("edge_101", "chrome_101"), ("edge_131", "chrome_131"),
                   ("edge_latest", "chrome_131"), ("brave_146", "chrome_146"), ("brave_146_PSK", "chrome_146")):
    PROFILE_SOURCES[name] = (base, "Chromium of the same major version (same network stack)")
for name, base in (("opera_89", "opera_89.0.4447.83"), ("opera_90", "opera_90.0.4480.84"), ("opera_91", "opera_91.0.4516.77")):
    PROFILE_SOURCES[name] = (base, "captured")
for v in (102, 104, 105, 106, 108, 110, 117, 120, 123, 132, 133, 135, 146, 147, 148):
    PROFILE_SOURCES[f"firefox_{v}"] = (f"firefox_{v}.0", "captured")
PROFILE_SOURCES["firefox_146_PSK"] = ("firefox_146.0", "captured (the PSK variant differs in TCP resumption only)")
PROFILE_SOURCES["firefox_147_PSK"] = ("firefox_147.0", "captured (the PSK variant differs in TCP resumption only)")


def _num(name: str) -> int:
    if name in SETTING_IDS:
        return SETTING_IDS[name]
    return int(name, 16)


def _tp(t: dict, later: set[str]) -> dict:
    name = t["name"]
    if name == "grease":
        return {"kind": "grease"}
    tid = t["id"]
    if name == "initial_source_connection_id":
        return {"id": tid, "kind": "scid"}
    if name in ("version_information", "version_information_draft"):
        v = t.get("value")
        if isinstance(v, list):
            data = "".join(x[2:] for x in v)
        else:
            data = v
        words = [data[i:i + 8] for i in range(0, len(data), 8)]
        words = [w if (int(w, 16) & 0x0F0F0F0F) != 0x0A0A0A0A else "0a0a0a0a" for w in words]
        # the available versions come in a random order: keep the chosen one first
        return {"id": tid, "kind": "version_information", "hex": words[0] + "".join(sorted(words[1:]))}
    if tid in VARINT_TPS:
        return {"id": tid, "kind": "varint", "value": t.get("value", 0)}
    return {"id": tid, "kind": "bytes", "hex": t.get("value", "")}


def _shuffled(values: list) -> bool:
    return len({json.dumps(v) for v in values}) > 1


def build(caps: list[dict], name: str) -> dict:
    firsts = [c["connections"][0] for c in caps if c.get("connections")]
    later = [c for cap in caps for c in cap["connections"][1:]]
    first = firsts[0]
    tls = first["tls"]
    tps = first["transport_parameters"]
    later_names = {t["name"] for c in later for t in c["transport_parameters"]}
    params = [_tp(t, later_names) for t in tps]
    grease_lens = [t["len"] for c in firsts + later for t in c["transport_parameters"] if t["name"] == "grease"]
    for p in params:
        if p["kind"] == "grease":
            p["max_len"] = 15 if max(grease_lens, default=0) > 0 else 0
    if "google_initial_rtt" in later_names and not any(t["name"] == "google_initial_rtt" for t in tps):
        # later connections to the same server announce the RTT measured before (us)
        params.append({"id": 0x3127, "kind": "initial_rtt"})
    # the connection that carried the navigation: its HTTP/3 control stream and requests
    nav = next((c for c in [first] + later if c["h3"]["requests"]), first)
    control = next((u for u in nav["h3"]["uni_streams"] if u["type"] == "control"), {"frames": []})
    frames = control.get("frames", [])
    settings = next((f["settings"] for f in frames if f["type"] == "SETTINGS"), [])
    order = [f["type"] for f in frames]
    greases = [f.get("len", 0) for cap in caps for c in cap["connections"] for u in c["h3"]["uni_streams"]
               if u["type"] == "control" for f in u.get("frames", []) if f["type"] == "GREASE"]
    updates = [f for f in frames if f["type"] == "PRIORITY_UPDATE"]
    req = nav["h3"]["requests"][0]
    headers = req.get("headers", [])
    priority = next((v for k, v in headers if k == "priority"), None)
    uni_ids = {u["type"]: u["stream"] for c in [first] + later for u in c["h3"]["uni_streams"]}
    qpack_data = {u["type"]: u.get("data") for c in [first] + later for u in c["h3"]["uni_streams"]}
    qpack = None
    if "qpack_encoder" in uni_ids or "qpack_decoder" in uni_ids:
        dec, enc = uni_ids.get("qpack_decoder", 1 << 30), uni_ids.get("qpack_encoder", 1 << 30)
        qpack = {
            "open": True,
            "decoder_first": dec < enc,
            # a stream type sent with no instruction behind it: the streams start eagerly
            "eager": qpack_data.get("qpack_encoder") == "" or qpack_data.get("qpack_decoder") == "",
            "zero_capacity": qpack_data.get("qpack_encoder") == "20",
        }
    packets = first["quic"]["initial_packets"]
    dcid_lens = {c["quic"]["dcid_len"] for c in firsts + later}
    pns = {c["quic"]["initial_packets"][0].get("pn", 0) for c in firsts + later if c["quic"]["initial_packets"]}
    chaos_seen = any(sum(1 for f in p.get("frames", []) if f.startswith("CRYPTO")) > 1 or "PING" in p.get("frames", [])
                     for c in firsts for p in c["quic"]["initial_packets"][:2])
    multi = len(first["quic"]["initial_datagrams"]) > 1
    chaos = "off"
    p0 = [f for f in packets[0]["frames"] if f.startswith("CRYPTO")] if packets else []
    if len(p0) == 2 and "PING" not in packets[0]["frames"] and p0[1].startswith("CRYPTO(0,") \
            and not p0[0].startswith("CRYPTO(0,"):
        chaos_seen = False
        chaos = "sni_slice"  # neqo: the part after the middle of the SNI first, no PING/PADDING frames
    if chaos_seen:
        if multi:
            p0 = [f for f in packets[0]["frames"] if f.startswith("CRYPTO")]
            chaos = "last_packet" if len(p0) == 1 and "PING" not in packets[0]["frames"] else "multi_packet"
        else:
            chaos = "single_packet"
    ext_orders = [c["tls"]["extensions"] for c in firsts + later if c["tls"]]
    # GREASE ECH: the payload length varies per connection (extension length - 58)
    ech = sorted({int(c["tls"]["extension_data"]["65037"][1:].split()[0]) - 58
                  for c in firsts + later if c["tls"] and "65037" in c["tls"].get("extension_data", {})})
    if ech and name.startswith(("chrome", "opera")) and set(ech) <= {128, 160, 192, 224}:
        ech = [128, 160, 192, 224]  # BoringSSL's GREASE ECH payload lengths
    tp_orders = [[t["name"] for t in c["transport_parameters"]] for c in firsts]
    entry = {
        "source": caps[0]["build"] | {"client_version": caps[0]["client"].get("version")},
        "quic": {
            "client_hello": tls["raw_hello"],
            "ech_grease_payload_lens": ech,
            "ja4": tls["ja4"],
            "shuffle_extensions": _shuffled(ext_orders),
            "transport_parameters": params,
            "shuffle_transport_parameters": _shuffled(tp_orders),
            "initial_packet_size": first["quic"]["initial_datagrams"][0],
            # a length that varies between connections is random (quic-go: 8 to 20 bytes)
            "dcid_len": dcid_lens.pop() if len(dcid_lens) == 1 else 0,
            "scid_len": first["quic"]["scid_len"],
            # a first packet number that varies is random (neqo's distribution)
            "first_packet_number": pns.pop() if len(pns) == 1 else -1,
            "chaos": chaos,
            # PADDING frames fill the Initial packet, or zero bytes follow it (neqo)
            "pad_with_zeros": bool(packets) and packets[0]["len"] < first["quic"]["initial_datagrams"][0],
        },
        "h3": {
            "settings": [["GREASE"] if s[0] == "GREASE" else [_num(s[0]), s[1]] for s in settings],
            "grease_frame": "GREASE" in order,
            "grease_frame_max_len": max(greases, default=0),
            "priority_updates": bool(updates),
            "priority": priority or (updates[0]["value"] if updates else None),
            "priority_header": priority is not None,
            "pseudo_header_order": [k for k, _ in headers if k.startswith(":")],
            "qpack": qpack,
        },
    }
    if len(caps) < 2:
        entry["note"] = f"one capture: order randomisation of {name} not verified"
    return entry


def known_profiles() -> set[str]:
    """yumeclient's client identifiers (tls-client's profile map + native extra profiles)."""
    native = Path(__file__).resolve().parents[1] / "native"
    names: set[str] = set()
    for src, var in ((native / "third_party" / "tls-client" / "profiles" / "profiles.go", "var MappedTLSClients"),
                     (native / "main.go", "var extraProfiles")):
        text = src.read_text(encoding="utf-8")
        block = text[text.index(var):]
        block = block[:block.index("\n}")]
        names |= set(re.findall(r'"([^"]+)":', block))
    return names


def write_python_list(names: list[str]) -> None:
    """yumeclient/profiles.py HTTP3_FINGERPRINTS (warnings and checks on the Python side)."""
    path = Path(__file__).resolve().parents[1] / "yumeclient" / "profiles.py"
    text = path.read_text(encoding="utf-8")
    begin, end = "# --- HTTP3_FINGERPRINTS begin ---\n", "# --- HTTP3_FINGERPRINTS end ---"
    head, rest = text.split(begin)
    _, tail = rest.split(end)
    lines, line = [], "   "
    for name in names:
        item = f' "{name}",'
        if len(line) + len(item) > 100:
            lines.append(line)
            line = "   "
        line += item
    lines.append(line)
    body = "HTTP3_FINGERPRINTS: Final[frozenset[str]] = frozenset({\n" + "\n".join(lines) + "\n})\n"
    path.write_text(head + begin + body + end + tail, encoding="utf-8", newline="\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("captures")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "native" / "h3profiles.json"))
    args = ap.parse_args()
    groups: dict[str, list[dict]] = {}
    for f in sorted(glob.glob(str(Path(args.captures) / "*.json"))):
        stem = Path(f).stem
        name = re.sub(r"_\d$", "", stem)
        cap = json.loads(Path(f).read_text(encoding="utf-8"))
        if not cap.get("ok") or not cap.get("connections") or "build" not in cap:
            continue
        if not cap["connections"][0]["tls"] or "raw_hello" not in cap["connections"][0]["tls"]:
            continue
        groups.setdefault(name, []).append(cap)
    captures = {name: build(caps, name) for name, caps in groups.items()}
    # a client whose Destination Connection ID length varies in any capture picks it
    # at random: a few captures of one version may just happen to agree
    for family in {n.split("_")[0] for n in captures}:
        members = [c for n, c in captures.items() if n.split("_")[0] == family]
        if any(c["quic"]["dcid_len"] == 0 for c in members):
            for c in members:
                c["quic"]["dcid_len"] = 0
    profiles = {}
    missing = []
    known = known_profiles()
    for profile, (cap, relation) in sorted(PROFILE_SOURCES.items()):
        if profile not in known:
            continue
        if cap in captures:
            profiles[profile] = {"capture": cap, "relation": relation}
        else:
            missing.append(profile)
    out = {"format": "yumeclient.h3profiles", "version": 1, "captures": captures, "profiles": profiles}
    Path(args.out).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    write_python_list(sorted(profiles))
    print(f"{args.out}: {len(captures)} captures, {len(profiles)} profiles; no capture for: {', '.join(missing) or '-'}")


if __name__ == "__main__":
    main()
